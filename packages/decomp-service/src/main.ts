/**
 * The decompilation service.
 *
 *     bun --watch src/main.ts        (dev)
 *     bun src/main.ts                (run)
 *
 * It owns three things nothing else may own:
 *
 *   THE DATABASE -- the system of record. Reconstruction source and verdicts
 *   live in it. There is no JSON to drift from and no file an agent can edit
 *   behind the service's back.
 *
 *   THE GATE -- the only thing that may decide byte-exactness, and the only
 *   holder of the compiler. Agents submit source and are told the verdict;
 *   they never run cl.exe and never take a lock.
 *
 *   THE WORKERS -- the claim reaper, the gate queue, and the producer. They
 *   are started HERE, by the server, because a worker started by hand becomes
 *   a second worker fighting the first for the same lock. That has happened.
 */
import fs from 'node:fs';
import { Effect, Layer, Option, pipe } from 'effect';
import { check as healthCheck, report as healthReport } from './health';
import { throttleStats } from './modules/gate/throttle';
import { canaryState, superviseCanary } from './canary';
import { modules } from './modules';
import { guestRamPaths } from './modules/subject/paths';
import { PORTABLE_TREE_PATH } from './modules/portable/paths';
import { ComposeImpl } from './modules/compose/impl';
import { DbImpl, handle as dbHandle } from './modules/db/impl';
import { DisasmImpl } from './modules/disasm/impl';
import { DiscoveryImpl } from './modules/discovery/impl';
import { GateImpl } from './modules/gate/impl';
import { GlobalsImpl } from './modules/globals/impl';
import { ImportNamesImpl } from './modules/import-names/impl';
import { LegacyImpl } from './modules/legacy/impl';
import { NamesImpl } from './modules/names/impl';
import { PortableImpl } from './modules/portable/impl';
import { MetricsImpl } from './modules/metrics/impl';
import { RegistryImpl } from './modules/registry/impl';
import { RelocImpl } from './modules/reloc/impl';
import { SubjectImpl } from './modules/subject/impl';
import { WorkImpl } from './modules/work/impl';
import { SUBJECT_FLAGS, SWEEP_FLAG_SETS } from './modules/gate/interface';
import type { PortState } from './modules/portable/interface';
import {
  encodeAgents, encodeComposition, encodeGlobal, encodeGlobals, encodeNames, encodeSweep,
  encodeProbe, encodeVerdict, encodeWorkItems,
} from './api/wire';

const PORT = Number(process.env.PORT ?? 8787);

/** Composed once, at the entry point. Db is depended on by everything, so it
 *  merges last. */
export const layerLive = pipe(
  WorkImpl.Layer,
  Layer.provideMerge(ComposeImpl.Layer),
  Layer.provideMerge(PortableImpl.Layer),
  Layer.provideMerge(RelocImpl.Layer),
  Layer.provideMerge(LegacyImpl.Layer),
  Layer.provideMerge(NamesImpl.Layer),
  Layer.provideMerge(ImportNamesImpl.Layer),
  Layer.provideMerge(GateImpl.Layer),
  Layer.provideMerge(GlobalsImpl.Layer),
  Layer.provideMerge(DiscoveryImpl.Layer),
  Layer.provideMerge(DisasmImpl.Layer),
  Layer.provideMerge(SubjectImpl.Layer),
  Layer.provideMerge(MetricsImpl.Layer),
  Layer.provideMerge(RegistryImpl.Layer),
  Layer.provideMerge(DbImpl.Layer),
);

const run = <A, E>(program: Effect.Effect<A, E, never>) => Effect.runPromise(program);

const json = (body: unknown, status = 200) =>
  Response.json(body, {
    status,
    headers: {
      'cache-control': 'no-store',
      // The dashboard is a separate dev server on another port and is a pure
      // client of this service -- it holds no database of its own. The
      // listener is bound to 127.0.0.1, so this is reachable only from this
      // machine.
      'access-control-allow-origin': '*',
    },
  });

/** A tagged failure becomes an HTTP status. Anything untagged is a defect in
 *  this service and must surface as a 500 with its detail, never as a
 *  plausible-looking empty result. */
const statusFor = (tag: string): number =>
  ({
    UnknownAgent: 404,
    UnknownFunction: 404,
    NotClaimed: 409,
    ParkWithoutReason: 400,
    DbError: 500,
  })[tag] ?? 500;

const handle = async (
  program: Effect.Effect<unknown, { readonly _tag: string }, never>,
): Promise<Response> => {
  // Effect 4's Result carries `success` / `failure`, not `value`. Reading the
  // wrong field handed `undefined` to Response.json, which threw rather than
  // returning anything -- a silent 500 on every successful call.
  const result = await Effect.runPromise(Effect.result(program));
  if (result._tag === 'Success') return json(result.success);
  const failure = result.failure as { _tag: string } & Record<string, unknown>;
  // `message` is the one field a client is likely to print. urllib and most
  // HTTP helpers raise on a 4xx and expose the body only through an extra
  // call, so an error whose reason lives three levels into a JSON object is
  // an error nobody reads -- one worker took a 409 to mean "already proven"
  // when it meant "your lease expired" and re-derived work it still held.
  return json(
    {
      error: failure._tag,
      message:
        typeof failure.detail === 'string'
          ? failure.detail
          : `${failure._tag}: ${JSON.stringify(failure)}`,
      detail: failure,
    },
    statusFor(failure._tag),
  );
};

const provided = <A, E>(p: Effect.Effect<A, E, Layer.Success<typeof layerLive>>) =>
  Effect.provide(p, layerLive) as Effect.Effect<A, E, never>;

// ------------------------------------------------------------------ routes

const routes = async (req: Request): Promise<Response> => {
  const url = new URL(req.url);
  const seg = url.pathname.split('/').filter(Boolean);
  const body = await req
    .json()
    .then((b) => (b && typeof b === 'object' ? (b as Record<string, unknown>) : {}))
    .catch(() => ({}) as Record<string, unknown>);
  const str = (v: unknown) =>
    typeof v === 'string' && v !== '' ? Option.some(v) : Option.none<string>();

  // /api/agents/<id>/<action>
  if (seg[0] === 'api' && seg[1] === 'agents' && seg.length === 4) {
    const [, , id, action] = seg as [string, string, string, string];
    return handle(
      provided(
        Effect.gen(function* () {
          const reg = yield* modules.Registry;
          switch (action) {
            case 'register':
              yield* reg.register(id, str(body.role));
              return { ok: true, id };
            case 'beat':
              // One sentence, in the agent's own words, riding on a call it
              // already makes. Optional: a beat with no summary keeps the
              // previous one and its age rather than blanking it.
              yield* reg.beat(id, str(body.doing));
              return { ok: true, id };
            case 'done':
              yield* reg.deregister(id, str(body.note));
              return { ok: true, id };
            default:
              return { ok: false, error: `unknown action ${action}` };
          }
        }),
      ) as Effect.Effect<unknown, { readonly _tag: string }, never>,
    );
  }

  if (seg[0] === 'api' && seg[1] === 'agents' && seg.length === 2) {
    return handle(
      provided(
        Effect.gen(function* () {
          const reg = yield* modules.Registry;
          return encodeAgents(yield* reg.list());
        }),
      ) as Effect.Effect<unknown, { readonly _tag: string }, never>,
    );
  }

  // /api/subject -- what is being reconstructed, and what produced it.
  if (seg[0] === 'api' && seg[1] === 'subject' && seg.length === 2) {
    return handle(
      provided(
        Effect.gen(function* () {
          const subject = yield* modules.Subject;
          return { subject: yield* subject.ingest(), compIds: yield* subject.compIds() };
        }),
      ) as Effect.Effect<unknown, { readonly _tag: string }, never>,
    );
  }

  // ---- the agent's whole surface: claim, submit, park, release.
  // An agent holds no files, runs no compiler and takes no lock.
  if (seg[0] === 'api' && seg[1] === 'work') {
    const agentId = String(body.agent ?? '');
    const num = (v: unknown) => (typeof v === 'number' ? v : Number(v));
    return handle(
      provided(
        Effect.gen(function* () {
          const work = yield* modules.Work;
          switch (seg[2]) {
            case 'claim':
              return encodeWorkItems(
                yield* work.claim(
                  agentId, Math.min(16, num(body.count ?? 1)), num(body.lease ?? 3600),
                  Array.isArray(body.vas) ? body.vas.map(num) : undefined,
                ),
              );
            case 'submit':
              return encodeVerdict(
                yield* work.submit(
                  agentId, num(body.va), String(body.source ?? ''),
                  String(body.flags ?? SUBJECT_FLAGS),
                  Option.getOrUndefined(str(body.toolchain)),
                ),
              );
            case 'amend':
              return encodeVerdict(
                yield* work.amend(
                  agentId, num(body.va), String(body.source ?? ''),
                  String(body.flags ?? SUBJECT_FLAGS),
                  Option.getOrUndefined(str(body.toolchain)),
                ),
              );
            case 'park':
              // Both fields are required. A park is how a function leaves the
              // queue, and the class is the only part that aggregates into
              // "what is stopping us" -- the figure that decides what gets
              // built next.
              yield* work.park(
                agentId, num(body.va), String(body.blockedClass ?? ''),
                String(body.eliminated ?? ''),
              );
              return { ok: true };
            case 'release': {
              const freed = yield* work.release(agentId, num(body.va));
              return freed
                ? { ok: true, released: true }
                : {
                    ok: false,
                    released: false,
                    error:
                      `${agentId} holds no live claim on 0x${num(body.va).toString(16)}, ` +
                      'so nothing was released',
                  };
            }
            // One call asks every flag set. It costs the compiler, so it needs
            // the same live lease `submit` does, and it writes nothing: a hit
            // under flags the configuration does not name is a finding for a
            // person, not a verdict.
            // Every parked function in a class, with what its author ruled
            // out. Two workers read `near_misses` straight out of the
            // database in one day for want of this.
            case 'parked': {
              const klass = str(body.class ?? (url.searchParams.get('class') ?? ''));
              const want = Number(
                body.limit ?? url.searchParams.get('limit') ?? 25,
              );
              const records = yield* work.parked(klass, Number.isFinite(want) ? want : 25);
              return {
                class: Option.getOrNull(klass),
                parked: records.length,
                records: records.map((r) => ({
                  va: `0x${r.va.toString(16)}`,
                  size: r.size,
                  blockedClass: Option.getOrNull(r.blockedClass),
                  eliminated: Option.getOrNull(r.eliminated),
                  note: Option.getOrNull(r.note),
                  claimed: r.claimed,
                })),
              };
            }
            // MANY SOURCES, ONE FLAG SET -- the mirror of `sweep`, and the
            // call a structural question actually needs. Two workers reported
            // that one HTTP round trip per source spelling, not the
            // reasoning, set their pace.
            case 'probe':
              return encodeProbe(
                yield* work.probe(
                  agentId,
                  num(body.va),
                  Array.isArray(body.sources) ? body.sources.map((x) => String(x)) : [],
                  String(body.flags ?? SUBJECT_FLAGS),
                  Option.getOrUndefined(str(body.toolchain)),
                ),
              );
            case 'sweep':
              return encodeSweep(
                yield* work.sweep(
                  agentId, num(body.va), String(body.source ?? ''),
                  Array.isArray(body.flagSets) && body.flagSets.length > 0
                    ? body.flagSets.map((f) => String(f))
                    : SWEEP_FLAG_SETS,
                  Option.getOrUndefined(str(body.toolchain)),
                ),
              );
            // Why each named address can or cannot be claimed. `claim` with
            // explicit addresses returns fewer rows without saying which were
            // refused or why, and "someone else holds it" and "it is already
            // done" are opposite instructions to a worker.
            case 'claimable': {
              const asked = Array.isArray(body.vas)
                ? body.vas.map(num)
                : (url.searchParams.get('vas') ?? '')
                    .split(',')
                    .filter((x) => x.trim() !== '')
                    .map((x) => Number(x.trim()));
              if (asked.length === 0) {
                return {
                  ok: false,
                  error:
                    'name the addresses: /api/work/claimable?vas=0x5e1110,0x5e1170 ' +
                    'or POST {"vas":[...]}',
                };
              }
              return {
                asked: asked.length,
                addresses: (yield* work.claimable(asked)).map((c) => ({
                  va: `0x${c.va.toString(16)}`,
                  reason: c.reason,
                  size: Option.getOrNull(c.size),
                  // Reported beside `reason`, not folded into it: a parked
                  // function CAN still be claimed by explicit address, which
                  // is how a second pass happens, so parked is not one of the
                  // mutually-exclusive claim verdicts.
                  proven: c.proven,
                  parked: c.parked,
                  blockedClass: Option.getOrNull(c.blockedClass),
                  heldBy: Option.getOrNull(c.heldBy),
                  secondsLeft: Option.getOrNull(c.secondsLeft),
                })),
              };
            }
            // GET or POST; the agent id may come from the query string so
            // this is answerable with a plain `curl` while an agent is mid-run.
            case 'claims': {
              const who = agentId !== '' ? agentId : (url.searchParams.get('agent') ?? '');
              if (who === '') {
                return {
                  ok: false,
                  error: 'name the agent: /api/work/claims?agent=<id>',
                };
              }
              const held = yield* work.claims(who);
              return {
                agent: who,
                held: held.length,
                claims: held.map((c) => ({
                  va: `0x${c.va.toString(16)}`,
                  size: c.size,
                  secondsLeft: c.secondsLeft,
                  proven: c.proven,
                })),
              };
            }
            case 'depth':
              return { depth: yield* work.queueDepth() };
            default:
              return { ok: false, error: `unknown work action ${seg[2]}` };
          }
        }),
      ) as Effect.Effect<unknown, { readonly _tag: string }, never>,
    );
  }

  // /api/composition -- the recorded composition proof, as a fact rather than
  // a run. Assembling the span recompiles every reconstruction and takes
  // minutes, so it is not something an HTTP request starts: `bun src/verify.ts`
  // makes a run, this reads the last one made under the configuration in force.
  if (seg[0] === 'api' && seg[1] === 'composition' && seg.length === 2) {
    return handle(
      provided(
        Effect.gen(function* () {
          const compose = yield* modules.Compose;
          const found = yield* compose.current();
          return Option.isNone(found)
            ? {
                run: null,
                note:
                  'no composition has been made under the configuration currently in ' +
                  'force; run bun src/verify.ts',
              }
            : { run: encodeComposition(found.value) };
        }),
      ) as Effect.Effect<unknown, { readonly _tag: string }, never>,
    );
  }

  // /api/port?state=refused -- which files the portable tree could not render,
  // BY ADDRESS. The Python's port_status.json recorded `"refused": 30` and
  // dropped the identities, so this list did not previously exist.
  if (seg[0] === 'api' && seg[1] === 'port' && seg.length === 2) {
    const asked = url.searchParams.get('state');
    const state: Option.Option<PortState> =
      asked === 'converted' || asked === 'needs_globals' || asked === 'refused'
        ? Option.some(asked)
        : Option.none();
    return handle(
      provided(
        Effect.gen(function* () {
          const portable = yield* modules.Portable;
          const files = yield* portable.files(state);
          return {
            state: Option.getOrNull(state),
            files: files.length,
            vas: files.map((f) => f.va),
          };
        }),
      ) as Effect.Effect<unknown, { readonly _tag: string }, never>,
    );
  }

  // Everything the dashboard renders, in one call, every figure a query.
  if (seg[0] === 'api' && seg[1] === 'status') {
    return handle(
      provided(
        Effect.gen(function* () {
          const m = yield* modules.Metrics;
          const reg = yield* modules.Registry;
          return {
            now: Date.now() / 1000,
            phase2: yield* m.phase2(),
            gate: yield* m.lastGateRun(),
            composition: yield* m.composition(),
            blocked: yield* m.blockedClasses(),
            imports: yield* m.importSurface(),
            symbols: yield* m.symbolMap(),
            port: yield* m.portSurface(),
            progress: yield* m.progress(24 * 3600, 80),
            queue: yield* m.queue(),
            inventory: yield* m.inventoryHealth(),
            blockers: yield* m.blockers(),
            workingOn: Option.match(yield* m.workingOn(), {
              onNone: () => null,
              onSome: (w) => ({ note: w.note, updatedAt: w.updatedAt }),
            }),
            // The globals surface, from the module that owns it rather than
            // a second copy of its queries here. The wasm build needs every
            // global the game reads, so "how many do we know the extent and
            // meaning of" belongs beside the function count, not behind a
            // separate call nobody looks at.
            // `summary()`, never `recorded()`: the full report assembles
            // every entry, deferral and pointer candidate -- tens of
            // thousands of rows -- and this is polled every five seconds.
            globals: yield* (yield* modules.Globals).summary(),
            agents: encodeAgents(yield* reg.list()),
          };
        }),
      ) as Effect.Effect<unknown, { readonly _tag: string }, never>,
    );
  }

  // /api/working-on   what is being worked on right now, in prose
  //
  // Every other figure on the dashboard is derived from evidence, which is
  // what makes them trustworthy and also what makes them silent about
  // intent: the proven count cannot say why the queue was reordered or what
  // the next blocker is. GET reads the note, POST replaces it, and the
  // timestamp is set by the service so it always says when the text was
  // actually written rather than when someone claims it was.
  if (seg[0] === 'api' && seg[1] === 'working-on' && seg.length === 2) {
    return handle(
      provided(
        Effect.gen(function* () {
          const m = yield* modules.Metrics;
          if (req.method === 'POST') {
            const note = typeof body.note === 'string' ? body.note.trim() : '';
            if (note === '') {
              return { ok: false, error: 'body.note must be a non-empty string' };
            }
            // Capped so the panel stays a couple of paragraphs. A note that
            // grows without limit becomes a log, and a log on a status panel
            // is not read.
            if (note.length > 4000) {
              return {
                ok: false,
                error: `body.note is ${note.length} characters; the panel holds 4000`,
              };
            }
            yield* m.setWorkingOn(note);
            return { ok: true, updatedAt: Date.now() / 1000 };
          }
          return Option.match(yield* m.workingOn(), {
            onNone: () => ({
              note: null,
              updatedAt: null,
              note_absent:
                'nothing has been written yet; POST /api/working-on with {"note": "..."}',
            }),
            onSome: (w) => ({ note: w.note, updatedAt: w.updatedAt }),
          });
        }),
      ) as Effect.Effect<unknown, { readonly _tag: string }, never>,
    );
  }

  // /api/disasm/0x4e6ce0?bytes=64   disassemble ANY address
  //
  // There was no way to ask. An agent correcting a misaligned inventory entry
  // had to reach for an outside disassembler to establish that 0x50241E is
  // the second byte of a `call dword ptr [edx+0x16c]` beginning at 0x50241D --
  // a question the service answers for a claimed function and refused to
  // answer for an address. Correcting the inventory is exactly the work that
  // happens OUTSIDE a claim.
  if (seg[0] === 'api' && seg[1] === 'disasm' && seg.length === 3) {
    return handle(
      provided(
        Effect.gen(function* () {
          const raw = seg[2] as string;
          const va = Number.parseInt(raw, raw.startsWith('0x') ? 16 : 10);
          if (!Number.isFinite(va)) {
            return { ok: false, error: `${raw} is not an address` };
          }
          const asked = Number(url.searchParams.get('bytes') ?? 64);
          const length = Math.min(Math.max(Number.isFinite(asked) ? asked : 64, 1), 4096);
          const subject = yield* modules.Subject;
          const current = yield* subject.current();
          if (Option.isNone(current)) {
            return { ok: false, error: 'no subject has been ingested' };
          }
          const s = current.value;
          const img = {
            sha256: s.sha256,
            bytes: yield* subject.imageBytes(),
            imageBase: s.imageBase,
            textLo: s.textLo,
            textHi: s.textHi,
          };
          const off = va - img.imageBase;
          if (off < 0 || off + length > img.bytes.length) {
            return {
              ok: false,
              error:
                `0x${va.toString(16)} + ${length} is outside the image ` +
                `(${`0x${img.imageBase.toString(16)}`}..` +
                `0x${(img.imageBase + img.bytes.length).toString(16)})`,
            };
          }
          const listing = yield* (yield* modules.Disasm).listingOfBytes(
            img.bytes.subarray(off, off + length),
            va,
            `0x${va.toString(16)}`,
          );
          // What the inventory believes about this address, which is the
          // other half of the question when an entry looks misaligned.
          const db = yield* modules.Db;
          const covering = yield* db.one(
            `SELECT va, size FROM functions
              WHERE ? >= va AND ? < va + size ORDER BY va DESC LIMIT 1`,
            [va, va],
          );
          const c = covering as { va: number; size: number } | null;
          return {
            va: `0x${va.toString(16)}`,
            bytes: length,
            listing,
            insideKnownFunction:
              c === null
                ? null
                : {
                    va: `0x${c.va.toString(16)}`,
                    size: c.size,
                    offset: va - c.va,
                    isEntry: va === c.va,
                  },
          };
        }),
      ) as Effect.Effect<unknown, { readonly _tag: string }, never>,
    );
  }

  // /api/imports/0x6353dc   what the service knows about one import slot
  //
  // An agent reported this slot unnamed while the service held
  // `WINMM.dll!timeGetTime` for it, because there was no way to ask about one
  // slot: the name report covers the redirected libraries and the JSON on
  // disk is stale. A fact nobody can look up is a fact nobody has.
  if (seg[0] === 'api' && seg[1] === 'imports' && seg.length === 3) {
    return handle(
      provided(
        Effect.gen(function* () {
          const raw = seg[2] as string;
          const slot = Number.parseInt(raw, raw.startsWith('0x') ? 16 : 10);
          if (!Number.isFinite(slot)) {
            return { ok: false, error: `${raw} is not a slot address` };
          }
          const db = yield* modules.Db;
          const row = (yield* db.one(
            `SELECT dll, name, resolution, blocked_by FROM import_slots WHERE slot = ?`,
            [slot],
          )) as Record<string, unknown> | null;
          if (row === null) {
            return { ok: false, error: `0x${slot.toString(16)} is not an import slot` };
          }
          const dead = yield* db.one(
            'SELECT reason FROM unreferenced_import_slots WHERE slot = ?',
            [slot],
          );
          return {
            slot: `0x${slot.toString(16)}`,
            dll: row.dll,
            name: row.name,
            resolution: row.resolution,
            blockedBy: row.blocked_by,
            // A slot nothing calls needs no implementation.
            unreferenced: dead === null ? null : (dead as { reason: string }).reason,
            // The unit that matters: one slot can serve several APIs.
            callSites: yield* db.all(
              `SELECT call_site, api, evidence FROM import_bindings
                WHERE slot = ? ORDER BY call_site`,
              [slot],
            ),
          };
        }),
      ) as Effect.Effect<unknown, { readonly _tag: string }, never>,
    );
  }

  // /api/discovery              how the inventory is growing, and from what
  // /api/discovery/expand       harvest entries from every proven function
  // /api/discovery/reference     entries from reference evidence -- the strongest rule
  // /api/discovery/remeasure    check recorded sizes against the bytes
  //
  // Discovery used to be a one-off script run by hand, which is how its
  // whitelist of eight prologue bytes survived long enough to reject 14% of
  // our own proven functions unseen. Here it is a capability with a surface:
  // what it found, what evidence found it, and what it set aside and why.
  if (seg[0] === 'api' && seg[1] === 'discovery' && seg.length <= 3) {
    return handle(
      provided(
        Effect.gen(function* () {
          const d = yield* modules.Discovery;
          const db = yield* modules.Db;

          if (seg[2] === 'expand') {
            const rounds = typeof body.rounds === 'number' ? body.rounds : 4;
            const reports = yield* d.expandAll(rounds);
            return {
              rounds: reports.length,
              added: reports.reduce((n, r) => n + r.added, 0),
              reports,
            };
          }

          // Functions nothing points at. Every other rule follows a
          // reference, so none can find one; this works by elimination over
          // the space between known extents.
          if (seg[2] === 'gaps') {
            const g = yield* d.scanGaps(body.add === true);
            return {
              at: g.at,
              textBytes: g.textBytes,
              coveredBytes: g.coveredBytes,
              coveredPct: Number(((100 * g.coveredBytes) / g.textBytes).toFixed(2)),
              gaps: g.gaps,
              paddingGaps: g.paddingGaps,
              paddingBytes: g.paddingBytes,
              residueGaps: g.residueGaps,
              residueBytes: g.residueBytes,
              residuePct: Number(((100 * g.residueBytes) / g.textBytes).toFixed(2)),
              measured: g.measured,
              added: g.added,
              deferred: g.deferred.length,
              // The largest unmeasurable regions first: these are where the
              // remaining executable bytes actually are.
              worst: [...g.deferred]
                .sort((a, b) => b.bytes - a.bytes)
                .slice(0, 25)
                .map((x) => ({
                  va: `0x${x.va.toString(16)}`,
                  bytes: x.bytes,
                  head: x.head,
                  reason: x.reason,
                })),
            };
          }

          if (seg[2] === 'remeasure') {
            // No `vas` means every entry no proof depends on: the whole
            // question of whether the inventory's sizes describe the bytes.
            const vas = Array.isArray(body.vas)
              ? body.vas.filter((v): v is number => typeof v === 'number')
              : (yield* db.all(
                  `SELECT f.va AS va FROM functions f
                    WHERE NOT EXISTS (SELECT 1 FROM proven p WHERE p.va = f.va)
                    ORDER BY f.va`,
                )).map((r: unknown) => (r as { va: number }).va);
            const results = yield* d.remeasure(vas, body.apply === true);
            // Three DISJOINT outcomes. Reporting `agreed` as
            // `checked - disagreed` counted the unmeasurable as agreeing,
            // which read as "3 checked, 3 agreed" over a set where two
            // addresses had produced no measurement at all.
            const unmeasurable = results.filter((r) => Option.isNone(r.measured));
            const disagreed = results.filter(
              (r) => Option.isSome(r.measured) && r.measured.value !== r.recorded,
            );
            const hex = (n: number) => `0x${n.toString(16)}`;
            return {
              checked: results.length,
              agreed: results.length - disagreed.length - unmeasurable.length,
              disagreed: disagreed.length,
              applied: results.filter((r) => r.applied).length,
              // Named, not counted: an address whose extent cannot be measured
              // is a question for the decoder, and a bare total asks nobody.
              unmeasurable: unmeasurable.slice(0, 200).map((r) => ({
                va: hex(r.va),
                recorded: r.recorded,
                boundedBy: hex(r.nextEntry),
              })),
              unmeasurableTotal: unmeasurable.length,
              disagreements: disagreed.slice(0, 200).map((r) => ({
                va: hex(r.va),
                recorded: r.recorded,
                measured: Option.getOrNull(r.measured),
                boundedBy: hex(r.nextEntry),
                applied: r.applied,
              })),
            };
          }

          // An address judged not to be a function entry. Stored with the
          // decode that justifies it, because a deletion does not survive the
          // next producer pass -- three rows came back that way.
          if (seg[2] === 'reject') {
            const entries = Array.isArray(body.entries)
              ? body.entries.flatMap((e) => {
                  const o = e as { va?: unknown; reason?: unknown };
                  return typeof o.va === 'number' && typeof o.reason === 'string'
                    ? [{ va: o.va, reason: o.reason }]
                    : [];
                })
              : [];
            if (entries.length === 0) {
              return {
                ok: false,
                error: 'body.entries must hold { va: number, reason: string } objects',
              };
            }
            const outcomes = yield* d.reject(entries);
            return {
              accepted: outcomes.filter((o) => o.accepted).length,
              refused: outcomes
                .filter((o) => !o.accepted)
                .map((o) => ({
                  va: `0x${o.va.toString(16)}`,
                  because: Option.getOrNull(o.refusedBecause),
                })),
              // The point of a rejection: the predecessor it was truncating
              // can now be measured.
              unblocked: outcomes
                .flatMap((o) => o.unblocks)
                .map((va) => `0x${va.toString(16)}`),
            };
          }

          // How many inventory entries can an agent actually work on? An
          // entry whose recorded size cuts mid-instruction decodes to
          // nothing, so the agent is handed an empty listing and the address
          // can never leave the queue. Nothing errors, so nothing asks.
          if (seg[2] === 'workability') {
            const a = yield* d.auditWorkability(body.repair === true);
            return {
              at: a.at,
              entries: a.entries,
              workable: a.workable,
              undecodable: a.undecodable.length,
              repaired: a.undecodable.filter((x) => x.repaired).length,
              // Split out, because a PROVEN entry that does not decode is a
              // different and worse problem: the proof was taken against a
              // span the decoder now refuses.
              undecodableProven: a.undecodable.filter((u) => u.proven).length,
              repairable: a.undecodable.filter(
                (u) => !u.proven && Option.isSome(u.measured),
              ).length,
              worst: a.undecodable.slice(0, 50).map((u) => ({
                va: `0x${u.va.toString(16)}`,
                recorded: u.size,
                measured: Option.getOrNull(u.measured),
                proven: u.proven,
                repaired: u.repaired,
                covered: u.covered,
              })),
            };
          }

          // An entry an agent established by reading the bytes. Checked, not
          // trusted: it must decode, it must measure, and it must not sit
          // inside a function that has a proof.
          // The strongest rule the project has, and nothing was running it:
          // `Disasm.discover` had no caller, no route and no job while the
          // inventory grew from layout instead.
          if (seg[2] === 'reference') {
            const r = yield* d.discoverByReference(body.add === true);
            return {
              candidates: r.candidates,
              measured: r.measured,
              added: r.added,
              compilerGenerated: r.compilerGenerated,
              rejectedOnRecord: r.rejectedOnRecord,
              refusals: r.refusals,
              largest: r.largest.map((f) => ({ va: `0x${f.va.toString(16)}`, size: f.size })),
            };
          }
          if (seg[2] === 'unreject') {
            const entries = Array.isArray(body.entries)
              ? body.entries.flatMap((e) => {
                  const o = e as { va?: unknown; reason?: unknown };
                  return typeof o.va === 'number' && typeof o.reason === 'string'
                    ? [{ va: o.va, reason: o.reason }]
                    : [];
                })
              : [];
            if (entries.length === 0) {
              return {
                ok: false,
                error: 'body.entries must hold { va: number, reason: string } objects',
              };
            }
            return { outcomes: yield* d.unreject(entries) };
          }
          if (seg[2] === 'entry') {
            const entries = Array.isArray(body.entries)
              ? body.entries.flatMap((e) => {
                  const o = e as { va?: unknown; evidence?: unknown };
                  return typeof o.va === 'number' && typeof o.evidence === 'string'
                    ? [{ va: o.va, evidence: o.evidence }]
                    : [];
                })
              : [];
            if (entries.length === 0) {
              return {
                ok: false,
                error: 'body.entries must hold { va: number, evidence: string } objects',
              };
            }
            const outcomes = yield* d.recordEntry(entries);
            return {
              accepted: outcomes
                .filter((o) => o.accepted)
                .map((o) => ({
                  va: `0x${o.va.toString(16)}`,
                  size: Option.getOrNull(o.size),
                })),
              refused: outcomes
                .filter((o) => !o.accepted)
                .map((o) => ({
                  va: `0x${o.va.toString(16)}`,
                  because: Option.getOrNull(o.refusedBecause),
                })),
            };
          }

          if (seg[2] === 'rejections') {
            const rows = yield* d.rejections();
            return {
              total: rows.length,
              rejections: rows.map((r) => ({
                va: `0x${r.va.toString(16)}`,
                reason: r.reason,
                evidence: r.evidence,
              })),
            };
          }

          if (seg[2] !== undefined) {
            return { ok: false, error: `unknown discovery action ${seg[2]}` };
          }

          // Delegated, not re-queried. This route had its own copy of the
          // evidence breakdown next to the one the dashboard reads through
          // Metrics, which is two answers to one question waiting to
          // disagree the first time either is edited.
          const health = yield* (yield* modules.Metrics).inventoryHealth();
          return {
            byEvidence: health.byEvidence,
            total: { functions: health.byEvidence.reduce((n, e) => n + e.functions, 0) },
            rejected: { addresses: health.rejected },
            workability: Option.getOrNull(health.audit),
          };
        }),
      ) as Effect.Effect<unknown, { readonly _tag: string }, never>,
    );
  }

  // /api/names            what is recorded
  // /api/names/recover    read it out of the bytes again
  //
  // Re-running is a route rather than something the boot does, because it
  // decodes the whole executable span: the answer only changes when the
  // inventory does, and re-deriving it on every start would pay for that on
  // every start. It replaces the whole derivation for the subject, so a name
  // it no longer finds is gone rather than left looking current.
  if (seg[0] === 'api' && seg[1] === 'names' && seg.length <= 3) {
    return handle(
      provided(
        Effect.gen(function* () {
          const names = yield* modules.Names;
          if (seg[2] === 'recover') return { report: encodeNames(yield* names.recover()) };
          if (seg[2] !== undefined) {
            return { ok: false, error: `unknown names action ${seg[2]}` };
          }
          const found = yield* names.recorded();
          return Option.isNone(found)
            ? {
                report: null,
                note:
                  'no names have been recovered for the subject currently in force; ' +
                  'call /api/names/recover',
              }
            : { report: encodeNames(found.value) };
        }),
      ) as Effect.Effect<unknown, { readonly _tag: string }, never>,
    );
  }

  // /api/globals                   the inventory as recorded
  // /api/globals/rebuild           re-derive it now
  // /api/globals/deferrals         every question the evidence does not settle
  // /api/globals/0x684480          one global and the functions that touch it
  //
  // Re-deriving is also a timer below, because the inventory CONVERGES: each
  // new proof turns the literals in one more function from a decode into a
  // fact about verified bytes. A route exists so it can be forced after an
  // ingest without waiting for the tick.
  if (seg[0] === 'api' && seg[1] === 'globals' && seg.length <= 3) {
    return handle(
      provided(
        Effect.gen(function* () {
          const globals = yield* modules.Globals;
          if (seg[2] === 'rebuild') return { report: encodeGlobals(yield* globals.rebuild()) };
          if (seg[2] === 'deferrals') {
            const deferred = yield* globals.deferrals();
            return {
              deferrals: deferred.length,
              addresses: deferred.map((d) => ({
                address: d.address,
                what: d.what,
                reason: d.reason,
              })),
            };
          }
          if (seg[2] !== undefined) {
            const address = Number.parseInt(seg[2], seg[2].startsWith('0x') ? 16 : 10);
            if (!Number.isFinite(address)) {
              return { ok: false, error: `${seg[2]} is not an address` };
            }
            const found = yield* globals.at(address);
            return Option.isNone(found)
              ? { global: null, note: 'no evidence places a global at that address' }
              : { global: encodeGlobal(found.value) };
          }
          const found = yield* globals.recorded();
          return Option.isNone(found)
            ? {
                report: null,
                note:
                  'no globals have been inventoried for the subject currently in force; ' +
                  'call /api/globals/rebuild',
              }
            : { report: encodeGlobals(found.value) };
        }),
      ) as Effect.Effect<unknown, { readonly _tag: string }, never>,
    );
  }

  if (seg[0] === 'api' && seg[1] === 'health') {
    // 503 when a check fails, so a monitor or a supervisor can act on it.
    // Answering 200 whatever the state is what let a broken submit path
    // serve errors for 75 minutes.
    const h = healthCheck(dbHandle());
    const canary = canaryState();
    // The gate is part of being healthy. Twice now a work path has been dead
    // while health answered ok:true, because no check exercised it. A canary
    // that has run and failed turns health red; one that has not run yet is
    // not evidence either way and does not.
    const gateOk = Option.isNone(canary) || canary.value.ok;
    const ok = h.ok && gateOk;
    return json(
      {
        ...h,
        ok,
        compiler: throttleStats(),
        gate: Option.isNone(canary)
          ? { state: 'not yet probed' }
          : { state: canary.value.ok ? 'ok' : 'FAILING', ...canary.value },
      },
      ok ? 200 : 503,
    );
  }

  return json({ error: 'not found', path: url.pathname }, 404);
};

// ----------------------------------------------------------------- workers

/**
 * What a worker failure actually was.
 *
 * `Effect.runPromise` rejects with the typed failure itself, and a
 * `Schema.TaggedError` has an empty `message`: reading only that printed a
 * worker's label and nothing else, which reads as a successful quiet tick.
 */
const describeFailure = (cause: unknown): string => {
  if (cause !== null && typeof cause === 'object') {
    const tagged = cause as { _tag?: unknown; message?: unknown };
    if (typeof tagged._tag === 'string') {
      const fields = Object.entries(cause as Record<string, unknown>)
        .filter(([key]) => key !== '_tag')
        .map(([key, value]) => `${key}=${typeof value === 'string' ? value : JSON.stringify(value)}`)
        .join(' ');
      return fields === '' ? tagged._tag : `${tagged._tag}: ${fields}`;
    }
    if (cause instanceof Error) {
      return cause.message === '' ? (cause.stack ?? String(cause)) : cause.message;
    }
    return JSON.stringify(cause);
  }
  return String(cause);
};

/**
 * Server-owned background work. Each loop is self-limiting: it does what
 * there is to do and sleeps. None of them is startable by hand, because a
 * second copy would contend for the same rows.
 */
const supervise = () => {
  /**
   * A server-owned job, on an interval, with its FIRST run delayed.
   *
   * `void tick()` fired every job the moment the server started. Each of
   * these is heavy and synchronous -- the inventory audit decodes all 6,982
   * entries, the portable tree converts 3,321 reconstructions, the globals
   * inventory walks the whole data region -- so starting them together
   * saturated the event loop, `/api/health` could not be answered, and the
   * supervisor's three probes timed out and killed the process. It then
   * booted, did the same thing, and was killed again: a restart loop the
   * service could not escape, and every restart began by redoing the work
   * that caused it.
   *
   * So the first run waits. Boot finishes, health answers, agents can claim,
   * and the heavy work starts afterwards -- staggered, so two jobs do not
   * block the loop at the same moment.
   */
  const every = (
    label: string,
    seconds: number,
    body: () => Promise<void>,
    firstRunAfterSeconds = 0,
  ) => {
    const tick = async () => {
      try {
        await body();
      } catch (e) {
        // A worker must never die of one bad iteration; the next tick retries.
        //
        // A tagged failure carries its detail in its FIELDS, not in
        // `message` -- Schema.TaggedError leaves that empty -- so printing
        // only the message logged `[globals] ` with nothing after it and the
        // worker looked like it had run. The tag and the fields are what say
        // what went wrong.
        console.error(`[${label}] ${describeFailure(e)}`);
      }
    };
    if (firstRunAfterSeconds <= 0) void tick();
    else setTimeout(() => void tick(), firstRunAfterSeconds * 1000);
    return setInterval(() => void tick(), seconds * 1000);
  };

  // WHAT THE QUEUE SHOULD HAND OUT NEXT, measured rather than guessed.
  //
  // The queue orders by size band and then by whether a function can actually
  // be finished -- branch density, with x87 and jump tables pushed to the
  // back. Those facts come from decoding the function, which is far too
  // expensive to do inside a claim: a claim already came close to tripping
  // the supervisor's watchdog once.
  //
  // So it is measured here, incrementally, and a function whose recorded
  // extent has since been corrected is re-measured because the old number was
  // about different bytes. 500 at a time keeps any single pass short.
  every('closability', 600, async () => {
    const r = await Effect.runPromise(
      provided(
        Effect.gen(function* () {
          return yield* (yield* modules.Work).measureClosability(500);
        }),
      ),
    );
    if (r.measured > 0) {
      console.log(
        `[closability] measured ${r.measured} function(s), ${r.vetoed} with x87 or a ` +
          `jump table; ${r.remaining} still unmeasured`,
      );
    }
  }, 120);

  // Expiring a lease is how work from a dead agent returns to the queue.
  // Nothing notices an agent died; the lease simply runs out.
  // Discovery is a consequence of progress, not a chore. Every proof makes
  // its call targets verified facts, so the inventory grows on its own as the
  // proven set does. It was previously a one-off script nobody ran, which is
  // how 385 functions sat undiscovered in the data for the whole project.
  every('discovery', 600, async () => {
    const reports = await Effect.runPromise(
      provided(
        Effect.gen(function* () {
          const d = yield* modules.Discovery;
          return yield* d.expandAll(3);
        }),
      ),
    );
    const added = reports.reduce((a, r) => a + r.added, 0);
    if (added > 0) console.log(`[discovery] ${added} new function(s) entered the inventory`);
  }, 90); // first run delayed: decodes every proven function to harvest call targets

  // Does the inventory describe the bytes? An entry whose recorded extent
  // does not decode reaches an agent with no readable body, and before this
  // existed nothing asked: two such entries sat in the queue recorded 436
  // and 482 bytes short of their true extents, and only turned up because
  // their sizes were being checked for an unrelated reason.
  //
  // `repair: true` is deliberate. It only writes where the recorded extent
  // ALREADY fails to decode -- so the stored size is unusable either way --
  // and never touches a proven function, whose span a proof was taken
  // against. Replacing an unusable size with a measured one cannot lose
  // information, and leaving it for someone to run by hand is how the last
  // standing task became a script nobody ran.
  every('inventory audit', 900, async () => {
    const a = await Effect.runPromise(
      provided(
        Effect.gen(function* () {
          const d = yield* modules.Discovery;
          return yield* d.auditWorkability(true);
        }),
      ),
    );
    const repaired = a.undecodable.filter((u) => u.repaired).length;
    if (a.undecodable.length > 0 || repaired > 0) {
      console.log(
        `[inventory] ${a.workable}/${a.entries} entries decode; ` +
          `${a.undecodable.length} do not (${repaired} repaired this pass)`,
      );
    }
  }, 150); // first run delayed: decodes all 6,982 inventory entries

  // How much of the game's code is still invisible to every discovery rule.
  //
  // The rules all follow a reference -- a call inside a proven function, a
  // pointer in a table -- so a function nothing references cannot be found by
  // any of them, however many rounds they run. This measures the space
  // between known functions and records what is in it. `add` is false: the
  // regions are real code, with prologues to prove it, but their extents
  // cannot yet be measured honestly, and a wrong size reaches an agent as a
  // function with no readable body.
  every('gap scan', 1800, async () => {
    const g = await Effect.runPromise(
      provided(
        Effect.gen(function* () {
          const d = yield* modules.Discovery;
          return yield* d.scanGaps(false);
        }),
      ),
    );
    console.log(
      `[gaps] ${((100 * g.coveredBytes) / g.textBytes).toFixed(2)}% of executable bytes ` +
        `claimed; ${g.residueBytes} byte(s) in ${g.residueGaps} gap(s) are unfound code ` +
        `(${((100 * g.residueBytes) / g.textBytes).toFixed(2)}%)`,
    );
  }, 390); // first run delayed: decodes the whole executable span

  // THE WHOLE-TREE PROOF, which was not running at all.
  //
  // Every `submit` compiles one reconstruction and compares its bytes, so
  // per-function verification has never stopped. The COMPOSITION proof is a
  // different question: it recompiles every reconstruction in force, places
  // each at its real address, and diffs the assembled span against the
  // subject. That is what catches two functions claiming overlapping bytes,
  // or a reconstruction that stops matching once its neighbours are placed
  // around it.
  //
  // It existed only as `bun src/verify.ts`, run by hand. It last ran 21 hours
  // ago over 2,614 functions while 3,356 are now proven, so 742 of them had
  // never been through it. "Proved individually" and "proved together" are
  // different claims and only the first was being made.
  //
  // Gated on the proven set having CHANGED since the last run, because the
  // run recompiles thousands of functions through one serialised compiler and
  // repeating it over an unchanged set would take compile slots from agents
  // to re-answer a question nothing had altered.
  every('composition proof', 1800, async () => {
    const outcome = await Effect.runPromise(
      provided(
        Effect.gen(function* () {
          const db = yield* modules.Db;
          const now = (yield* db.one('SELECT COUNT(*) AS n FROM proven')) as { n: number };

          // A run claims its row before it starts work, so an unfinished row
          // means one is either still going or was killed. Starting a second
          // one alongside it would put two composers through the single
          // compiler and make the pair take longer than either -- so a live
          // run is waited for, and an abandoned one is not waited for
          // forever. The cutoff is generous against the ~7 minutes a run
          // takes; past it the row can only be a casualty of a restart.
          const inFlight = (yield* db.one(
            `SELECT started_at FROM composition_runs
              WHERE finished_at IS NULL
                AND started_at > ?
              ORDER BY started_at DESC LIMIT 1`,
            [Date.now() / 1000 - 1800],
          )) as { started_at: number } | null;
          if (inFlight !== null) return { skipped: true as const, proven: now.n };

          // Compare against the last run that FINISHED. An abandoned row
          // records an attempt and says nothing about the proven set, so
          // treating it as the baseline would skip the work it failed to do.
          const last = (yield* db.one(
            `SELECT considered FROM composition_runs
              WHERE finished_at IS NOT NULL
              ORDER BY finished_at DESC LIMIT 1`,
          )) as { considered: number } | null;
          if (last !== null && last.considered === now.n) {
            return { skipped: true as const, proven: now.n };
          }
          const r = yield* (yield* modules.Compose).run();
          return { skipped: false as const, run: r, proven: now.n };
        }),
      ),
    );
    if (outcome.skipped) return;
    const r = outcome.run;
    console.log(
      `[composition] placed ${r.placed} of ${r.considered} reconstruction(s), ` +
        `${r.placedBytes} byte(s), ${r.diffBytes} differing`,
    );
    if (r.diffBytes > 0) {
      console.error(
        `[composition] THE ASSEMBLED SPAN DIFFERS FROM THE SUBJECT in ` +
          `${r.diffBytes} byte(s) -- functions that pass individually do not ` +
          'agree once placed together',
      );
    }
  }, 450); // first run delayed: recompiles every reconstruction in force

  // The portable tree is a CONSEQUENCE of the proven set, like discovery.
  // It had been run once, covering 2,614 files while 3,314 were proven, so
  // ~700 recoveries had never been converted and nothing closed the gap as
  // the set grew. generate() always converts everything in force; it just
  // needed an owner.
  every('portable', 900, async () => {
    const r = await Effect.runPromise(
      provided(
        Effect.gen(function* () {
          const p = yield* modules.Portable;
          // INTO THE TREE, not nowhere. This passed `None`, which records
          // every file's outcome in `port_files` and writes no file at all --
          // so the 2,490 files on disk were the old Python script's, four
          // days stale, while the service's conversion existed only as rows.
          // The browser build compiles the tree, so the tree has to be what
          // the service produced.
          return yield* p.generate(Option.some(PORTABLE_TREE_PATH));
        }),
      ),
    );
    const n = (r as { converted?: number }).converted ?? 0;
    if (n > 0) console.log(`[portable] ${n} reconstruction(s) converted for the browser build`);
  }, 210); // first run delayed: converts every reconstruction for the browser build

  // Naming import slots is also a consequence of the proven set: every CRT
  // function identified makes its library object's relocation table readable,
  // and those relocations name the Windows APIs the object calls. Run once by
  // hand it named 10 slots; it should converge as identification grows rather
  // than wait for someone to re-run it.
  every('import-names', 1800, async () => {
    const r = await Effect.runPromise(
      provided(
        Effect.gen(function* () {
          const n = yield* modules.ImportNames;
          return yield* n.nameImportSlots();
        }),
      ),
    );
    // What this run CHANGED. `slotsNamed` is the derivation's whole answer,
    // which does not shrink as the names are stored, so logging it reported
    // the same ten slots as newly named on every tick for as long as the
    // worker had been scheduled.
    const named = r.slotsNewlyNamed.length;
    if (named > 0) {
      console.log(`[import-names] ${named} slot(s) named from library relocations: ` +
        r.slotsNewlyNamed.map((s) => `0x${s.slot.toString(16).toUpperCase()}=${s.name}`).join(' '));
    }
  }, 330); // first run delayed: re-derives every import binding from the libraries

  // The globals inventory is a CONSEQUENCE of the proven set, like discovery
  // and the portable tree. Every new proof turns the literal addresses in one
  // more function from a decode into a fact about bytes this project
  // reproduces, so the inventory's strongest evidence class grows on its own
  // -- and an inventory derived once would describe a proven set that no
  // longer exists.
  every('globals', 1200, async () => {
    const report = await Effect.runPromise(
      provided(
        Effect.gen(function* () {
          const globals = yield* modules.Globals;
          return yield* globals.rebuild();
        }),
      ),
    );
    const proven = report.byEvidence.find((e) => e.evidence === 'proven-literal')?.globals ?? 0;
    console.log(
      `[globals] ${report.globals} global(s), ${proven} evidenced by a proven function, ` +
        `${report.named} named, ${report.sized} sized`,
    );
  }, 270); // first run delayed: walks the whole data region

  every('reaper', 30, async () => {
    const freed = await Effect.runPromise(
      provided(
        Effect.gen(function* () {
          const work = yield* modules.Work;
          return yield* work.reapExpiredClaims();
        }),
      ),
    );
    if (freed > 0) console.log(`[reaper] returned ${freed} expired claim(s) to the queue`);
  });
};

// -------------------------------------------------------------------- boot

const applied = await run(
  provided(
    Effect.gen(function* () {
      const db = yield* modules.Db;
      return yield* db.migrate();
    }),
  ),
);
if (applied.length > 0) console.log(`migrations applied: ${applied.join(', ')}`);

/**
 * Record the subject, and read the guest out of the RAM image if this subject
 * has not been read before.
 *
 * Keyed on the subject's own hash, so a different dump is a different subject
 * with no rows and is mapped automatically -- there is no staleness to notice
 * and no command anyone has to remember to run. Re-reading does not retract
 * anything: these are derived facts about the binary, and verdicts are retired
 * by the superseded view alone.
 */
const subjectSummary = await run(
  provided(
    Effect.gen(function* () {
      const subject = yield* modules.Subject;
      const db = yield* modules.Db;
      const recorded = yield* subject.ingest();
      // Keyed on guest_modules, which only the guest read produces. import_slots
      // is written by the legacy import as well, from the Python's JSON, so an
      // emptiness test on it would skip the derivation and leave the imported
      // copy as the answer. Both agree row-for-row today; the derivation from
      // the subject's own bytes is the one that must win, because the JSON can
      // be edited behind the service's back and the bytes cannot.
      const mapped = yield* db.one(
        'SELECT COUNT(*) AS n FROM guest_modules WHERE subject_sha = ?',
        [recorded.sha256],
      );
      // THE DUMP SET IS THE TRIGGER for re-reading the import surface.
      //
      // This used to skip the whole derivation whenever `guest_modules` had
      // rows, which made it a one-time job. A second memory dump then sat on
      // disk for hours changing nothing -- and a dump is new evidence, not a
      // duplicate: SafeDisc records a slot's API only once the game calls
      // through it, so each capture answers for the slots its session
      // exercised. The first leaves 54 of 255 unanswered, and the only way
      // to close that is more captures.
      //
      // So the surface is re-read when the set of dumps on disk differs from
      // the set `import_dumps` says was read. Identity is the name and the
      // size, which notices a new or replaced capture without hashing 512MB.
      // Identity is name, size AND modification time. Size alone cannot tell
      // two captures apart -- every capture of the same region is 512MB -- so
      // replacing a weak dump with a strong one left name and size identical
      // and this never fired.
      const onDisk = guestRamPaths().map((p) => {
        const st = fs.statSync(p);
        return {
          dump: p.split('/').pop() ?? p,
          bytes: st.size,
          mtime: st.mtimeMs / 1000,
        };
      });
      const readBefore = (yield* db.all(
        'SELECT dump, bytes, mtime FROM import_dumps WHERE subject_sha = ?',
        [recorded.sha256],
      )) as ReadonlyArray<{ dump: string; bytes: number; mtime: number }>;
      const key = (rows: ReadonlyArray<{ dump: string; bytes: number; mtime: number }>) =>
        [...rows]
          .map((r) => `${r.dump}:${r.bytes}:${Math.round(r.mtime)}`)
          .sort()
          .join('|');
      const dumpsChanged = key(onDisk) !== key(readBefore);

      if ((mapped as { n: number }).n > 0 && !dumpsChanged) return Option.none<string>();
      if (dumpsChanged && readBefore.length > 0) {
        console.log(
          `[imports] the dump set changed (${readBefore.length} read before, ` +
            `${onDisk.length} on disk); re-reading the import surface`,
        );
      }
      const guest = yield* subject.mapGuestModules();
      const imports = yield* subject.mapImports();
      for (const d of imports.byDump) {
        console.log(
          `[imports] ${d.dump}: CR3 0x${d.cr3.toString(16)}, loader at ` +
            `0x${d.loaderBase.toString(16)}, offered ${d.bindingsOffered} binding(s), ` +
            `added ${d.bindingsAdded} new` +
            (d.contradictions.length > 0
              ? `, ${d.contradictions.length} CONTRADICTING an earlier dump`
              : ''),
        );
        for (const c of d.contradictions.slice(0, 10)) {
          console.error(
            `[imports] CONTRADICTION slot 0x${c.slot.toString(16)} call site ` +
              `0x${c.callSite.toString(16)}: recorded ${c.existing}, ${d.dump} says ${c.offered}`,
          );
        }
      }
      const crt = yield* subject.identifyCrtFunctions();
      return Option.some(
        `${guest.modules} guest modules, ${guest.exports} exports (${guest.named} named); ` +
          `${imports.slots} import slots, ${imports.bindings} call-site bindings naming ` +
          `${imports.distinctApis} APIs; ${crt.addressesNamed} CRT addresses identified`,
      );
    }),
  ),
);
console.log(`subject recorded`);
if (Option.isSome(subjectSummary)) console.log(`  ${subjectSummary.value}`);

supervise();

// LISTEN FIRST. A degraded service that answers /api/health is diagnosable;
// one that refuses to bind is a silent outage, and blocking boot on a probe
// is how this file previously deadlocked against its own reaper.
const server = Bun.serve({ port: PORT, fetch: routes });
console.log(`decomp service on http://127.0.0.1:${server.port}`);

// Report our own health immediately, and keep reporting it. A failure is
// announced in the log the moment it appears rather than waiting to be
// discovered by whoever loses work to it.
{
  const say = () => {
    const h = healthCheck(dbHandle());
    if (!h.ok) console.error(healthReport(h));
    return h.ok;
  };
  const ok = say();
  console.log(ok ? healthReport(healthCheck(dbHandle())) : 'SERVING DEGRADED');
  setInterval(() => void say(), 60_000);
}

// One real compilation every three minutes. A gate that cannot compile is a
// service that cannot do its job, however green its SQL looks.
superviseCanary(180);
