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
import { Effect, Layer, Option, pipe } from 'effect';
import { check as healthCheck, report as healthReport } from './health';
import { throttleStats } from './modules/gate/throttle';
import { canaryState, superviseCanary } from './canary';
import { modules } from './modules';
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
  encodeVerdict, encodeWorkItems,
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
  ({ UnknownAgent: 404, UnknownFunction: 404, NotClaimed: 409, DbError: 500 })[tag] ?? 500;

const handle = async (
  program: Effect.Effect<unknown, { readonly _tag: string }, never>,
): Promise<Response> => {
  // Effect 4's Result carries `success` / `failure`, not `value`. Reading the
  // wrong field handed `undefined` to Response.json, which threw rather than
  // returning anything -- a silent 500 on every successful call.
  const result = await Effect.runPromise(Effect.result(program));
  if (result._tag === 'Success') return json(result.success);
  const failure = result.failure as { _tag: string } & Record<string, unknown>;
  return json(
    { error: failure._tag, detail: failure },
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
              yield* reg.beat(id);
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
                ),
              );
            case 'amend':
              return encodeVerdict(
                yield* work.amend(
                  agentId, num(body.va), String(body.source ?? ''),
                  String(body.flags ?? SUBJECT_FLAGS),
                ),
              );
            case 'park':
              yield* work.park(
                agentId, num(body.va), String(body.blockedClass ?? ''),
                String(body.eliminated ?? ''),
              );
              return { ok: true };
            case 'release':
              yield* work.release(agentId, num(body.va));
              return { ok: true };
            // One call asks every flag set. It costs the compiler, so it needs
            // the same live lease `submit` does, and it writes nothing: a hit
            // under flags the configuration does not name is a finding for a
            // person, not a verdict.
            case 'sweep':
              return encodeSweep(
                yield* work.sweep(
                  agentId, num(body.va), String(body.source ?? ''),
                  Array.isArray(body.flagSets) && body.flagSets.length > 0
                    ? body.flagSets.map((f) => String(f))
                    : SWEEP_FLAG_SETS,
                ),
              );
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
            agents: encodeAgents(yield* reg.list()),
          };
        }),
      ) as Effect.Effect<unknown, { readonly _tag: string }, never>,
    );
  }

  // /api/discovery              how the inventory is growing, and from what
  // /api/discovery/expand       harvest entries from every proven function
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

          // Derived by query, never a stored scalar: the inventory IS the
          // answer to "how was each function found".
          return {
            byEvidence: yield* db.all(
              `SELECT COALESCE(discovered_by, 'pre-existing') AS evidence,
                      COUNT(*) AS functions,
                      SUM(CASE WHEN EXISTS
                        (SELECT 1 FROM proven p WHERE p.va = f.va)
                        THEN 1 ELSE 0 END) AS proven
                 FROM functions f
                GROUP BY evidence ORDER BY functions DESC`,
            ),
            total: yield* db.one('SELECT COUNT(*) AS functions FROM functions'),
            rejected: yield* db.one(
              'SELECT COUNT(*) AS addresses FROM rejected_entries',
            ),
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
 * Server-owned background work. Each loop is self-limiting: it does what
 * there is to do and sleeps. None of them is startable by hand, because a
 * second copy would contend for the same rows.
 */
const supervise = () => {
  const every = (label: string, seconds: number, body: () => Promise<void>) => {
    const tick = async () => {
      try {
        await body();
      } catch (e) {
        // A worker must never die of one bad iteration; the next tick retries.
        console.error(`[${label}] ${e instanceof Error ? e.message : String(e)}`);
      }
    };
    void tick();
    return setInterval(() => void tick(), seconds * 1000);
  };

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
  });

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
          return yield* p.generate(Option.none());
        }),
      ),
    );
    const n = (r as { converted?: number }).converted ?? 0;
    if (n > 0) console.log(`[portable] ${n} reconstruction(s) converted for the browser build`);
  });

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
    // `slotsNamed` is the LIST of slots it named, not a count.
    const named = r.slotsNamed.length;
    if (named > 0) {
      console.log(`[import-names] ${named} slot(s) named from library relocations: ` +
        r.slotsNamed.map((s) => `0x${s.slot.toString(16).toUpperCase()}=${s.name}`).join(' '));
    }
  });

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
  });

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
      if ((mapped as { n: number }).n > 0) return Option.none<string>();
      const guest = yield* subject.mapGuestModules();
      const imports = yield* subject.mapImports();
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
