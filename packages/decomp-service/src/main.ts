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
import { modules } from './modules';
import { ComposeImpl } from './modules/compose/impl';
import { DbImpl } from './modules/db/impl';
import { DisasmImpl } from './modules/disasm/impl';
import { GateImpl } from './modules/gate/impl';
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
  encodeAgents, encodeComposition, encodeNames, encodeSweep, encodeVerdict,
  encodeWorkItems,
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
  Layer.provideMerge(GateImpl.Layer),
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
                ),
              );
            case 'submit':
              return encodeVerdict(
                yield* work.submit(
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

  if (seg[0] === 'api' && seg[1] === 'health') {
    return json({ ok: true, at: Date.now() / 1000 });
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

const server = Bun.serve({ port: PORT, fetch: routes });
console.log(`decomp service on http://127.0.0.1:${server.port}`);
