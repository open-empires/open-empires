/**
 * Periodically compile something trivial, so a broken gate is visible.
 *
 * `/api/health` compiles every SQL statement against the live schema, which
 * is why a stray paren in an INSERT can no longer ship. It does not touch the
 * COMPILER, and that gap has now cost twice:
 *
 *   - a one-character SQL error took `submit` down for 75 minutes while
 *     health reported `{ok:true}`
 *   - a `ReferenceError: effunct is not defined` in the gate took `sweep`
 *     down while health again reported `{ok:true}`, because none of its seven
 *     checks invokes the gate at all
 *
 * The lesson both times is the same: a check that does not exercise a path
 * cannot see that path break. So this runs one real compilation of a trivial
 * source on an interval and records the outcome. A route failing for ANY
 * reason -- bad SQL, a missing symbol, a dead container, a leaked compile
 * permit -- turns health red within one interval instead of whenever someone
 * notices.
 *
 * It is cheap on purpose: one small compile every few minutes, taking one of
 * six permits, so it can never be the reason the gate is busy.
 */
import { Effect, Layer, Option, pipe } from 'effect';
import { modules } from './modules';
import { DbImpl } from './modules/db/impl';
import { GateImpl } from './modules/gate/impl';
import { SubjectImpl } from './modules/subject/impl';
import { SUBJECT_FLAGS } from './modules/gate/interface';

export interface CanaryState {
  readonly ok: boolean;
  readonly at: number;
  readonly detail: string;
  readonly ms: number;
}

const KEY = Symbol.for('open-empires.gate.canary');

const slot = (): { current: Option.Option<CanaryState> } => {
  const g = globalThis as Record<symbol, unknown>;
  const existing = g[KEY];
  if (existing !== undefined) return existing as { current: Option.Option<CanaryState> };
  const fresh = { current: Option.none<CanaryState>() };
  g[KEY] = fresh;
  return fresh;
};

export const canaryState = (): Option.Option<CanaryState> => slot().current;

const layer = pipe(
  GateImpl.Layer,
  Layer.provideMerge(SubjectImpl.Layer),
  Layer.provideMerge(DbImpl.Layer),
);

/**
 * A source whose EXACT bytes do not matter: the question is whether the gate
 * can compile anything at all and hand back a coherent verdict. Compared
 * against four bytes of the subject it will not match, so the expected
 * outcome is `compiled: true, exact: false` -- and `compiled: false` or a
 * thrown error is the signal.
 */
const PROBE = 'int oe_canary(void) { return 1; }\n';

export const runCanary = async (): Promise<CanaryState> => {
  const started = Date.now();
  const record = (ok: boolean, detail: string): CanaryState => {
    const s: CanaryState = { ok, at: Date.now() / 1000, detail, ms: Date.now() - started };
    slot().current = Option.some(s);
    return s;
  };

  try {
    const verdict = await Effect.runPromise(
      Effect.provide(
        Effect.gen(function* () {
          const gate = yield* modules.Gate;
          return yield* gate.check({
            va: 0x401000,
            original: new Uint8Array([0x33, 0xc0, 0xc3, 0x90]),
            source: PROBE,
            flags: SUBJECT_FLAGS,
          });
        }),
        layer,
      ),
    );
    // `compiled` is the health signal. `exact` is expected to be false: the
    // probe is not a reconstruction of anything.
    return verdict.compiled
      ? record(true, `gate compiled a probe in ${Date.now() - started}ms`)
      : record(false, 'gate reached but refused to compile a trivial source');
  } catch (e) {
    return record(false, e instanceof Error ? e.message.slice(0, 200) : String(e));
  }
};

/** Started by the server. The first run is immediate so a service that comes
 *  up with a broken gate says so at boot rather than at the first interval. */
export const superviseCanary = (everySeconds: number): void => {
  const tick = async () => {
    const s = await runCanary();
    if (!s.ok) console.error(`CANARY FAILING: ${s.detail}`);
  };
  void tick();
  setInterval(() => void tick(), everySeconds * 1000);
};
