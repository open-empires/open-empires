/**
 * A bound on how many compilations run at once.
 *
 * The gate had none. A single agent's cleanup step fired 60 sweeps at the
 * shared container, every one of them spawning a Wine compile, and the
 * service stopped answering: its own supervisor logged
 * `probe failed (1/3): The operation timed out`, and the agent saw empty
 * response bodies. It recovered before the third strike, so nothing
 * restarted and nothing in the system recorded an incident -- which is the
 * same shape as the outage this service was hardened against, just shorter.
 *
 * Compilation is the only expensive thing here and it is shared: one
 * container, one machine. So requests queue instead of competing. The
 * service stays responsive at any request volume, health keeps answering
 * (it never touches the compiler), and a burst costs latency rather than
 * availability.
 *
 * This is a plain promise queue rather than an Effect primitive because it
 * guards a resource outside the Effect runtime -- a docker exec -- and must
 * hold regardless of which fiber, route or background worker asks.
 */

/** Concurrent compiles. The machine has 16 cores and the container is shared
 *  with whatever else is running; 6 keeps the box busy without letting a
 *  burst starve the event loop that answers /api/health. */
const LIMIT = Number(process.env.GATE_CONCURRENCY ?? 6);

const KEY = Symbol.for('open-empires.gate.throttle');

interface State {
  active: number;
  readonly waiting: Array<() => void>;
  /** Observability: a queue nobody can see is a queue nobody fixes. */
  peakWaiting: number;
  admitted: number;
}

const state = (): State => {
  const g = globalThis as Record<symbol, unknown>;
  const existing = g[KEY];
  if (existing !== undefined) return existing as State;
  const fresh: State = { active: 0, waiting: [], peakWaiting: 0, admitted: 0 };
  g[KEY] = fresh;
  return fresh;
};

/** Wait for a compile permit. The caller MUST release it, in a `finally`, or
 *  the gate deadlocks after LIMIT failures. */
export const acquireCompileSlot = async (): Promise<void> => {
  const s = state();
  if (s.active >= LIMIT) {
    s.peakWaiting = Math.max(s.peakWaiting, s.waiting.length + 1);
    await new Promise<void>((resolve) => s.waiting.push(resolve));
  }
  s.active++;
  s.admitted++;
};

export const releaseCompileSlot = (): void => {
  const s = state();
  s.active = Math.max(0, s.active - 1);
  const next = s.waiting.shift();
  if (next !== undefined) next();
};

export const throttleStats = (): {
  limit: number;
  active: number;
  waiting: number;
  peakWaiting: number;
  admitted: number;
} => {
  const s = state();
  return {
    limit: LIMIT,
    active: s.active,
    waiting: s.waiting.length,
    peakWaiting: s.peakWaiting,
    admitted: s.admitted,
  };
};
