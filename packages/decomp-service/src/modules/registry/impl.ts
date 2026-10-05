import { Effect, Option } from 'effect';
import { implementing, type EffectGen } from 'effective-modules';
import { modules } from '../index';
import type { DbError } from '../db/interface';
import {
  STALE_AFTER_SECONDS, UnknownAgent,
  type Agent, type IRegistry,
} from './interface';

const now = () => Date.now() / 1000;
const optStr = (v: unknown): Option.Option<string> =>
  v === null || v === undefined || v === '' ? Option.none() : Option.some(String(v));
const optNum = (v: unknown): Option.Option<number> =>
  v === null || v === undefined ? Option.none() : Option.some(Number(v));

export class RegistryImpl
  extends implementing(modules.Registry).uses(modules.Db)
  implements IRegistry
{
  *register(id: string, role: Option.Option<string>): EffectGen<void, DbError> {
    const t = now();
    yield* this.dependencies.Db.run(
      `INSERT INTO agents(id, role, started, last_beat, beats)
       VALUES (?,?,?,?,0)
       ON CONFLICT(id) DO UPDATE SET
         role = excluded.role, started = excluded.started,
         last_beat = excluded.last_beat, beats = 0,
         finished = NULL, note = NULL`,
      [id, Option.getOrNull(role), t, t],
    );
  }

  *beat(id: string): EffectGen<void, DbError | UnknownAgent> {
    const n = yield* this.dependencies.Db.run(
      `UPDATE agents SET last_beat = ?, beats = beats + 1
       WHERE id = ? AND finished IS NULL`,
      [now(), id],
    );
    // A beat must not invent an agent: a typo would become a phantom worker.
    if (n === 0) return yield* Effect.fail(new UnknownAgent({ id }));
  }

  *deregister(
    id: string,
    note: Option.Option<string>,
  ): EffectGen<void, DbError | UnknownAgent> {
    const t = now();
    const n = yield* this.dependencies.Db.run(
      `UPDATE agents SET finished = ?, last_beat = ?, note = ? WHERE id = ?`,
      [t, t, Option.getOrNull(note), id],
    );
    if (n === 0) return yield* Effect.fail(new UnknownAgent({ id }));
  }

  *list(): EffectGen<ReadonlyArray<Agent>, DbError> {
    const t = now();
    const rows = yield* this.dependencies.Db.all(
      `SELECT id, role, started, last_beat, beats, finished, note FROM agents
       ORDER BY (finished IS NOT NULL), started DESC LIMIT 100`,
    );
    return rows.map((raw) => {
      const o = raw as Record<string, unknown>;
      const finished = optNum(o.finished);
      const lastBeat = Number(o.last_beat);
      const silent = t - lastBeat;
      return {
        id: String(o.id),
        role: optStr(o.role),
        started: Number(o.started),
        lastBeat,
        beats: Number(o.beats),
        finished,
        note: optStr(o.note),
        state: Option.isSome(finished)
          ? ('finished' as const)
          : silent > STALE_AFTER_SECONDS
            ? ('gone' as const)
            : ('live' as const),
        silentFor: Option.isSome(finished) ? Option.none() : Option.some(silent),
      };
    });
  }
}
