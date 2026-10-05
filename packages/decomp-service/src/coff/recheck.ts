// Did the shared-COFF refactor move any verdict? Sample fn/ (must stay
// exact) and wip/ (must stay not-exact).
import { Effect, Layer, pipe } from 'effect';
import { modules } from '../modules';
import { DbImpl } from '../modules/db/impl';
import { GateImpl } from '../modules/gate/impl';
import { SUBJECT_FLAGS, SUBJECT_FLAGS_O1 } from '../modules/gate/interface';
import { SUBJECT_IMAGE_PATH } from '../modules/subject/paths';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(import.meta.dir, '../../../aoe2-in-browser');
const IMG = new Uint8Array(readFileSync(SUBJECT_IMAGE_PATH));
const BASE = 0x400000;
const INV: Record<number, number> = {};
for (const f of JSON.parse(readFileSync(path.join(ROOT, 'decomp/functions.json'), 'utf8')).functions)
  INV[f.va] = f.size;

const pick = (dir: string, n: number) => {
  const all = readdirSync(path.join(ROOT, dir)).filter((f) => /^sub_[0-9A-F]{8}\.cpp$/.test(f)).sort();
  const step = Math.max(1, Math.floor(all.length / n));
  return all.filter((_, i) => i % step === 0).slice(0, n);
};

const layer = pipe(GateImpl.Layer, Layer.provideMerge(DbImpl.Layer));

const check = (dir: string, flags: string, files: string[]) =>
  Effect.gen(function* () {
    const gate = yield* modules.Gate;
    const out: { va: number; exact: boolean }[] = [];
    for (const f of files) {
      const va = parseInt(f.slice(4, 12), 16);
      const size = INV[va];
      if (size === undefined) continue;
      const v = yield* gate.check({
        va,
        original: IMG.subarray(va - BASE, va - BASE + size),
        source: readFileSync(path.join(ROOT, dir, f), 'utf8'),
        flags,
      });
      out.push({ va, exact: v.exact });
    }
    return out;
  });

const run = async (dir: string, flags: string, n: number, expect: boolean) => {
  const files = pick(dir, n);
  const res = await Effect.runPromise(Effect.provide(check(dir, flags, files), layer));
  const wrong = res.filter((r) => r.exact !== expect);
  console.log(`${dir}: ${res.length} checked, expected exact=${expect}, ` +
    `disagreeing=${wrong.length}` + (wrong.length ? ` -> ${wrong.map(w => w.va.toString(16)).join(' ')}` : ''));
};

await run('decomp/src/fn', SUBJECT_FLAGS, 40, true);
await run('decomp/src/fn-o1', SUBJECT_FLAGS_O1, 15, true);
await run('decomp/src/wip', SUBJECT_FLAGS, 25, false);
