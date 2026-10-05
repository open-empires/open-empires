import { Effect, Layer, Option, pipe } from 'effect';
import { Database } from 'bun:sqlite';
import { readFileSync, existsSync } from 'node:fs';
import { modules } from './modules';
import { DbImpl } from './modules/db/impl';
import { GateImpl } from './modules/gate/impl';
import { SubjectImpl } from './modules/subject/impl';

const db = new Database('data/decomp.db', { readonly: true });
const layer = pipe(GateImpl.Layer, Layer.provideMerge(SubjectImpl.Layer), Layer.provideMerge(DbImpl.Layer));
const ROOT = '../aoe2-in-browser/decomp/src';

for (const va of [0x5eaf30, 0x5eb130]) {
  const hex = va.toString(16).toUpperCase().padStart(8, '0');
  const p = db.query(
    `SELECT a.id, a.source, a.flags, a.author FROM proven pv
     JOIN attempts a ON a.id = pv.attempt_id WHERE pv.va = ?`).get(va) as
    { id: number; source: string; flags: string; author: string | null } | null;
  const size = (db.query('SELECT size FROM functions WHERE va = ?').get(va) as { size: number }).size;
  if (p === null) { console.log(hex, 'not proven'); continue; }

  const file = ['fn', 'fn-o1'].map((d) => `${ROOT}/${d}/sub_${hex}.cpp`).find(existsSync);
  const sameAsFile = file !== undefined && readFileSync(file, 'utf8') === p.source;

  const v = await Effect.runPromise(Effect.provide(Effect.gen(function* () {
    const subject = yield* modules.Subject; const gate = yield* modules.Gate;
    const bytes = yield* subject.bytesAt({ va, length: size });
    if (Option.isNone(bytes)) throw new Error('no bytes');
    return yield* gate.check({ va, original: bytes.value, source: p.source, flags: p.flags });
  }), layer));

  console.log(`${hex}  size ${size}  ${p.flags}  author=${p.author ?? '(import)'}`);
  console.log(`   file on disk: ${file ? file.split('/').slice(-2).join('/') : 'NONE'}  stored source matches file: ${sameAsFile}`);
  console.log(`   re-run: exact=${v.exact}  matchedAt=${JSON.stringify(v.matchedAt)}  emitted=${JSON.stringify(v.emittedSize)}  masked=${v.masked}/${v.compared}`);
}
