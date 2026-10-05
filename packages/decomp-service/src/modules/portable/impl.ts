import { Effect, Option, Schema } from 'effect';
import { implementing, type EffectGen } from 'effective-modules';
import fs from 'node:fs';
import path from 'node:path';
import { modules } from '../index';
import type { DbError, IDb } from '../db/interface';
import { reconstructionsInForce } from '../db/reconstructions';
import { rows } from '../db/rows';
import { NoCurrentSubject } from '../subject/interface';
import { convert, PORT_HEADER } from './convert';
import {
  PortWriteError,
  type IPortable,
  type PortFailure,
  type PortFile,
  type PortReport,
  type PortState,
} from './interface';

const PortFileRow = Schema.Struct({
  va: Schema.Number,
  state: Schema.String,
  reason: Schema.NullOr(Schema.String),
});

const name = (va: number) => `sub_${va.toString(16).toUpperCase().padStart(8, '0')}.cpp`;

export class PortableImpl
  extends implementing(modules.Portable).uses(modules.Db, modules.Subject)
  implements IPortable
{
  *generate(into: Option.Option<string>): EffectGen<PortReport, PortFailure> {
    const db: IDb = this.dependencies.Db;
    const current = yield* this.dependencies.Subject.current();
    if (Option.isNone(current)) {
      return yield* Effect.fail(
        new NoCurrentSubject({
          reason: 'no subject is configured, so there are no reconstructions in force',
        }),
      );
    }
    const subjectSha = current.value.sha256;
    const corpus = yield* reconstructionsInForce(db);

    const files: Array<{ readonly va: number; readonly state: PortState; readonly reason: string | null; readonly text: string | null }> = [];
    const stranded: Array<{ readonly va: number; readonly literal: number }> = [];
    for (const r of corpus) {
      const out = convert(r.source);
      if (out.state === 'refused') {
        files.push({ va: r.va, state: 'refused', reason: out.reason, text: null });
        continue;
      }
      for (const literal of out.literalsOutsideThePattern) {
        stranded.push({ va: r.va, literal });
      }
      files.push({
        va: r.va,
        state: out.needsGlobals ? 'needs_globals' : 'converted',
        reason: null,
        text: PORT_HEADER(r.va) + out.text,
      });
    }

    // Stranded literals are STORED, not just returned. They were computed on
    // every run and discarded with the report, so the one correctness hole
    // between the proven set and a browser build could not be counted or
    // tracked. Replaced wholesale with the files, for the same reason they
    // are: a literal from a source no longer proved is an answer about
    // something that is gone.
    // Replaced wholesale for this subject, inside one transaction: a
    // conversion is derived entirely from the sources in force, so a row left
    // behind from a source that is no longer proved would be an answer about a
    // file the generated tree does not contain.
    yield* db.tx(function* () {
      yield* db.run('DELETE FROM port_files WHERE subject_sha = ?', [subjectSha]);
      yield* db.run('DELETE FROM port_stranded_literals WHERE subject_sha = ?', [
        subjectSha,
      ]);
      const foundAt = Date.now() / 1000;
      for (const s of stranded) {
        yield* db.run(
          `INSERT INTO port_stranded_literals(subject_sha, va, literal, found_at)
           VALUES (?,?,?,?) ON CONFLICT(subject_sha, va, literal) DO NOTHING`,
          [subjectSha, s.va, s.literal, foundAt],
        );
      }
      for (const f of files) {
        yield* db.run(
          `INSERT INTO port_files(subject_sha, va, state, reason) VALUES (?,?,?,?)`,
          [subjectSha, f.va, f.state, f.reason],
        );
      }
    });

    let filesWritten = 0;
    if (Option.isSome(into)) {
      const dir = into.value;
      yield* Effect.try({
        try: () => {
          fs.mkdirSync(dir, { recursive: true });
          // Stale generated files are removed, because a file left behind from
          // a source that no longer exists answers a question wrongly where a
          // missing one asks it.
          const keep = new Set(files.filter((f) => f.text !== null).map((f) => name(f.va)));
          for (const existing of fs.readdirSync(dir)) {
            if (existing.endsWith('.cpp') && !keep.has(existing)) {
              fs.rmSync(path.join(dir, existing));
            }
          }
          for (const f of files) {
            if (f.text === null) continue;
            fs.writeFileSync(path.join(dir, name(f.va)), f.text);
            filesWritten += 1;
          }
        },
        catch: (cause) =>
          new PortWriteError({
            path: dir,
            reason: cause instanceof Error ? cause.message : String(cause),
          }),
      });
    }

    const refusedVas = files.filter((f) => f.state === 'refused').map((f) => f.va);
    return {
      subjectSha,
      considered: corpus.length,
      converted: files.filter((f) => f.state !== 'refused').length,
      needsGlobals: files.filter((f) => f.state === 'needs_globals').length,
      refused: refusedVas.length,
      refusedVas,
      strandedLiterals: stranded,
      writtenTo: into,
      filesWritten,
    };
  }

  *files(state: Option.Option<PortState>): EffectGen<ReadonlyArray<PortFile>, DbError> {
    const db: IDb = this.dependencies.Db;
    const found = yield* rows(
      db,
      PortFileRow,
      `SELECT p.va AS va, p.state AS state, p.reason AS reason
       FROM port_files p
       JOIN current_config c ON c.only_row = 1 AND c.subject_sha = p.subject_sha
       WHERE (? IS NULL OR p.state = ?)
       ORDER BY p.va`,
      [Option.getOrNull(state), Option.getOrNull(state)],
    );
    return found.map((r) => ({
      va: r.va,
      state: r.state as PortState,
      reason: r.reason === null ? Option.none() : Option.some(r.reason),
    }));
  }
}
