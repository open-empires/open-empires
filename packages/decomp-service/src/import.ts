/**
 * Move the decompilation project's state into the database, once.
 *
 *     bun src/import.ts
 *
 * Safe to run twice: every row is keyed on a fact from the files, so a second
 * run recognises its own work. Nothing under `decomp/` is read after this
 * except by this file, and nothing under `decomp/` is deleted by it -- those
 * files stay as the reference the generated ports are checked against until
 * every port agrees, which is a separate, later step.
 *
 * It prints the queries it asked and the answers it got, because an import
 * that reports its own bookkeeping is asking to be trusted about the one thing
 * it cannot be trusted about.
 */
import { Effect, Layer, pipe } from 'effect';
import { modules } from './modules';
import { DbImpl } from './modules/db/impl';
import { GateImpl } from './modules/gate/impl';
import { LegacyImpl } from './modules/legacy/impl';

const layer = pipe(
  LegacyImpl.Layer,
  Layer.provideMerge(GateImpl.Layer),
  Layer.provideMerge(DbImpl.Layer),
);

const rule = (title: string) => `\n${title}\n${'-'.repeat(title.length)}`;

const program = Effect.gen(function* () {
  const applied = yield* (yield* modules.Db).migrate();
  if (applied.length > 0) console.log(`migrations applied: ${applied.join(', ')}`);

  const legacy = yield* modules.Legacy;

  const summary = yield* legacy.importState();
  console.log(rule('imported'));
  console.log(`subject   ${summary.subjectSha}`);
  console.log(`toolchain ${summary.toolchainId}`);
  console.log(`gate run  ${summary.gateRunId}`);
  for (const { table, rows } of summary.written) {
    console.log(`  ${table.padEnd(16)} ${String(rows).padStart(6)}`);
  }

  console.log(rule('carried by the files, with nowhere in the schema to put it'));
  for (const { what, detail } of summary.unexpressed) {
    console.log(`\n${what}\n  ${detail.replace(/(.{1,92})(\s|$)/g, '$1\n  ').trimEnd()}`);
  }

  const checks = yield* legacy.audit();
  console.log(rule('audit -- asked of the database, answered against the files'));
  for (const check of checks) {
    console.log(`\n${check.passed ? 'PASS' : 'FAIL'}  ${check.question}`);
    for (const line of check.sql.trim().split('\n')) console.log(`      ${line.trim()}`);
    console.log(`      expected ${check.expected}`);
    console.log(`      actual   ${check.actual}`);
    for (const line of check.detail) console.log(`      - ${line}`);
  }

  const failed = checks.filter((c) => !c.passed);
  console.log(
    rule(`${checks.length - failed.length} of ${checks.length} checks passed`),
  );
  for (const check of failed) console.log(`FAIL  ${check.question}`);
  return failed.length;
});

const result = await Effect.runPromise(
  Effect.result(Effect.provide(program, layer) as Effect.Effect<number, unknown, never>),
);
if (result._tag === 'Failure') {
  console.error('\nimport failed:', JSON.stringify(result.failure, null, 2));
  process.exit(1);
}
// A non-zero exit on a failed check, so a caller cannot read "it ran" as "it
// agreed with the files".
process.exit(result.success === 0 ? 0 : 2);
