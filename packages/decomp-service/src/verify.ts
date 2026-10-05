/**
 * The whole-corpus audits.
 *
 *     bun src/verify.ts                 all three
 *     bun src/verify.ts compose         assemble the span and diff it
 *     bun src/verify.ts reloc           classify every relocation field
 *     bun src/verify.ts port [dir]      generate the portable tree
 *     bun src/verify.ts imports         name import slots from the libraries
 *     bun src/verify.ts portable-compiles
 *                                       compile every rendered file for wasm32
 *
 * These are not HTTP routes. Each one recompiles every reconstruction in force
 * -- thousands of calls into one serialised compiler -- so a request that
 * started one would hold a socket open for minutes and compete with the agents
 * the service exists to serve. The composition run is RECORDED, so the answer
 * is readable afterwards at /api/composition without rerunning it; the portable
 * tree's per-file outcome is recorded likewise and readable at /api/port.
 *
 * The exit status is non-zero when an audit's answer is not the one the project
 * claims: a non-zero composition diff, or a dangling relocation. A run that
 * exited 0 because it merely completed would be worthless.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Effect, Layer, Option, pipe } from 'effect';
import { modules } from './modules';
import { ComposeImpl } from './modules/compose/impl';
import { DbImpl } from './modules/db/impl';
import { DisasmImpl } from './modules/disasm/impl';
import { GateImpl } from './modules/gate/impl';
import { ImportNamesImpl } from './modules/import-names/impl';
import { PortableImpl } from './modules/portable/impl';
import { RelocImpl } from './modules/reloc/impl';
import { SubjectImpl } from './modules/subject/impl';

const layer = pipe(
  ComposeImpl.Layer,
  Layer.provideMerge(ImportNamesImpl.Layer),
  Layer.provideMerge(PortableImpl.Layer),
  Layer.provideMerge(RelocImpl.Layer),
  Layer.provideMerge(GateImpl.Layer),
  Layer.provideMerge(DisasmImpl.Layer),
  Layer.provideMerge(SubjectImpl.Layer),
  Layer.provideMerge(DbImpl.Layer),
);

const hex = (n: number) => `0x${n.toString(16)}`;
const rule = (title: string) => `\n${title}\n${'-'.repeat(title.length)}`;
const row = (label: string, value: string | number) =>
  `  ${label.padEnd(34)}${String(value).padStart(12)}`;

const asked = process.argv.slice(2);
const wants = (name: string) => asked.length === 0 || asked.includes(name);
const portInto = (() => {
  const i = asked.indexOf('port');
  const next = i < 0 ? undefined : asked[i + 1];
  return next === undefined || next.startsWith('-') ? Option.none<string>() : Option.some(next);
})();

const program = Effect.gen(function* () {
  const applied = yield* (yield* modules.Db).migrate();
  if (applied.length > 0) console.log(`migrations applied: ${applied.join(', ')}`);
  let failures = 0;

  if (wants('compose')) {
    const r = yield* (yield* modules.Compose).run();
    console.log(rule('composition -- the whole .text span, assembled and diffed'));
    console.log(row('span', `${hex(r.textLo)}..${hex(r.textHi)}`));
    console.log(row('span bytes', r.spanBytes));
    console.log(row('reconstructions in force', r.considered));
    console.log(row('placed from compiled C++', r.placed));
    console.log(row('bytes placed', r.placedBytes));
    console.log(
      row(
        'of which masked relocations',
        `${r.maskedBytes} (${((100 * r.maskedBytes) / Math.max(1, r.placedBytes)).toFixed(1)}%)`,
      ),
    );
    console.log(
      row('compiled C++ share of .text', `${((100 * r.placedBytes) / r.spanBytes).toFixed(1)}%`),
    );
    console.log(row('did not build', r.notBuilt));
    console.log(row('emitted too few bytes', r.tooShort));
    console.log(row('outside the span', r.outsideSpan));
    console.log(row('placed and disagreeing', r.disagreeing));
    console.log(row('overlapping inventory entries', r.overlaps.length));
    console.log(row('DIFF against the subject', `${r.diffBytes} bytes`));
    console.log(row('  of which unattributed', r.unattributedDiffBytes));
    console.log(
      r.diffBytes === 0
        ? '  0 means every reconstruction composes at its real address.'
        : '  NON-ZERO is a composition bug: a proof that no longer holds, an ' +
            'overlapping entry,\n  or a compiled length that disagrees with the inventory.',
    );
    if (r.toolchainInForce !== r.toolchainUsed) {
      console.log(
        `\n  WARNING: the configuration names ${r.toolchainInForce} but the gate ` +
          `is ${r.toolchainUsed}.\n  Every source composed here was proved by a ` +
          'compiler that is not the one that just built it.',
      );
      failures += 1;
    }
    for (const p of r.problems.slice(0, 40)) {
      console.log(
        `    sub_${p.va.toString(16).toUpperCase().padStart(8, '0')}  ${p.origin.padEnd(13)}` +
          `size ${String(p.size).padStart(6)}  diff ${String(p.diffBytes).padStart(5)}  ` +
          Option.getOrElse(p.detail, () => ''),
      );
    }
    if (r.problems.length > 40) console.log(`    ... ${r.problems.length - 40} more`);
    for (const o of r.overlaps) {
      console.log(
        `    OVERLAP ${hex(o.va)}+${o.size} runs ${o.overlappingBytes} bytes into ${hex(o.nextVa)}`,
      );
    }
    console.log(`\n  recorded as composition run ${r.runId}`);
    if (r.diffBytes !== 0) failures += 1;
  }

  if (wants('reloc')) {
    const r = yield* (yield* modules.Reloc).check();
    console.log(rule('relocations -- does every reference leave for somewhere real'));
    console.log(row('reconstructions in force', r.considered));
    console.log(row('still reproducing at the entry', r.reproduced));
    console.log(row('no longer reproducing', r.notReproduced));
    console.log(row('relocation fields', r.fields));
    console.log(
      row(
        'explained',
        `${r.explained} (${((100 * r.explained) / Math.max(1, r.fields)).toFixed(1)}%)`,
      ),
    );
    for (const c of r.byClass) {
      console.log(
        `  ${String(c.fields).padStart(8)}  ` +
          `${((100 * c.fields) / Math.max(1, r.fields)).toFixed(1).padStart(5)}%  ${c.label}`,
      );
    }
    console.log(row('DANGLING', r.dangling.length));
    for (const d of r.dangling.slice(0, 40)) {
      console.log(
        `    sub_${d.va.toString(16).toUpperCase().padStart(8, '0')} +${String(d.offset).padStart(4)}` +
          `  ${d.kind.padEnd(8)} -> ${hex(d.target)}`,
      );
    }
    if (r.dangling.length > 40) console.log(`    ... ${r.dangling.length - 40} more`);
    if (r.dangling.length !== 0) failures += 1;
  }

  if (wants('port')) {
    const r = yield* (yield* modules.Portable).generate(portInto);
    console.log(rule('portable tree -- MSVC-6 reconstructions rendered for WebAssembly'));
    console.log(row('reconstructions in force', r.considered));
    console.log(row('converted', r.converted));
    console.log(row('  of which need the globals model', r.needsGlobals));
    console.log(row('refused', r.refused));
    for (const va of r.refusedVas) {
      console.log(`    sub_${va.toString(16).toUpperCase().padStart(8, '0')}  hand-written __asm`);
    }
    console.log(row('literals the rewrite cannot reach', r.strandedLiterals.length));
    for (const s of r.strandedLiterals.slice(0, 20)) {
      console.log(
        `    sub_${s.va.toString(16).toUpperCase().padStart(8, '0')}  ${hex(s.literal)} ` +
          'is inside the globals model and outside the rewrite pattern',
      );
    }
    if (Option.isSome(r.writtenTo)) {
      console.log(`\n  wrote ${r.filesWritten} files to ${r.writtenTo.value}`);
      console.log('  plus gameimage.h, from the same constants the rewrite used.');
    } else {
      console.log('\n  recorded only; pass a directory to write the tree.');
    }
  }

  // DOES THE RENDERED TREE COMPILE AT ALL.
  //
  // It had never been asked. 3,322 files were being generated and the only
  // thing checked about them was that the conversion did not refuse -- so 167
  // of them did not compile, for two reasons nothing else could have found:
  // the rendering did not carry the `string.h` the gate prepends to every
  // verification compile, and `0x4e-4` is a single invalid preprocessing
  // token because a pp-number continues through `e-`, which MSVC 6 accepts
  // and conforming compilers reject.
  //
  // Checked against the stubs in platform/ rather than a real sysroot, so it
  // needs nothing but clang and therefore cannot quietly stop running. Those
  // stubs are also the list of what a real WebAssembly build must provide.
  if (wants('portable-compiles')) {
    const dir = Option.getOrElse(portInto, () =>
      path.join(os.tmpdir(), 'oe-portable-check'),
    );
    if (Option.isNone(portInto)) {
      yield* (yield* modules.Portable).generate(Option.some(dir));
    }
    const stubs = path.join(import.meta.dir, '../platform');
    const sources = fs.readdirSync(dir).filter((f) => f.endsWith('.cpp'));
    const broken: Array<{ file: string; error: string }> = [];
    const batch = 8;
    for (let i = 0; i < sources.length; i += batch) {
      const slice = sources.slice(i, i + batch);
      const results = yield* Effect.promise(() =>
        Promise.all(
          slice.map(async (file) => {
            const proc = Bun.spawn(
              [
                'clang', '--target=wasm32', '-std=c++17', '-fno-exceptions',
                '-fsyntax-only', '-I', dir, '-I', stubs, path.join(dir, file),
              ],
              { stdout: 'pipe', stderr: 'pipe' },
            );
            const [code, err] = await Promise.all([
              proc.exited,
              new Response(proc.stderr).text(),
            ]);
            return { file, code, err };
          }),
        ),
      );
      for (const r of results) {
        if (r.code !== 0) {
          const first = r.err.split('\n').find((l) => l.includes('error:')) ?? 'failed';
          broken.push({ file: r.file, error: first.replace(/^.*error: /, '') });
        }
      }
    }
    console.log(rule('portable tree -- does it compile for WebAssembly'));
    console.log(row('files', sources.length));
    console.log(row('compile', sources.length - broken.length));
    console.log(row('fail', broken.length));
    const byError = new Map<string, number>();
    for (const f of broken) {
      const key = f.error.replace(/'[^']*'/g, 'X');
      byError.set(key, (byError.get(key) ?? 0) + 1);
    }
    for (const [error, n] of [...byError].sort((a, b) => b[1] - a[1]).slice(0, 10)) {
      console.log(`    ${String(n).padStart(8)}  ${error}`);
    }
    for (const f of broken.slice(0, 10)) console.log(`      ${f.file}: ${f.error}`);
    if (broken.length > 0) {
      console.log(
        '\n  a rendered file that does not compile is a function that cannot ' +
          'reach the browser build.',
      );
      // The OUTER counter, which decides the exit status and the closing
      // line. A local array shadowed it, so this audit printed 20 failures
      // and then "every audit answered what the project claims" and exited 0
      // -- a check that reports its own success is worse than no check.
      failures += 1;
    }
  }

  if (wants('imports')) {
    const r = yield* (yield* modules.ImportNames).nameImportSlots();
    console.log(rule('import names -- read out of the libraries\' own relocation tables'));
    console.log(row('CRT identifications read', r.identifications));
    console.log(row('library sections confirmed in the image', r.sectionsPlaced));
    console.log(row('__imp_ relocations in them', r.relocations));
    console.log(row('references confirmed against the image', r.referencesConfirmed));
    for (const f of r.formCounts) console.log(`    ${String(f.count).padStart(8)}  ${f.form}`);
    console.log(row('refused', r.refusals));
    for (const f of r.refusalReasons) console.log(`    ${String(f.count).padStart(8)}  ${f.reason}`);
    console.log(row('slots referenced', r.slotsReferenced));
    console.log(row('call-site bindings written', r.bindingsWritten));
    console.log(row('call sites the dump names too, same name', r.bindingsReproduced));
    console.log(
      row('call sites the dump names too, same address', r.bindingsAliasResolved.length),
    );
    for (const a of r.bindingsAliasResolved) {
      console.log(
        `    slot ${hex(a.slot)} site ${hex(a.callSite)}  ${a.cachedApi} and ` +
          `${a.libraryApi} are both at that address (${a.cachedTargetExports.join(', ')})`,
      );
    }
    console.log(row('call sites the dump names too, DISAGREEING', r.bindingDisagreements.length));
    for (const d of r.bindingDisagreements) {
      console.log(
        `    slot ${hex(d.slot)} site ${hex(d.callSite)}  the cache resolved it to ` +
          `${hex(d.cachedTarget)} (${d.cachedTargetExports.join(', ') || 'no export'}), ` +
          `the library links it against ${d.libraryApi}`,
      );
    }
    console.log(row('slots NAMED by this derivation', r.slotsNamed.length));
    for (const n of r.slotsNamed) console.log(`    ${hex(n.slot)}  ${n.name}`);
    console.log(row('already-named slots reproduced', r.slotsReproduced.length));
    for (const n of r.slotsReproduced) console.log(`    ${hex(n.slot)}  ${n.name}`);
    console.log(row('already-named slots serving MORE APIs', r.disagreements.length));
    for (const d of r.disagreements) {
      console.log(
        `    ${hex(d.slot)}  ${d.storedName} from ${d.cachedSites} cached site(s); ` +
          `${d.librarySites} library site(s) name ${d.libraryApis.join(', ')}`,
      );
    }
    console.log(row('referenced slots still unnamed', r.slotsStillUnnamed.length));
    for (const u of r.slotsStillUnnamed) {
      console.log(`    ${hex(u.slot)}  ${u.reason}; the libraries name ${u.apis.join(', ')}`);
    }
    // A contradiction about one call site means one of the two derivations is
    // wrong. Everything else above is a finding, not a failure.
    if (r.bindingDisagreements.length !== 0) failures += 1;
  }

  return failures;
});

const result = await Effect.runPromise(
  Effect.result(Effect.provide(program, layer) as Effect.Effect<number, unknown, never>),
);
if (result._tag === 'Failure') {
  console.error('\nverify failed:', JSON.stringify(result.failure, null, 2));
  process.exit(1);
}
console.log(
  result.success === 0
    ? '\nevery audit answered what the project claims.'
    : `\n${result.success} audit(s) did NOT answer what the project claims.`,
);
process.exit(result.success === 0 ? 0 : 2);
