import { Effect, Option } from 'effect';
import { implementing, type EffectGen } from 'effective-modules';
import fs from 'node:fs';
import path from 'node:path';
import { modules } from '../index';
import { emittedFunctions, compilerStamp } from './coff';
import { compareToSubject } from './compare';
import {
  GateUnavailable,
  WEAKLY_VERIFIED_ABOVE,
  type Contribution,
  type GateAttempt,
  type IGate,
  type Toolchain,
  type Verdict,
} from './interface';

/**
 * The game's own MSVC 6.0 SP3, driven under Wine.
 *
 * This is the SAME cl.exe / c1xx.dll / c2.dll extracted from the SP3-patched
 * install; Wine supplies only the Win32 syscalls, so the emitted bytes are
 * identical to running it on Windows. The compiler lives in a container whose
 * Wine prefix is already populated, because copying 178 MB of toolchain into a
 * fresh prefix costs about 33 seconds and the compile itself costs 0.14.
 */
const TOOLCHAIN_ROOT = path.resolve(
  process.env.DECOMP_TOOLCHAIN ??
    path.join(import.meta.dir, '../../../../aoe2-in-browser/work/toolchain'),
);
const VC98 = path.join(TOOLCHAIN_ROOT, 'vc98');
const CL_EXE = path.join(VC98, 'VC98/Bin/CL.EXE');
/** Bind-mounted into the container at /work: how a source gets in and an
 *  object gets out. */
const EXCHANGE = path.join(TOOLCHAIN_ROOT, 'ccwork');
const IMAGE = 'oe-cc';
const CONTAINER = 'oe-cc-live';

/**
 * Prepended to every source, exactly as it is for every other attempt.
 *
 * Several reconstructions call CRT string functions and declare nothing, and
 * the gate must not pass or fail an attempt for a reason that depends on which
 * other attempts it was checked alongside.
 */
const PROLOGUE = '#include <string.h>\n';

/** How long the bind mount is given to make a file visible on either side. */
const VISIBILITY_ATTEMPTS = 100;
const VISIBILITY_INTERVAL_MS = 50;

/** Memo of a pure function of the compiler's bytes, keyed by toolchain id. */
const toolchains = new Map<string, Toolchain>();

const reason = (cause: unknown): string =>
  cause instanceof Error ? cause.message : String(cause);

/** The one line of a compiler diagnostic worth recording against a verdict. */
const lastLine = (text: string): string => {
  const lines = text.trim().split('\n');
  return (lines[lines.length - 1] ?? '').slice(0, 120);
};

interface Ran {
  readonly code: number;
  readonly stdout: string;
  readonly stderr: string;
}

/** Either the compiler produced a complete object, or it refused the source. */
type Compilation =
  | { readonly built: true; readonly object: Uint8Array }
  | { readonly built: false; readonly diagnostic: string };

export class GateImpl extends implementing(modules.Gate) implements IGate {
  private *docker(args: ReadonlyArray<string>): EffectGen<Ran, GateUnavailable> {
    return yield* Effect.tryPromise({
      try: async () => {
        const proc = Bun.spawn(['docker', ...args], { stdout: 'pipe', stderr: 'pipe' });
        const [stdout, stderr, code] = await Promise.all([
          new Response(proc.stdout).text(),
          new Response(proc.stderr).text(),
          proc.exited,
        ]);
        return { code, stdout, stderr };
      },
      catch: (cause) =>
        new GateUnavailable({ stage: 'container', reason: `docker: ${reason(cause)}` }),
    });
  }

  /**
   * Keep one container alive with the Wine prefix already populated.
   *
   * Checked on every attempt rather than once per process: a container that
   * died would otherwise make every remaining attempt report that the compiler
   * rejected it, which is a retraction of the whole proof set dressed up as
   * thousands of bad reconstructions.
   */
  private *ensureContainer(): EffectGen<void, GateUnavailable> {
    const running = yield* this.docker([
      'inspect',
      '-f',
      '{{.State.Running}}',
      CONTAINER,
    ]);
    if (running.stdout.trim() === 'true') return;

    if (!fs.existsSync(CL_EXE)) {
      return yield* new GateUnavailable({
        stage: 'toolchain',
        reason: `no cl.exe at ${CL_EXE}; set DECOMP_TOOLCHAIN to the directory holding vc98/`,
      });
    }
    // Remove only a container that EXISTS and is dead. An unconditional
    // removal can delete one another agent created and populated a moment
    // ago, which costs that agent its prefix and the next 33 seconds.
    if (running.code === 0) yield* this.docker(['rm', '-f', CONTAINER]);
    const started = yield* this.docker([
      'run',
      '-d',
      '--name',
      CONTAINER,
      '-v',
      `${VC98}:/vc98:ro`,
      '-v',
      `${EXCHANGE}:/work`,
      IMAGE,
      'bash',
      '-c',
      'sleep infinity',
    ]);
    if (started.code !== 0) {
      // Another caller -- a concurrent attempt here, or the Python tooling
      // sharing this container -- may have won the race to create it. What
      // matters is whether it is running now, not who started it.
      const again = yield* this.docker(['inspect', '-f', '{{.State.Running}}', CONTAINER]);
      if (again.stdout.trim() === 'true') return;
      return yield* new GateUnavailable({
        stage: 'container',
        reason: `could not start ${CONTAINER} from image ${IMAGE}: ${lastLine(started.stderr)}`,
      });
    }
    // mspdb60.dll lives in Common/MSDev98/Bin; without it cl.exe dies with a
    // bare import error and no diagnostic.
    const setup = [
      'export WINEPREFIX=/prefix WINEARCH=win32 WINEDEBUG=-all',
      'wineboot -i >/dev/null 2>&1; wineserver -w',
      'mkdir -p /prefix/drive_c/VC98 /prefix/drive_c/Common',
      'cp -a /vc98/VC98/*   /prefix/drive_c/VC98/',
      'cp -a /vc98/Common/* /prefix/drive_c/Common/',
    ].join('\n');
    const prepared = yield* this.docker(['exec', CONTAINER, 'bash', '-c', setup]);
    if (prepared.code !== 0) {
      return yield* new GateUnavailable({
        stage: 'container',
        reason: `Wine prefix setup failed: ${lastLine(prepared.stderr)}`,
      });
    }
  }

  /**
   * Compile one source and bring its object back.
   *
   * Everything awkward here is load-bearing. The source is flushed and fsynced
   * before the container is told to read it, and the container then waits for
   * the file to reach its full length, because the bind mount hands over a file
   * that EXISTS well before it is complete -- cl.exe given a truncated source
   * exits 0 and emits a valid object with no code, which looks exactly like a
   * compiler bug. Every compile gets its own filename, its own directory and
   * its own TMP, because cl.exe hands work to c1xx.exe and c2.exe through
   * intermediate files in TMP and concurrent agents sharing one prefix were
   * stepping on each other. cl.exe's own exit status and the size the container
   * sees are recorded and checked against what is read back, because a short
   * read surfaced as "no code in object" and named the wrong problem.
   */
  private *compile(source: string, flags: string): EffectGen<Compilation, GateUnavailable> {
    yield* this.ensureContainer();
    const tag = crypto.randomUUID().replaceAll('-', '').slice(0, 8);
    const bytes = new TextEncoder().encode(source);
    const sourcePath = path.join(EXCHANGE, `in-${tag}.cpp`);
    const objectPath = path.join(EXCHANGE, `out-${tag}.obj`);
    const logPath = path.join(EXCHANGE, `build-${tag}.log`);

    yield* Effect.try({
      try: () => {
        fs.mkdirSync(EXCHANGE, { recursive: true });
        const fd = fs.openSync(sourcePath, 'w');
        try {
          fs.writeSync(fd, bytes);
          fs.fsyncSync(fd);
        } finally {
          fs.closeSync(fd);
        }
      },
      catch: (cause) =>
        new GateUnavailable({
          stage: 'compile',
          reason: `could not stage the source in ${EXCHANGE}: ${reason(cause)}`,
        }),
    });

    const build =
      'export WINEPREFIX=/prefix WINEARCH=win32 WINEDEBUG=-all; ' +
      `mkdir -p /prefix/drive_c/b-${tag} && cd /prefix/drive_c/b-${tag} && ` +
      `export TMP=C:\\b-${tag} TEMP=C:\\b-${tag} && ` +
      `for i in $(seq 1 ${VISIBILITY_ATTEMPTS}); do cp /work/in-${tag}.cpp in-${tag}.cpp 2>/dev/null; ` +
      `[ "$(stat -c%s in-${tag}.cpp 2>/dev/null || echo 0)" = "${bytes.length}" ]` +
      ` && break || sleep ${VISIBILITY_INTERVAL_MS / 1000}; done && ` +
      `test $(stat -c%s in-${tag}.cpp) -eq ${bytes.length} && ` +
      "export WINEPATH='C:\\VC98\\Bin;C:\\Common\\MSDev98\\Bin' && " +
      `wine 'C:\\VC98\\Bin\\CL.EXE' /c ${flags} /I 'C:\\VC98\\Include' in-${tag}.cpp` +
      ` > /work/build-${tag}.log 2>&1; ` +
      `echo "status=$? size=$(stat -c%s in-${tag}.obj 2>/dev/null || echo 0)" >> /work/build-${tag}.log`;
    yield* this.docker(['exec', CONTAINER, 'bash', '-c', build]);
    // A separate step on purpose: folding the copy onto the end of the compile
    // made the escaping fragile enough that the object was built and then
    // silently not copied out.
    yield* this.docker([
      'exec',
      CONTAINER,
      'bash',
      '-c',
      `cp /prefix/drive_c/b-${tag}/in-${tag}.obj /work/out-${tag}.obj 2>/dev/null; ` +
        `rm -rf /prefix/drive_c/b-${tag}; true`,
    ]);

    const read = yield* Effect.result(
      Effect.tryPromise({
        try: async (): Promise<Compilation> => {
          for (let i = 0; i < VISIBILITY_ATTEMPTS; i += 1) {
            const file = Bun.file(objectPath);
            if ((await file.exists()) && file.size > 0) break;
            await Bun.sleep(VISIBILITY_INTERVAL_MS);
          }
          const log = (await Bun.file(logPath).exists())
            ? await Bun.file(logPath).text()
            : '';
          if (!(await Bun.file(objectPath).exists())) {
            return { built: false, diagnostic: lastLine(log.slice(-800) || 'no object') };
          }
          const object = await Bun.file(objectPath).bytes();
          // "It appeared and is non-empty" is not "it is the object": the
          // container's own view of the status and size is the authority.
          let want: number | undefined;
          let status: string | undefined;
          for (const token of log.split(/\s+/)) {
            if (token.startsWith('size=')) want = Number(token.slice(5));
            if (token.startsWith('status=')) status = token.slice(7);
          }
          if ((status !== undefined && status !== '0') || (want !== undefined && object.length !== want)) {
            return {
              built: false,
              diagnostic: lastLine(
                `compile did not produce a complete object: cl status=${status}, ` +
                  `container size=${want}, read ${object.length} bytes\n` +
                  log.slice(-500),
              ),
            };
          }
          return { built: true, object };
        },
        catch: (cause) =>
          new GateUnavailable({
            stage: 'compile',
            reason: `reading the object back: ${reason(cause)}`,
          }),
      }),
    );

    // Cleanup runs whether or not the read succeeded. Leaving these behind on
    // the failure path is how the exchange directory accumulated 1,618 files
    // nobody could attribute to a compile.
    for (const stale of [sourcePath, objectPath, logPath]) {
      try {
        fs.rmSync(stale, { force: true });
      } catch {
        // The exchange directory is shared; another agent's cleanup winning
        // this race is not this attempt's problem.
      }
    }
    if (read._tag === 'Failure') return yield* Effect.fail(read.failure);
    return read.success;
  }

  *toolchain(flags: string): EffectGen<Toolchain, GateUnavailable> {
    const clSha256 = yield* Effect.tryPromise({
      try: async () =>
        new Bun.CryptoHasher('sha256').update(await Bun.file(CL_EXE).bytes()).digest('hex'),
      catch: (cause) =>
        new GateUnavailable({
          stage: 'toolchain',
          reason: `cannot hash ${CL_EXE}: ${reason(cause)}`,
        }),
    });
    const id = `${clSha256}:${flags}`;
    const known = toolchains.get(id);
    if (known !== undefined) return known;

    // The stamp is read out of an object this compiler actually produced, so
    // the identity is a fact about emitted bytes rather than about an install.
    const probe = yield* this.compile(`${PROLOGUE}int probe(int a) { return a + 1; }\n`, flags);
    if (!probe.built) {
      return yield* new GateUnavailable({
        stage: 'toolchain',
        reason: `the compiler could not build the probe source: ${probe.diagnostic}`,
      });
    }
    const resolved: Toolchain = {
      id,
      clSha256,
      flags,
      compId: compilerStamp(probe.object),
    };
    toolchains.set(id, resolved);
    return resolved;
  }

  *check(attempt: GateAttempt): EffectGen<Verdict, GateUnavailable> {
    return (yield* this.contribute(attempt)).verdict;
  }

  *contribute(attempt: GateAttempt): EffectGen<Contribution, GateUnavailable> {
    const toolchain = yield* this.toolchain(attempt.flags);
    const source = PROLOGUE + attempt.source;

    // One retry. Under many concurrent agents the shared container
    // occasionally hands back an object with no code, and a transient failure
    // reported as a defect sends someone hunting a bug that is not there.
    let compilation = yield* this.compile(source, attempt.flags);
    if (!compilation.built) compilation = yield* this.compile(source, attempt.flags);
    if (!compilation.built) {
      return {
        verdict: {
          va: attempt.va,
          exact: false,
          compiled: false,
          emittedSize: Option.none(),
          masked: 0,
          compared: 0,
          weaklyVerified: false,
          firstDiff: Option.none(),
          matchedAt: Option.none(),
          symbol: Option.none(),
          detail: Option.some(compilation.diagnostic),
          toolchain,
        },
        entry: Option.none(),
      };
    }

    const comparison = compareToSubject({
      original: attempt.original,
      functions: emittedFunctions(compilation.object),
    });
    const fragment = comparison.exact && Option.getOrElse(comparison.matchedAt, () => 0) > 0;
    return {
      verdict: {
        va: attempt.va,
        exact: comparison.exact,
        compiled: true,
        emittedSize: comparison.emittedSize,
        masked: comparison.masked,
        compared: comparison.compared,
        weaklyVerified:
          comparison.exact &&
          attempt.original.length > 0 &&
          comparison.masked / attempt.original.length > WEAKLY_VERIFIED_ABOVE,
        firstDiff: comparison.firstDiff,
        matchedAt: comparison.matchedAt,
        symbol: comparison.symbol,
        detail: fragment
          ? Option.some(
              'matched at a non-zero offset inside a larger emitted function, ' +
                'not at a function entry',
            )
          : Option.none(),
        toolchain,
      },
      entry: Option.map(comparison.selected, (fn) => ({
        symbol: fn.symbol,
        bytes: fn.code,
        relocated: fn.relocated,
      })),
    };
  }
}
