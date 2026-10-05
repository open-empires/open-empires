import { Option, Schema } from 'effect';
import type { EffectGen } from 'effective-modules';

/**
 * The byte-exactness gate.
 *
 * A reconstruction counts only when the game's own MSVC 6.0 SP3 compiles it to
 * machine code byte-identical to the subject's bytes at that function's
 * address. Behavioural agreement is not consulted here and cannot produce a
 * pass. Everything else the project claims rests on this module.
 */

/**
 * The gate itself could not run: the compiler is unreachable, cl.exe is
 * missing, the container will not start.
 *
 * This is never a verdict. A source the compiler REJECTS is an outcome of the
 * attempt (`compiled: false`) and must not abort anything; a gate that cannot
 * run has no outcome at all, and silently recording "differs" for it would
 * retract every proof in one pass.
 */
export class GateUnavailable extends Schema.TaggedError<GateUnavailable>()('GateUnavailable', {
  stage: Schema.Literals(['container', 'toolchain', 'compile']),
  reason: Schema.String,
}) {}

/**
 * The flags the subject's own code was built with: C++ exceptions on, RTTI
 * off. Half of the toolchain identity every verdict is keyed on.
 */
export const SUBJECT_FLAGS = '/O2 /GX /GR-';

/**
 * The second bucket. A minority of the subject's functions only reproduce at
 * /O1, so an attempt names which flags it is claiming and the verdict is only
 * ever a claim about that one toolchain.
 */
export const SUBJECT_FLAGS_O1 = '/O1 /GX /GR-';

/**
 * Flag sets worth asking about when a reconstruction has resisted every source
 * spelling.
 *
 * The subject is ONE link, but a 1999 build has no obligation to compile every
 * translation unit alike: a library, a performance-critical file or a file with
 * its own pragma can carry different settings. The project's own two buckets
 * come first, so a plain pass is never mistaken for a finding; the rest are the
 * plausible per-file variations of a 1998 MSVC build.
 *
 * A match under anything but the first two is a FINDING, not a pass. Nothing
 * here may become a proof: a verdict is only ever a claim about the toolchain
 * the configuration names, and a third bucket is a decision for a person to
 * take, recorded by changing the configuration.
 */
export const SWEEP_FLAG_SETS: ReadonlyArray<string> = [
  '/O2 /GX /GR-', '/O1 /GX /GR-',
  '/Ox /GX /GR-', '/Og /GX /GR-', '/O2 /Ob0 /GX /GR-',
  '/O2 /Oy- /GX /GR-', '/O2 /Os /GX /GR-', '/O2 /Ot /GX /GR-',
  '/O2 /Oi- /GX /GR-', '/O2 /Gy /GX /GR-', '/O2 /G5 /GX /GR-',
  '/O2 /G3 /GX /GR-', '/Od /GX /GR-', '/O2 /GX- /GR-',
];

/**
 * Above this share of a function's bytes excused as relocation fields, a pass
 * is WEAKLY VERIFIED: it passed, but on too few bytes to carry much weight.
 * Named here so that every caller reports the same standard -- the threshold
 * is the gate's own judgement about how strong one of its passes is, not a
 * number each reader of a verdict gets to pick.
 */
export const WEAKLY_VERIFIED_ABOVE = 0.25;

/**
 * The compiler a verdict was proved against, identified by BYTES.
 *
 * Not by a version string: two installs that both report "6.0" can emit
 * different code, and the project has already shipped thousands of proofs made
 * by compilers that no longer existed, because the proofs carried no prover
 * identity.
 */
export interface Toolchain {
  /** `${clSha256}:${flags}`. Proofs are stored under this. */
  readonly id: string;
  /** sha256 of cl.exe's own bytes. */
  /**
   * sha256 over every binary that decides the output -- CL.EXE, C1.DLL,
   * C1XX.DLL, C2.DLL and LINK.EXE -- not over cl.exe alone. The name is kept
   * because it is a stored column, but it has not meant "cl.exe's own bytes"
   * since that identity turned out not to change when the code generator did.
   */
  readonly clSha256: string;
  readonly flags: string;
  /**
   * The `@comp.id` the compiler stamps into every object it emits, read back
   * out of an object it actually produced. Its low 16 bits are the build
   * number -- SP3 reads back as 0x20ff, 8447 -- and it names the code
   * generator, which cl.exe's hash does not cover. `None` only if the probe
   * object carried no such symbol.
   */
  readonly compId: Option.Option<number>;
}

/**
 * One reconstruction, offered against one address.
 *
 * The gate takes the subject's bytes rather than reading them, so the
 * comparison cannot drift from whichever module owns the image, and the gate
 * stays testable with bytes that came from anywhere.
 */
export interface GateAttempt {
  /** The address this reconstruction claims. Reported; never used to find the
   *  bytes, which are supplied. */
  readonly va: number;
  /** The subject's own bytes at `va`, and therefore the size under test. */
  readonly original: Uint8Array;
  /** The reconstruction's C++, exactly as its author wrote it. */
  readonly source: string;
  /** `SUBJECT_FLAGS` or `SUBJECT_FLAGS_O1`. */
  readonly flags: string;
  /**
   * Which compiler install to use: a directory name under the toolchain root.
   * Defaults to `vc98`, build 8447.
   *
   * The subject was built by TWO compilers -- its own Rich header records 306
   * objects from build 8447 and 169 from build 8168 -- so an attempt has to be
   * able to say which one it is claiming. The verdict records the toolchain
   * that produced it, and a proof is only a proof under the compiler that
   * made it.
   */
  readonly toolchain?: string;
}

/** What the gate decided about one attempt. */
export interface Verdict {
  readonly va: number;
  /**
   * Byte-identical to the subject, relocation fields excused. The only field
   * that may be read as a proof.
   */
  readonly exact: boolean;
  /** False means the compiler rejected the source or emitted nothing usable.
   *  An outcome of its own, never folded into "differs". */
  readonly compiled: boolean;
  /** The emitted function's own length, which is not the subject's size: a
   *  section is padded to its alignment, and a switch's tables sit after its
   *  code. */
  readonly emittedSize: Option.Option<number>;
  /** Relocation bytes the gate had to EXCUSE because the linker would fill
   *  them. Over a quarter of the subject's size is weakly verified. */
  readonly masked: number;
  /** Bytes actually compared: the subject's size minus `masked`. */
  readonly compared: number;
  /** An exact pass that rests on fewer compared bytes than
   *  `WEAKLY_VERIFIED_ABOVE` allows. Always false when `exact` is false. */
  readonly weaklyVerified: boolean;
  /** Offset of the first unexcused difference. Diagnostic only. */
  readonly firstDiff: Option.Option<number>;
  /**
   * Where the match sits inside the emitted function. `Some(0)` is the claim a
   * reconstruction makes -- the match is at the function's ENTRY. `Some(n)`
   * for n > 0 is a FRAGMENT match, a weaker and different claim, reported
   * separately rather than rejected. `None` when nothing matched.
   */
  readonly matchedAt: Option.Option<number>;
  /** The emitted symbol the verdict describes: the one that matched, or the
   *  closest candidate when none did. */
  readonly symbol: Option.Option<string>;
  /** The compiler's own diagnostic when it rejected the source, or the note
   *  explaining a weaker outcome. */
  readonly detail: Option.Option<string>;
  readonly toolchain: Toolchain;
}

/**
 * One function exactly as the compiler emitted it, with the offsets inside it
 * the LINKER would patch.
 *
 * The offsets come from the object's own relocation records, so nothing
 * downstream has to guess which bytes are addresses.
 */
export interface EmittedCode {
  readonly symbol: string;
  readonly bytes: Uint8Array;
  readonly relocated: ReadonlySet<number>;
}

/**
 * A verdict, plus the bytes the attempt actually produced.
 *
 * `check` answers "does this reconstruction match"; this answers "and what
 * exactly did it emit", which is what a caller needs when the bytes have to go
 * somewhere -- composed into the image at the function's real address, or
 * searched for relocation fields. The compile is the same compile: one attempt
 * per compilation, for the same reason `check` cannot express a batch.
 */
export interface Contribution {
  readonly verdict: Verdict;
  /**
   * The emitted function the comparison selected, or `None` when the compiler
   * rejected the source or emitted no code.
   *
   * Its bytes start at that function's ENTRY, never at a fragment offset: a
   * caller placing them at the subject's address can only place what the
   * compiler emitted THERE, and a fragment match is a different and weaker
   * claim about where the bytes occur.
   */
  readonly entry: Option.Option<EmittedCode>;
}

export interface IGate {
  /**
   * The identity every verdict this gate produces is relative to.
   *
   * Derived from the compiler's bytes and confirmed by a probe compile, so it
   * cannot be satisfied by a version banner.
   */
  toolchain(flags: string, install?: string): EffectGen<Toolchain, GateUnavailable>;

  /**
   * Compile ONE reconstruction, alone, and compare it to the subject's bytes.
   *
   * One attempt per compilation is a correctness property, not a performance
   * choice, which is why this method cannot express a batch. Compiling several
   * reconstructions into one object made the gate search the whole
   * concatenated output for the subject's bytes, so a deliberately broken
   * reconstruction passed on a correct SIBLING's bytes -- three agents hit
   * that independently. A compilation containing only the attempt under test
   * cannot do it.
   */
  check(attempt: GateAttempt): EffectGen<Verdict, GateUnavailable>;

  /**
   * The same single compile as `check`, with the emitted bytes kept.
   *
   * `check` is the whole surface anything deciding a VERDICT needs, and stays
   * the only one it may use. This exists for the two audits that must place
   * compiled bytes rather than judge them.
   */
  contribute(attempt: GateAttempt): EffectGen<Contribution, GateUnavailable>;
}
