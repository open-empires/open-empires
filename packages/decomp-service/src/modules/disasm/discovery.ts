import { decodeSpan, type Decoder } from './decoder';
import type {
  Discovery,
  EvidenceKind,
  FunctionExtent,
  Rejection,
  SubjectImage,
} from './interface';

/**
 * Entries the inventory never listed.
 *
 * The inventory covers 71.9% of the executable span, and the rest is not
 * padding: a gap typically begins `56 8b f1 e8 ...` -- push esi, mov esi,ecx,
 * call -- which is a __thiscall member, not data. The inventory follows direct
 * calls, so it holds almost nothing reached only through a vtable.
 *
 * TWO MEASUREMENTS FIX THE ENTRY POINTS
 * -------------------------------------
 * A clean decode proves NOTHING on its own, because x86 decodes almost any
 * byte sequence: a prologue scan alone produced 1,043 entries, of which none
 * was a direct call target. The evidence that separates a real entry from
 * mid-function bytes is a REFERENCE -- a direct call, or a dword somewhere in
 * the image holding that address, which is what a vtable slot is.
 *
 *   known inventory functions referenced by a dword:   381/5504   (6%)
 *   prologue-carved gap entries referenced by a dword: 915/1043  (87%)
 *
 * The known functions are called directly and almost never appear in a table;
 * the gap entries are the reverse. So an entry is emitted only where both
 * agree: something references the address, AND the bytes there decode cleanly
 * from a prologue to a terminator.
 *
 * The reference must come from a direct call or from OUTSIDE the executable
 * span. A pointer stored inside the code is an exception scope table, which
 * sits beside the function it describes and points into its middle: 0x40506A
 * was referenced from 0x405934, in duplicate pairs, and is a shared epilogue
 * that pops edi, esi and ebx without pushing them. Requiring the reference to
 * come from the data section, where vtables live, rejects it. Two filters were
 * tried and discarded first -- a stack-balance check failed 25% of
 * KNOWN-GOOD functions, and a consecutive-pointer-run check kept 0x40506A --
 * so this one is measured against both the false positive and the known set
 * (4,543 of 5,504 known functions carry the same evidence).
 */

const PAD = new Set([0x90, 0xcc]);
const TERMINATORS = new Set(['ret', 'retf', 'jmp']);

/**
 * How many bytes of inter-function padding start at this offset, if any.
 *
 * `PAD` is a set of single BYTES and could not express MSVC 6's two-byte
 * filler: it pads with `8b ff` -- `mov edi,edi` -- as well as with `nop` and
 * `int3`. Adding 0x8b to the set would have been wrong in the other
 * direction, because 0x8b is the opcode of every ordinary `mov` and any
 * function whose first instruction was one would have read as padding.
 *
 * That gap had already cost four wrong extents. A worker recorded 0x565C70 at
 * 344 bytes where it is 130: a `ret` at 0x565CF1 is followed by `8b ff` and
 * then a switch table, and with the filler unrecognised the table's bytes were
 * decoded as instructions and yielded a branch belonging to the NEXT function.
 * Four real functions were rejected as interior to those four extents as a
 * result.
 */
/**
 * Length of a `lea r,[r+0]` filler at `off`, or 0 if there is not one.
 *
 * Four encodings, all of which MSVC 6 uses to align what follows:
 *
 *     8d 49 00                 lea ecx,[ecx+0]        3 bytes
 *     8d 64 24 00              lea esp,[esp+0]        4 bytes (SIB)
 *     8d 80 00 00 00 00        lea eax,[eax+0]        6 bytes (disp32)
 *     8d a4 24 00 00 00 00     lea esp,[esp+0]        7 bytes (SIB + disp32)
 *
 * The test is the ModRM, not the byte string: mod must be 01 or 10 (a
 * displacement is present), reg must equal r/m (the register is leaed from
 * itself), and every displacement byte must be zero.
 */
const leaFillerLength = (bytes: Uint8Array, off: number): number => {
  const modrm = bytes[off + 1];
  if (modrm === undefined) return 0;
  const mod = modrm >> 6;
  const reg = (modrm >> 3) & 7;
  const rm = modrm & 7;
  if (mod !== 1 && mod !== 2) return 0;
  if (reg !== rm) return 0;
  // rm == 4 means a SIB byte follows, and for `[r+0]` it must encode that
  // same register as the base with no index: 0x24 is base=esp/index=none,
  // and in general (index == 4) with base == reg.
  let at = off + 2;
  if (rm === 4) {
    const sib = bytes[at];
    if (sib === undefined) return 0;
    const index = (sib >> 3) & 7;
    const base = sib & 7;
    if (index !== 4 || base !== reg) return 0;
    at += 1;
  }
  const dispBytes = mod === 1 ? 1 : 4;
  for (let k = 0; k < dispBytes; k += 1) {
    if (bytes[at + k] !== 0) return 0;
  }
  return at + dispBytes - off;
};

export const paddingRun = (bytes: Uint8Array, off: number): number => {
  let n = 0;
  while (off + n < bytes.length) {
    const b = bytes[off + n]!;
    if (PAD.has(b)) { n += 1; continue; }
    if (b === 0x8b && bytes[off + n + 1] === 0xff) { n += 2; continue; }
    // `lea r,[r+0]` -- a THIRD filler form, and the one that aligns a
    // function's own jump table to a dword.
    //
    // At 0x54F530 the `ret 4` at 0x54F7DA is followed by `8d 49 00` and then
    // an 11-entry table at 0x54F7E0: without this the function cannot be
    // closed at all and its 688 bytes read as unreachable residue. Measured
    // across every residue head, the four encodings are worth 32,258 bytes
    // that become recordable, and they cost nothing: 594 of 600 random proven
    // sizes come out exact with and without them, 0 short and 0 long either
    // way.
    //
    // Matched by the RULE rather than by four byte strings: opcode 0x8D with a
    // ModRM whose reg field equals its r/m field and a zero displacement. A
    // `lea` of a register from itself with no offset computes nothing, so a
    // compiler emits it only as filler -- which is why it is safe to end a
    // function on, and why listing the canonical encodings would have missed
    // whichever register the next one happens to use.
    if (b === 0x8d) {
      const lea = leaFillerLength(bytes, off + n);
      if (lea > 0) { n += lea; continue; }
    }
    break;
  }
  return n;
};

/** Dwords needed to call what follows a terminator a jump table. */
const TABLE_MIN_ENTRIES = 4;

/**
 * Whether a switch's jump table starts at this offset.
 *
 * A function whose `switch` compiles to a dispatch table has that table laid
 * out AFTER its final terminator, inside the span the next entry bounds. The
 * terminator check therefore never fired -- the byte after it is the table's
 * first byte, which is neither `nop` nor `int3` -- so the function could not
 * be closed at all. That refused 103 stretches holding 78,882 bytes,
 * including the three largest functions in the image.
 *
 * The convention is settled by the proven set rather than chosen here:
 * 0x4DB870 is proven byte-exact at 227 bytes with its eight-entry table at
 * 0x4DB954 EXCLUDED from the size. So the table ends the function and is not
 * part of it.
 *
 * Four entries, not two, and every one of them an address inside `.text`. A
 * run of four consecutive dwords that all point into the executable span is
 * not something ordinary code produces, and requiring fewer would risk
 * truncating a real function -- which is the worse error, since a short
 * extent is an entry an agent cannot reconstruct at all.
 */
const jumpTableAt = (subject: SubjectImage, va: number, end: number): boolean => {
  const dwordAt = (at: number): number | undefined => {
    if (at < 0 || at + 3 >= subject.bytes.length) return undefined;
    return (
      subject.bytes[at]! |
      (subject.bytes[at + 1]! << 8) |
      (subject.bytes[at + 2]! << 16) |
      (subject.bytes[at + 3]! << 24)
    );
  };
  const inText = (v: number | undefined): boolean =>
    v !== undefined && v >= subject.textLo && v < subject.textHi;

  let entries = 0;
  let at = va - subject.imageBase;
  while (inText(dwordAt(at))) { entries += 1; at += 4; }
  if (entries < TABLE_MIN_ENTRIES) return false;

  // AND THE TABLE MUST BE THE LAST THING IN THE SPAN.
  //
  // Four in-text dwords alone is not enough, because MSVC also lays a switch
  // table in the MIDDLE of a function, with more of that function's code
  // after it. Closing there truncates a real function, which is the worse
  // error: a short extent is an inventory entry nothing can reconstruct.
  //
  // Measured, which is the only reason this clause is here: against the
  // proven set, the four-dword test alone cut 0x563770 to 1,836 bytes where
  // it is proved at 2,009. Requiring the run to reach the bound, or to be
  // followed by inter-function padding, is what makes it TRAILING rather than
  // merely present.
  const after = subject.imageBase + at;
  if (after >= end) return true;
  return paddingRun(subject.bytes, at) > 0;
};
/**
 * REMOVED: a first-byte whitelist.
 *
 * This was `[0x55, 0x53, 0x56, 0x57, 0x8b, 0x83, 0x6a, 0xa1]`, and anything
 * starting with another byte was rejected as 'no-prologue' -- while this
 * module's own contract says prologue matching is NOT used, because the
 * subject is MSVC 6 with frame-pointer omission.
 *
 * Measured against the proven set, which is the only ground truth available:
 * 468 of 3,314 byte-exact functions (14.1%) start with a byte outside that
 * list -- 0x8a (91 of them), 0x33 (57), 0x51 (51), 0x81, 0xff, 0xe9. Every
 * one is proven, so discovery would have refused to find any of them. It
 * rejected 524 addresses that DO carry reference evidence on this rule.
 *
 * A validator that rejects known-good input is worse than no validator; this
 * project has already lost a pass that way to a stack-balance filter. The
 * remaining checks are the ones that rest on evidence rather than shape: an
 * entry needs a reference, must decode, and must terminate.
 */

/** The one `__ehhandler` trampoline every try block in this subject jumps to.
 *  Subject-specific, like the address of anything else in it. */
const SHARED_HANDLER_TARGET = '0x613b31';

/**
 * A frame-borrower that is nonetheless a real function.
 *
 * sub_00613EAA is CRT code whose original source IS hand-written assembly: it
 * stores ebp itself as a value into the exception-registration record, so it
 * reads [ebp+8] without establishing a frame while being nobody's funclet. It
 * has a byte-exact reconstruction already, and a proof outranks a heuristic --
 * so the one case the classifier gets wrong is named here rather than silently
 * discarded.
 */
const PROVEN_NOT_GENERATED = new Set([0x613eaa]);

const CALL_TARGET = /^0x[0-9a-f]+$/;
const FRAME_READ = /\[ebp\s*[-+]/;

/** Index of the first element greater than `v`, on an ascending array. */
const upperBound = (xs: ReadonlyArray<number>, v: number): number => {
  let lo = 0;
  let hi = xs.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (xs[mid]! <= v) lo = mid + 1;
    else hi = mid;
  }
  return lo;
};

/** Addresses something in the image refers to as a function entry, and how. */
export const evidence = (
  d: Decoder,
  subject: SubjectImage,
  inventory: ReadonlyArray<FunctionExtent>,
): Map<number, EvidenceKind[]> => {
  const { bytes, imageBase, textLo, textHi } = subject;
  const ev = new Map<number, EvidenceKind[]>();
  const add = (va: number, kind: EvidenceKind) => {
    const at = ev.get(va);
    if (at === undefined) ev.set(va, [kind]);
    else if (!at.includes(kind)) at.push(kind);
  };
  for (const f of inventory) {
    for (const i of decodeSpan(d, subject, f.va, f.size)) {
      if (i.mnemonic === 'call' && CALL_TARGET.test(i.opStr)) {
        add(Number.parseInt(i.opStr.slice(2), 16), 'call');
      }
    }
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let p = 0; p < bytes.length - 3; p += 4) {
    const v = view.getUint32(p, true);
    const at = p + imageBase;
    if (v >= textLo && v < textHi && !(at >= textLo && at < textHi)) add(v, 'rdata-pointer');
  }
  return ev;
};

/**
 * Size of the function at `start`, or a reason it is not one.
 *
 * Closes at a ret/jmp followed by padding or by `end`. A function whose bytes
 * run straight into the next entry with no terminator is rejected: a wrong
 * size costs an agent its whole budget on an impossible target.
 */
export const body = (
  d: Decoder,
  subject: SubjectImage,
  start: number,
  end: number,
): number | Rejection['reason'] => {
  const off = start - subject.imageBase;
  if (off < 0 || off >= subject.bytes.length) return 'no-decode';
  const insns = decodeSpan(d, subject, start, end - start);
  if (insns.length === 0) return 'no-decode';
  for (const i of insns) {
    const next = i.address + i.size;
    const nextByte = subject.bytes[next - subject.imageBase];
    if (!TERMINATORS.has(i.mnemonic)) continue;
    // What may follow a function's last instruction: the bound, inter-function
    // padding, or -- after optional padding -- the switch table the function
    // dispatches through, which MSVC lays out past the code and which the
    // proven set shows is excluded from the size.
    const pad = paddingRun(subject.bytes, next - subject.imageBase);
    const closes =
      next >= end ||
      (nextByte !== undefined && PAD.has(nextByte)) ||
      pad > 0 ||
      jumpTableAt(subject, next + pad, end);
    if (!closes) continue;
    const covered = insns
      .filter((x) => x.address < next)
      .reduce((n, x) => n + x.size, 0);
    if (covered !== next - start) return 'discontiguous-decode';
    return next - start;
  }
  return 'no-terminator';
};

/**
 * True for code the COMPILER emitted, which has no source to recover.
 *
 * Under /GX, MSVC emits an unwind funclet (`mov ecx,[ebp-N]; jmp <dtor>`) and
 * an `__ehhandler` stub (`mov eax,<FuncInfo>; jmp <shared handler>`) for a
 * function with a try block, and places them past the end of the code, where
 * this discoverer finds them: they are referenced from the unwind map in the
 * data section, which is exactly the evidence a vtable slot provides.
 *
 * They must not enter the inventory. There is no C++ that produces either
 * piece on its own, so the only way to "reconstruct" one is to transcribe the
 * assembly -- which the gate then passes with 44% of the bytes masked. Six
 * agents did precisely that for 96 addresses before this was caught, and the
 * result inflates both the numerator and the denominator with work that is not
 * reconstruction. The funclets reappear on their own once the enclosing
 * function's try block is recovered.
 */
export const isCompilerGenerated = (
  d: Decoder,
  subject: SubjectImage,
  fn: FunctionExtent,
): boolean => {
  if (PROVEN_NOT_GENERATED.has(fn.va)) return false;
  const insns = decodeSpan(d, subject, fn.va, fn.size);
  if (insns.length === 0) return false;
  const shape = insns.map((i) => i.mnemonic).join(' ');
  if (
    shape === 'mov jmp' ||
    shape === 'mov jmp mov jmp' ||
    insns.some((i) => i.mnemonic === 'jmp' && i.opStr === SHARED_HANDLER_TARGET)
  ) {
    return true;
  }
  // The general rule, which the two shapes above are only instances of: a
  // function cannot read a stack frame it never established. These funclets
  // reach into the ENCLOSING function's locals via [ebp-N] without a
  // `push ebp` of their own, so they can only run while that frame is live.
  // Three agents hit a third form the shape tests missed --
  // `mov eax,[ebp-N]; push eax; call <operator delete>; pop ecx; ret`, the
  // cleanup for a `new T(...)` whose constructor throws -- which is what
  // prompted stating the rule instead of listing shapes. Measured: it flags
  // 394 of the discovered entries and only 21 of the 5,409 original ones.
  for (const i of insns) {
    if (i.mnemonic === 'push' && i.opStr === 'ebp') return false;
    if ((i.mnemonic === 'mov' || i.mnemonic === 'lea') && i.opStr.startsWith('ebp,')) return false;
    if (i.mnemonic === 'enter') return false;
    if (FRAME_READ.test(i.opStr)) return true;
  }
  return false;
};

export const discover = (
  d: Decoder,
  subject: SubjectImage,
  inventory: ReadonlyArray<FunctionExtent>,
): Discovery => {
  const { textLo, textHi } = subject;
  const known = [...inventory].sort((a, b) => a.va - b.va);
  const starts = known.map((f) => f.va);
  const inside = (v: number): boolean => {
    const k = upperBound(starts, v) - 1;
    return k >= 0 && known[k]!.va <= v && v < known[k]!.va + known[k]!.size;
  };

  const ev = evidence(d, subject, known);
  const candidates = [...ev.keys()]
    .filter((v) => v >= textLo && v < textHi && !inside(v))
    .sort((a, b) => a - b);
  // A function ends no later than the next thing already known to start
  // something: the next inventory entry, or the next evidenced address.
  const bounds = [...new Set([...starts, ...candidates, textHi])].sort((a, b) => a - b);

  const found: Array<Discovery['found'][number]> = [];
  const rejected: Rejection[] = [];
  for (const va of candidates) {
    const size = body(d, subject, va, bounds[upperBound(bounds, va)]!);
    if (typeof size === 'string') {
      rejected.push({ va, reason: size });
      continue;
    }
    if (size === 0) {
      rejected.push({ va, reason: 'no-decode' });
      continue;
    }
    if (isCompilerGenerated(d, subject, { va, size })) {
      rejected.push({ va, reason: 'compiler-generated' });
      continue;
    }
    found.push({ va, size, evidence: ev.get(va)! });
  }
  return { found, rejected };
};
