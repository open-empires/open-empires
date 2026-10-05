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
    if (!(next >= end || (nextByte !== undefined && PAD.has(nextByte)))) continue;
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
