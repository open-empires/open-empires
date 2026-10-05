import { instructionAt, type Decoder } from './decoder';
import type { FunctionExtent, Instruction, Inventory, SubjectImage } from './interface';

/**
 * Function entries and extents, from the call graph and from pointer tables.
 *
 * Entry points come from direct call targets, which is reliable here: 91.6% of
 * E8 displacements resolve inside the executable span, so the call graph
 * itself identifies function starts. Prologue matching is NOT used -- this
 * binary is MSVC 6 with frame-pointer omission, where only 229 functions
 * across 2.2 MB emit `push ebp; mov ebp, esp`.
 *
 * Extents come from a basic-block walk that follows BOTH edges of every branch
 * and stops at a jump to another known start, which is a tail call.
 */

/**
 * Whether control can leave this instruction for an address other than the
 * next one.
 *
 * The base mnemonic is the last space-separated word, because the decoder
 * prepends prefixes into the mnemonic (`bnd jmp`, `notrack jmp`, `repz ret`).
 * Measured against the reference decoder's own operand detail over all
 * 2,258,045 byte offsets of the subject's executable span: this predicate
 * agrees with it on every one of the 117,814 branch instructions found, and
 * no `j`-prefixed mnemonic is outside it.
 */
const isBranch = (mnemonic: string): boolean => {
  const base = mnemonic.slice(mnemonic.lastIndexOf(' ') + 1);
  return base.startsWith('j') || base === 'ljmp' || base === 'xbegin';
};

const FIRST_IMMEDIATE = /^(0x[0-9a-f]+|\d+)/;

/**
 * The branch's first operand when it is an immediate, which for a direct
 * branch is its target.
 *
 * Read from the printed operand because the decoder build in use exposes no
 * operand detail. Checked against the reference's `operands[0]` over the same
 * 117,814 branches: the presence and the value agree on every one, including
 * the far-jump `seg:offset` form, whose first operand is the segment.
 */
const branchImmediate = (insn: Instruction): number | undefined => {
  const m = FIRST_IMMEDIATE.exec(insn.opStr);
  if (m === null) return undefined;
  const t = m[1]!;
  return t.startsWith('0x') ? Number.parseInt(t.slice(2), 16) : Number.parseInt(t, 10);
};

/**
 * Direct call targets, plus every aligned dword anywhere in the image that
 * points into the executable span.
 *
 * Direct calls alone reach 71% of the span. The rest is mostly virtual
 * methods -- this is a C++ game, so a large share of functions are only ever
 * reached through a vtable, which appears as an aligned dword pointing into
 * code.
 */
export const seeds = (
  subject: SubjectImage,
): { starts: ReadonlyArray<number>; fromDirectCalls: number; fromPointerTables: number } => {
  const { bytes, imageBase, textLo, textHi } = subject;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const textOff = textLo - imageBase;
  const textSize = textHi - textLo;
  const found = new Set<number>();
  for (let i = 0; i < textSize - 5; i += 1) {
    if (bytes[textOff + i] !== 0xe8) continue;
    const target = textLo + i + 5 + view.getInt32(textOff + i + 1, true);
    if (target >= textLo && target < textHi) found.add(target);
  }
  const fromDirectCalls = found.size;
  for (let off = 0; off < bytes.length - 4; off += 4) {
    const v = view.getUint32(off, true);
    if (v >= textLo && v < textHi) found.add(v);
  }
  return {
    starts: [...found].sort((a, b) => a - b),
    fromDirectCalls,
    fromPointerTables: found.size - fromDirectCalls,
  };
};

/** Walk basic blocks from `start`; return the exclusive end address. */
export const extent = (
  d: Decoder,
  subject: SubjectImage,
  start: number,
  knownStarts: ReadonlySet<number>,
  cache: Map<number, Instruction>,
): number => {
  const { textLo, textHi } = subject;
  const seen = new Set<number>();
  const work: number[] = [start];
  let end = start;
  while (work.length > 0) {
    let va = work.pop()!;
    for (;;) {
      if (seen.has(va) || va < textLo || va >= textHi) break;
      seen.add(va);
      const insn = instructionAt(d, subject, va, cache);
      if (insn === undefined) break;
      end = Math.max(end, va + insn.size);
      if (d.stopIds.has(insn.id)) {
        // An unconditional jump to another function start is a tail call, so
        // the target belongs to that function and not to this one.
        if (insn.id === d.jmpId) {
          const t = branchImmediate(insn);
          if (t !== undefined && t >= textLo && t < textHi && !knownStarts.has(t)) work.push(t);
        }
        break;
      }
      if (isBranch(insn.mnemonic)) {
        const t = branchImmediate(insn);
        if (t !== undefined && t >= textLo && t < textHi && !knownStarts.has(t)) work.push(t);
      }
      va += insn.size;
    }
  }
  return end;
};

export const buildInventory = (d: Decoder, subject: SubjectImage): Inventory => {
  const { starts, fromDirectCalls, fromPointerTables } = seeds(subject);
  const known = new Set(starts);
  const cache = new Map<number, Instruction>();
  const functions: FunctionExtent[] = [];
  let coveredBytes = 0;
  for (let i = 0; i < starts.length; i += 1) {
    const va = starts[i]!;
    // A function ends no later than the next known start.
    const end = Math.min(
      extent(d, subject, va, known, cache),
      i + 1 < starts.length ? starts[i + 1]! : subject.textHi,
    );
    functions.push({ va, size: end - va });
    coveredBytes += end - va;
  }
  return {
    subjectSha256: subject.sha256,
    textLo: subject.textLo,
    textHi: subject.textHi,
    functions,
    coveredBytes,
    seedsFromDirectCalls: fromDirectCalls,
    seedsFromPointerTables: fromPointerTables,
  };
};
