import { Capstone, Const, loadCapstone } from 'capstone-wasm';
import type { Instruction, SubjectImage } from './interface';

/**
 * The capstone boundary. Nothing else in this service talks to the decoder.
 *
 * TWO THINGS HERE THAT SILENTLY PRODUCE WRONG ANSWERS IF GOT WRONG
 * ---------------------------------------------------------------
 * THE BASE ADDRESS IS AN OPTION, NOT A POSITIONAL ARGUMENT. `disasm(bytes,
 * va)` type-errors away and the decoder reports addresses counted from the
 * buffer start, so `je 0x441d31` becomes `je 0x331` and every branch target
 * in the listing names the wrong instruction. Passed as `{ address: va }` the
 * decoder resolves targets itself, which is why this module never computes a
 * displacement: there is one answer and capstone owns it.
 *
 * THE INPUT IS MARSHALLED THROUGH THE WASM STACK. A buffer over about 64 KB
 * throws "Out of bounds memory access" from inside the wasm, so every decode
 * here is chunked. The chunk restarts at the end of the last decoded
 * instruction, so an instruction straddling a boundary is decoded whole on the
 * next pass and the result is identical to one unchunked call.
 */

const CHUNK_BYTES = 4096;

/** Bytes a window covers when only the instruction at its start is wanted.
 *  At 256 bytes it can never truncate the first instruction (the longest x86
 *  instruction is 15 bytes), and everything decoded past it is cached, which
 *  turns a basic-block walk from one wasm call per instruction into one per
 *  window. */
const WALK_WINDOW_BYTES = 256;

export interface Decoder {
  readonly cs: Capstone;
  /**
   * Instructions after which control does not fall through, by decoder id.
   *
   * Derived from canonical encodings rather than written down, because the
   * mnemonic is not the instruction: byte `cf` decodes as `iretd` (a
   * different id), so a set built from the name `iret` would have had the
   * wrong member. Each id is checked against the mnemonic the decoder prints
   * for it, so a decoder that disagrees fails here instead of quietly
   * changing where every function ends.
   */
  readonly stopIds: ReadonlySet<number>;
  readonly jmpId: number;
}

export class DecoderFailure extends Error {}

const KEY = Symbol.for('open-empires.decomp.capstone');

/** Canonical encodings of the instructions that end a basic block, with the
 *  mnemonic each must decode to. */
const STOP_FORMS: ReadonlyArray<readonly [string, ReadonlyArray<number>]> = [
  ['ret', [0xc3]],
  ['retf', [0xcb]],
  ['iret', [0x66, 0xcf]],
  ['jmp', [0xeb, 0x00]],
  ['int3', [0xcc]],
  ['ud2', [0x0f, 0x0b]],
  ['hlt', [0xf4]],
];

/** Raw decode of one window. Returns [] where nothing decodes, and throws
 *  only when the decoder itself failed -- a reader that cannot fail would
 *  turn unreadable bytes into plausible instructions. */
const disasmWindow = (
  cs: Capstone,
  window: Uint8Array,
  address: number,
): ReadonlyArray<Instruction> => {
  if (window.length === 0) return [];
  try {
    return cs.disasm(window, { address }).map((i) => ({
      id: i.id,
      address: Number(i.address),
      size: i.size,
      bytes: i.bytes,
      mnemonic: i.mnemonic,
      opStr: i.opStr,
    }));
  } catch (cause) {
    const errNo = cs.errNo();
    if (errNo !== Const.CS_ERR_OK) {
      throw new DecoderFailure(
        `decoder failed at 0x${address.toString(16)}: ${Capstone.strError(errNo)}`,
        { cause },
      );
    }
    return [];
  }
};

export const loadDecoder = async (): Promise<Decoder> => {
  const g = globalThis as Record<symbol, unknown>;
  const existing = g[KEY];
  if (existing !== undefined) return existing as Decoder;
  await loadCapstone();
  const cs = new Capstone(Const.CS_ARCH_X86, Const.CS_MODE_32);
  const stopIds = new Set<number>();
  let jmpId: number | undefined;
  for (const [mnemonic, bytes] of STOP_FORMS) {
    const [insn] = disasmWindow(cs, new Uint8Array(bytes), 0);
    if (insn === undefined || insn.mnemonic !== mnemonic) {
      throw new DecoderFailure(
        `decoder does not spell ${mnemonic} as expected: got ${insn?.mnemonic ?? 'nothing'}`,
      );
    }
    stopIds.add(insn.id);
    if (mnemonic === 'jmp') jmpId = insn.id;
  }
  if (jmpId === undefined) throw new DecoderFailure('no jmp id derived');
  const decoder: Decoder = { cs, stopIds, jmpId };
  g[KEY] = decoder;
  return decoder;
};

/**
 * A linear sweep over `bytes`, stopping where the decoder stops.
 *
 * This is what the reference's single `disasm(buffer, va)` call produces: the
 * chunking is invisible because each chunk resumes at the end of the last
 * instruction the previous one decoded.
 */
export const decodeLinear = (
  d: Decoder,
  bytes: Uint8Array,
  address: number,
): ReadonlyArray<Instruction> => {
  const out: Instruction[] = [];
  let pos = 0;
  while (pos < bytes.length) {
    const window = bytes.subarray(pos, Math.min(bytes.length, pos + CHUNK_BYTES));
    const decoded = disasmWindow(d.cs, window, address + pos);
    if (decoded.length === 0) break;
    for (const i of decoded) out.push(i);
    const last = decoded[decoded.length - 1]!;
    const next = last.address + last.size - address;
    if (next <= pos) break;
    pos = next;
  }
  return out;
};

/** Offset of `va` in the subject's bytes, or undefined when the span named is
 *  not inside the image. */
export const offsetOf = (
  subject: SubjectImage,
  va: number,
  size: number,
): number | undefined => {
  const off = va - subject.imageBase;
  if (off < 0 || size < 0 || off + size > subject.bytes.length) return undefined;
  return off;
};

/** Whatever decodes in the `size` bytes at `va`, clamped to the image. No
 *  requirement that the instructions cover the span. */
export const decodeSpan = (
  d: Decoder,
  subject: SubjectImage,
  va: number,
  size: number,
): ReadonlyArray<Instruction> => {
  const off = va - subject.imageBase;
  if (off < 0 || off >= subject.bytes.length) return [];
  const end = Math.min(subject.bytes.length, off + Math.max(0, size));
  return decodeLinear(d, subject.bytes.subarray(off, end), va);
};

/**
 * Instructions covering EXACTLY the function's bytes, or undefined.
 *
 * A partial decode is not a function. Every caller that clusters, compares or
 * hands out a function asks this question, so it is asked in one place: a
 * second copy of "did it decode cleanly" is a second answer waiting to
 * disagree.
 */
export const decodeFunctionBody = (
  d: Decoder,
  subject: SubjectImage,
  fn: { readonly va: number; readonly size: number },
): ReadonlyArray<Instruction> | undefined => {
  if (offsetOf(subject, fn.va, fn.size) === undefined) return undefined;
  const insns = decodeSpan(d, subject, fn.va, fn.size);
  if (insns.length === 0) return undefined;
  return insns.reduce((n, i) => n + i.size, 0) === fn.size ? insns : undefined;
};

/**
 * The instruction at `va`, reading at most to the end of the executable span.
 *
 * `cache` is filled with every instruction the window yielded. Decoding a
 * larger window cannot change the first instruction in it, so a cached entry
 * is the same instruction a window opened at its own address would give.
 */
export const instructionAt = (
  d: Decoder,
  subject: SubjectImage,
  va: number,
  cache: Map<number, Instruction>,
): Instruction | undefined => {
  const hit = cache.get(va);
  if (hit !== undefined) return hit;
  const off = offsetOf(subject, va, 0);
  if (off === undefined) return undefined;
  const limit = Math.min(subject.textHi - subject.imageBase, subject.bytes.length);
  if (off >= limit) return undefined;
  const window = subject.bytes.subarray(off, Math.min(limit, off + WALK_WINDOW_BYTES));
  for (const i of decodeLinear(d, window, va)) {
    if (!cache.has(i.address)) cache.set(i.address, i);
  }
  return cache.get(va);
};
