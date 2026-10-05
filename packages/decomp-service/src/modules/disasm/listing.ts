import { Option } from 'effect';
import type { FunctionExtent, Instruction } from './interface';

/**
 * Rendering decoded instructions as text a person or an agent reads.
 *
 * Both renderers print the ADDRESS of every instruction. Without it a reader
 * has to count bytes by eye to find where a branch lands, and one agent
 * misread a `je` as targeting the adjacent instruction -- which would have
 * produced a wrong algorithm from a correct listing.
 */

const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');

const pad = (s: string, width: number): string => (s.length >= width ? s : s.padEnd(width));

export const functionName = (va: number): string =>
  `sub_${va.toString(16).toUpperCase().padStart(8, '0')}`;

/** One function's annotated disassembly. Bytes the linker fixes up are marked
 *  `*` when a mask is supplied; the mask is the gate's, because the gate owns
 *  the comparison it exists for. */
export const renderListing = (
  fn: FunctionExtent,
  insns: ReadonlyArray<Instruction>,
  relocationMask: Option.Option<Uint8Array>,
): string => {
  const mask = Option.getOrUndefined(relocationMask);
  const masked = mask === undefined ? 0 : mask.reduce((n, b) => n + (b === 0 ? 0 : 1), 0);
  const head =
    mask === undefined
      ? `${functionName(fn.va)}  ${fn.size} bytes`
      : `${functionName(fn.va)}  ${fn.size} bytes  (${masked} masked as relocations)`;
  const lines = insns.map((i) => {
    const o = i.address - fn.va;
    const rel =
      mask === undefined
        ? ''
        : mask.subarray(o, o + i.size).some((b) => b !== 0)
          ? '* '
          : '  ';
    const addr = `0x${i.address.toString(16).padStart(8, '0')}`;
    return `  ${addr} ${rel}${pad(hex(i.bytes), 20)} ${pad(i.mnemonic, 7)} ${i.opStr}`;
  });
  return [head, ...lines].join('\n');
};

/** One instruction as it appears inside a work batch. */
export const renderBatchInstruction = (i: Instruction): string =>
  `    ${i.address.toString(16).padStart(8, '0')}  ${pad(hex(i.bytes), 14)} ${pad(i.mnemonic, 7)} ${i.opStr}`;
