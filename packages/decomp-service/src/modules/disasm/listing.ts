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

/**
 * One function's annotated disassembly. Bytes the linker fixes up are marked
 * `*` when a mask is supplied; the mask is the gate's, because the gate owns
 * the comparison it exists for.
 *
 * `trailing` is the bytes at the end of the span that did not decode, printed
 * as data. MSVC places a switch's jump table and its byte-per-case index table
 * INSIDE the function body, and those are data: three inventory entries end in
 * one, and 0x563770 is proven byte-exact at its recorded 2009 bytes with such
 * a table in it. Before this they rendered as nothing at all -- the caller
 * turned an undecodable span into an empty string -- so a provable function
 * reached agents with no body and sat in the queue untouched.
 *
 * It is printed, never dropped. Silent truncation is the failure this module's
 * header warns about; naming the bytes as data is the opposite of hiding them.
 */
export const renderListing = (
  fn: FunctionExtent,
  insns: ReadonlyArray<Instruction>,
  relocationMask: Option.Option<Uint8Array>,
  trailing: Uint8Array = new Uint8Array(0),
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
  if (trailing.length === 0) return [head, ...lines].join('\n');

  // 16 bytes a row, addressed, so a reader can tell a jump table (dwords
  // pointing inside this function) from an index table (ascending small
  // integers) without counting bytes by eye.
  const dataAt = fn.va + fn.size - trailing.length;
  const rows: string[] = [
    `  ;; ${trailing.length} byte(s) from 0x${dataAt.toString(16).padStart(8, '0')} did not`
      + ` decode as instructions, and are shown as data. MSVC puts a switch's`,
    `  ;; jump table and index table inside the function body; those bytes are`
      + ` part of the function and the gate compares them.`,
  ];
  for (let o = 0; o < trailing.length; o += 16) {
    const row = trailing.subarray(o, Math.min(trailing.length, o + 16));
    const addr = `0x${(dataAt + o).toString(16).padStart(8, '0')}`;
    rows.push(`  ${addr}   ${pad(hex(row), 20)} db`);
  }
  return [head, ...lines, ...rows].join('\n');
};

/** One instruction as it appears inside a work batch. */
export const renderBatchInstruction = (i: Instruction): string =>
  `    ${i.address.toString(16).padStart(8, '0')}  ${pad(hex(i.bytes), 14)} ${pad(i.mnemonic, 7)} ${i.opStr}`;
