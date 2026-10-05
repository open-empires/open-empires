/**
 * What an instruction says about a global, and what it does not.
 *
 * Every case here is a real encoding, written out byte for byte, because the
 * confirmation step this file exists to test compares the decoder's printed
 * operand against the instruction's OWN BYTES. A test built from invented
 * bytes would pass while the check did nothing.
 */
import { expect, test } from 'bun:test';
import { Option } from 'effect';
import type { Instruction } from '../disasm/interface';
import { accessWidth, dataReferences, encodesDword, readsAsFloat } from './code-references';

const DATA_LO = 0x635000;
const DATA_HI = 0x7a5000;
const inDataRegion = (va: number): boolean => va >= DATA_LO && va < DATA_HI;

const insn = (
  address: number,
  mnemonic: string,
  opStr: string,
  bytes: ReadonlyArray<number>,
): Instruction => ({
  id: 0,
  address,
  size: bytes.length,
  bytes: new Uint8Array(bytes),
  mnemonic,
  opStr,
});

const read = (instructions: ReadonlyArray<Instruction>) =>
  dataReferences({ instructions, containingFunction: Option.some(0x401000), inDataRegion });

test('the operand size prefix is the access width, and dword is not read as word', () => {
  expect(accessWidth('byte ptr [0x684480]')).toEqual(Option.some(1));
  expect(accessWidth('word ptr [0x684480]')).toEqual(Option.some(2));
  expect(accessWidth('eax, dword ptr [0x684480]')).toEqual(Option.some(4));
  expect(accessWidth('qword ptr [0x684480]')).toEqual(Option.some(8));
  expect(accessWidth('tbyte ptr [0x684480]')).toEqual(Option.some(10));
  // No memory operand at all: an immediate reads nothing.
  expect(accessWidth('0x684480')).toEqual(Option.none());
});

test('a value counts only when the instruction encodes it as a 32-bit field', () => {
  // A1 80 44 68 00 -- mov eax, [0x684480]
  expect(encodesDword(new Uint8Array([0xa1, 0x80, 0x44, 0x68, 0x00]), 0x684480)).toBe(true);
  expect(encodesDword(new Uint8Array([0xa1, 0x80, 0x44, 0x68, 0x00]), 0x684481)).toBe(false);
  // Too short to hold a dword at all.
  expect(encodesDword(new Uint8Array([0xeb, 0x02]), 0x684480)).toBe(false);
});

test('an absolute access names the address and states how much of it is read', () => {
  // A1 80 44 68 00 -- mov eax, dword ptr [0x684480]
  const found = read([insn(0x401000, 'mov', 'eax, dword ptr [0x684480]', [0xa1, 0x80, 0x44, 0x68, 0x00])]);
  expect(found.unconfirmed).toEqual([]);
  expect(found.references).toHaveLength(1);
  expect(found.references[0]).toMatchObject({
    site: 0x401000,
    address: 0x684480,
    form: 'absolute',
    mnemonic: 'mov',
  });
  expect(found.references[0]!.width).toEqual(Option.some(4));
});

test('a register in the brackets makes the address an array base, not the whole address', () => {
  // 8B 04 95 80 44 68 00 -- mov eax, dword ptr [edx*4 + 0x684480]
  const found = read([
    insn(0x401000, 'mov', 'eax, dword ptr [edx*4 + 0x684480]', [
      0x8b, 0x04, 0x95, 0x80, 0x44, 0x68, 0x00,
    ]),
  ]);
  expect(found.references[0]!.form).toBe('indexed');
  // The width is the ELEMENT's, and is carried, but `indexed` is what tells a
  // reader the extent is not stated.
  expect(found.references[0]!.width).toEqual(Option.some(4));
});

test('an immediate takes the address and states no width', () => {
  // 68 80 44 68 00 -- push 0x684480
  const found = read([insn(0x401000, 'push', '0x684480', [0x68, 0x80, 0x44, 0x68, 0x00])]);
  expect(found.references[0]).toMatchObject({ form: 'immediate' });
  expect(found.references[0]!.width).toEqual(Option.none());
});

test('one instruction can name two globals: the one it writes and the one it stores', () => {
  // C7 05 80 44 68 00 00 B1 66 00 -- mov dword ptr [0x684480], 0x66b100
  const found = read([
    insn(0x401000, 'mov', 'dword ptr [0x684480], 0x66b100', [
      0xc7, 0x05, 0x80, 0x44, 0x68, 0x00, 0x00, 0xb1, 0x66, 0x00,
    ]),
  ]);
  expect(found.references.map((r) => [r.address, r.form])).toEqual([
    [0x684480, 'absolute'],
    [0x66b100, 'immediate'],
  ]);
  // The width belongs to the memory operand; the stored constant reads
  // nothing, so claiming four bytes for it would be an invented fact.
  expect(found.references[1]!.width).toEqual(Option.none());
});

test('a branch target the decoder computed is refused, not filed as a global', () => {
  // A short jump encodes a one-byte displacement. The decoder prints the
  // absolute target, which appears nowhere in the bytes -- so without the
  // encoding check a branch target becomes a global.
  const found = read([insn(0x63547e, 'jmp', '0x635482', [0xeb, 0x02])]);
  expect(found.references).toEqual([]);
  expect(found.unconfirmed).toEqual([
    { site: 0x63547e, address: 0x635482, mnemonic: 'jmp', opStr: '0x635482' },
  ]);
});

test('an address outside the data region is not this inventory’s business', () => {
  // E8 ... -- a call into .text. Its target is code, and the function
  // inventory owns it.
  const found = read([insn(0x401000, 'call', '0x441d31', [0xe8, 0x2c, 0x0d, 0x04, 0x00])]);
  expect(found.references).toEqual([]);
  expect(found.unconfirmed).toEqual([]);
});

test('x87 loads are floats, and the integer conversions are not', () => {
  expect(readsAsFloat('fld')).toBe(true);
  expect(readsAsFloat('fmul')).toBe(true);
  // fild and fist convert an INTEGER; calling them float evidence would
  // mislabel every integer the x87 unit touches.
  expect(readsAsFloat('fild')).toBe(false);
  expect(readsAsFloat('fistp')).toBe(false);
  expect(readsAsFloat('mov')).toBe(false);
});
