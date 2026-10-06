/**
 * The decisions the inventory makes, and the ones it refuses to make.
 *
 * Each test below is one rule that, if it quietly stopped holding, would
 * produce an inventory that looks right and is wrong: a vtable counted as 200
 * variables, an import slot answered twice, a byte flag declared four bytes
 * wide, or a contradiction resolved by whichever evidence happened to be
 * written first.
 */
import { expect, test } from 'bun:test';
import { Option } from 'effect';
import { assembleInventory, pointerCoverage } from './inventory';
import type { GlobalReference, LibrarySymbol, PointerCandidate } from './interface';

const TEXT_LO = 0x401000;
const TEXT_HI = 0x62847d;
const isCode = (va: number): boolean => va >= TEXT_LO && va < TEXT_HI;
const sectionOf = (va: number): string | undefined => {
  if (isCode(va)) return '.text';
  if (va >= 0x635000 && va < 0x66b000) return '.rdata';
  if (va >= 0x66b000 && va < 0x7941e8) return '.data';
  return undefined;
};

const reference = (over: Partial<GlobalReference> & { address: number }): GlobalReference => ({
  site: 0x401000,
  form: 'absolute',
  width: Option.some(4),
  mnemonic: 'mov',
  opStr: 'eax, dword ptr [...]',
  containingFunction: Option.some(0x410000),
  ...over,
});

const symbol = (over: Partial<LibrarySymbol> & { address: number; name: string }): LibrarySymbol => ({
  library: 'LIBC.LIB',
  member: 'winxfltr.obj',
  route: 'placed-data-section',
  sectionIndex: 3,
  relocationOffset: Option.none(),
  fieldValue: Option.none(),
  addend: Option.none(),
  offsetReached: 0,
  size: Option.none(),
  sizeBasis: Option.none(),
  ...over,
});

const candidate = (address: number, value: number, runStart: number, runLength: number): PointerCandidate => ({
  address,
  value,
  section: sectionOf(address) ?? '?',
  targetSection: sectionOf(value) ?? '?',
  runStart,
  runLength,
});

const assemble = (over: {
  references?: ReadonlyArray<GlobalReference>;
  provenFunctions?: ReadonlySet<number>;
  librarySymbols?: ReadonlyArray<LibrarySymbol>;
  pointerCandidates?: ReadonlyArray<PointerCandidate>;
  importSlots?: ReadonlySet<number>;
}) =>
  assembleInventory({
    references: over.references ?? [],
    provenFunctions: over.provenFunctions ?? new Set(),
    librarySymbols: over.librarySymbols ?? [],
    pointerCandidates: over.pointerCandidates ?? [],
    importSlots: over.importSlots ?? new Set(),
    sectionOf,
    isCode,
  });

const at = (
  inventory: ReturnType<typeof assemble>,
  address: number,
) => inventory.entries.find((e) => e.address === address);

test('an import slot gets no globals row, and the reason is recorded', () => {
  const inventory = assemble({
    references: [reference({ address: 0x6350e0, mnemonic: 'call' })],
    importSlots: new Set([0x6350e0]),
  });
  expect(inventory.entries).toEqual([]);
  expect(inventory.importSlotsSkipped).toBe(1);
  const deferred = inventory.deferrals.find((d) => d.address === 0x6350e0);
  expect(deferred?.what).toBe('identity');
  // The reason must say WHY, not just that it was skipped: a slot can serve
  // several APIs and no single global can express that.
  expect(deferred?.reason).toContain('import_slots');
});

test('a literal in a proven function outranks every other kind of evidence', () => {
  const inventory = assemble({
    references: [reference({ address: 0x684480, containingFunction: Option.some(0x410000) })],
    provenFunctions: new Set([0x410000]),
    librarySymbols: [symbol({ address: 0x684480, name: '_thing' })],
  });
  expect(at(inventory, 0x684480)?.evidence).toBe('proven-literal');
  // Being the strongest evidence does not discard the library's name.
  expect(at(inventory, 0x684480)?.name).toEqual(Option.some('_thing'));
});

test('an unproven function makes the same literal weaker, and a library symbol beats it', () => {
  const onlyDecoded = assemble({ references: [reference({ address: 0x684480 })] });
  expect(at(onlyDecoded, 0x684480)?.evidence).toBe('decoded-literal');

  const named = assemble({ librarySymbols: [symbol({ address: 0x684480, name: '_thing' })] });
  expect(at(named, 0x684480)?.evidence).toBe('library-symbol');
});

test('a library section size is an exact size and beats the width of one access', () => {
  const inventory = assemble({
    references: [reference({ address: 0x682670, width: Option.some(4) })],
    librarySymbols: [
      symbol({
        address: 0x682670,
        name: '__XcptActTab',
        size: Option.some(120),
        sizeBasis: Option.some('library-section'),
      }),
    ],
  });
  expect(at(inventory, 0x682670)?.size).toEqual(Option.some(120));
  expect(at(inventory, 0x682670)?.sizeBasis).toEqual(Option.some('library-section'));
});

test('two widths for one address withhold the size instead of picking one', () => {
  const inventory = assemble({
    references: [
      reference({ address: 0x684480, width: Option.some(4) }),
      reference({ address: 0x684480, site: 0x401010, width: Option.some(1) }),
    ],
  });
  expect(at(inventory, 0x684480)?.size).toEqual(Option.none());
  const deferred = inventory.deferrals.find(
    (d) => d.address === 0x684480 && d.what === 'size',
  );
  expect(deferred?.reason).toContain('1 and 4');
});

test('two library names for one address withhold the name: one placement is wrong', () => {
  const inventory = assemble({
    librarySymbols: [
      symbol({ address: 0x684480, name: '_first' }),
      symbol({ address: 0x684480, name: '_second', member: 'other.obj' }),
    ],
  });
  expect(at(inventory, 0x684480)?.name).toEqual(Option.none());
  const deferred = inventory.deferrals.find(
    (d) => d.address === 0x684480 && d.what === 'name',
  );
  expect(deferred?.reason).toContain('_first and _second');
});

test('a vtable is one global, not one per slot', () => {
  const base = 0x660000;
  const slots = [0, 1, 2, 3].map((k) =>
    candidate(base + k * 4, 0x410000 + k * 0x10, base, 4),
  );
  const inventory = assemble({
    references: [reference({ address: base, form: 'immediate', width: Option.none() })],
    pointerCandidates: slots,
  });
  expect(inventory.entries.map((e) => e.address)).toEqual([base]);
  expect(at(inventory, base)?.size).toEqual(Option.some(16));
  expect(at(inventory, base)?.sizeBasis).toEqual(Option.some('pointer-run'));
  // The three interior slots are fields of that table; each says so.
  for (const k of [1, 2, 3]) {
    const deferred = inventory.deferrals.find(
      (d) => d.address === base + k * 4 && d.what === 'identity',
    );
    expect(deferred?.reason).toContain(`dword ${k} of the 4-entry table`);
  }
});

test('an isolated pointer dword is four bytes, and says its boundary is unsettled', () => {
  const inventory = assemble({ pointerCandidates: [candidate(0x684480, 0x410000, 0x684480, 1)] });
  const entry = at(inventory, 0x684480);
  expect(entry?.evidence).toBe('pointer-dword');
  expect(entry?.size).toEqual(Option.some(4));
  expect(entry?.holds).toEqual(Option.some('code-pointer'));
  expect(entry?.pointsTo).toEqual(Option.some(0x410000));
  expect(
    inventory.deferrals.find((d) => d.address === 0x684480 && d.what === 'identity')?.reason,
  ).toContain('pointer field of a larger object');
});

test('an indirect call outranks whatever the dump happened to hold there', () => {
  const inventory = assemble({
    references: [reference({ address: 0x684480, mnemonic: 'call' })],
    // At the moment of the dump this slot held a .data address, which would
    // read as a data pointer. The instruction says it is called through.
    pointerCandidates: [candidate(0x684480, 0x66c000, 0x684480, 1)],
  });
  expect(at(inventory, 0x684480)?.holds).toEqual(Option.some('code-pointer'));
  expect(at(inventory, 0x684480)?.holdsBasis).toEqual(Option.some('indirect-call'));
});

test('an x87 access says float, which no pointer-shaped value overrides', () => {
  const inventory = assemble({
    references: [
      reference({ address: 0x660590, mnemonic: 'fld', width: Option.some(8) }),
    ],
    pointerCandidates: [candidate(0x660590, 0x410000, 0x660590, 1)],
  });
  expect(at(inventory, 0x660590)?.holds).toEqual(Option.some('float'));
  expect(at(inventory, 0x660590)?.holdsBasis).toEqual(Option.some('x87-access'));
});

test('a one-byte global does not hold a pointer, whatever its four bytes spell', () => {
  const inventory = assemble({
    references: [reference({ address: 0x684480, width: Option.some(1) })],
    pointerCandidates: [candidate(0x684480, 0x410000, 0x684480, 1)],
  });
  expect(at(inventory, 0x684480)?.size).toEqual(Option.some(1));
  expect(at(inventory, 0x684480)?.holds).toEqual(Option.none());
  expect(
    inventory.deferrals.find((d) => d.address === 0x684480 && d.what === 'holds')?.reason,
  ).toContain('is a valid address');
});

test('every function that touches a global is listed once, lowest first', () => {
  const inventory = assemble({
    references: [
      reference({ address: 0x684480, site: 0x420000, containingFunction: Option.some(0x420000) }),
      reference({ address: 0x684480, site: 0x420004, containingFunction: Option.some(0x420000) }),
      reference({ address: 0x684480, site: 0x410000, containingFunction: Option.some(0x410000) }),
      reference({ address: 0x684480, site: 0x430000, containingFunction: Option.none() }),
    ],
  });
  expect(at(inventory, 0x684480)?.functions).toEqual([0x410000, 0x420000]);
  expect(at(inventory, 0x684480)?.references).toBe(4);
});

test('a pointer dword counts as attributed only to a global the program names', () => {
  const base = 0x660000;
  const slots = [0, 1].map((k) => candidate(base + k * 4, 0x410000 + k * 0x10, base, 2));
  // Named by the program: the code pushes the table's address.
  const named = assemble({
    references: [reference({ address: base, form: 'immediate', width: Option.none() })],
    pointerCandidates: slots,
  });
  expect(
    pointerCoverage({ entries: named.entries, candidates: slots, isCode }),
  ).toEqual([
    { target: 'code', enumerated: 2, attributed: 2, resolvable: 2 },
    { target: 'data', enumerated: 0, attributed: 0, resolvable: 0 },
  ]);

  // The same bytes with nothing naming them. The run's extent was inferred
  // from these very dwords, so counting them as attributed would make the
  // measure report 100% while explaining nothing.
  const unnamed = assemble({ pointerCandidates: slots });
  expect(
    pointerCoverage({ entries: unnamed.entries, candidates: slots, isCode }),
  ).toEqual([
    // Nothing NAMES them, so `attributed` is 0 -- but the run's extent is
    // settled, so the browser build has somewhere to resolve them into and
    // `resolvable` is 2. The two columns answer different questions and this
    // is the case that separates them.
    { target: 'code', enumerated: 2, attributed: 0, resolvable: 2 },
    { target: 'data', enumerated: 0, attributed: 0, resolvable: 0 },
  ]);
});

test('a pointer inside a NESTED global is still found', () => {
  // A binary search over spans sorted by `lo` is only correct while no span
  // contains another. Thirteen of the real globals nest, and the search
  // stepped past the outer one: it cost 17 of the data column, which read 93
  // where an exact test gives 110. Code was unaffected either way, which is
  // what hid it.
  const outer = 0x660000;
  const inner = outer + 0x40;
  const slot = candidate(inner + 4, 0x410000, inner, 2);
  const inventory = assemble({
    references: [
      // The outer array: named, and sized by an access width.
      reference({ address: outer, form: 'immediate', width: Option.none() }),
      reference({ address: outer, width: Option.some(0x100) }),
      // A dword read inside it with its own stated width -- the nesting.
      reference({ address: inner, width: Option.some(4) }),
    ],
    pointerCandidates: [slot],
  });
  const [code] = pointerCoverage({
    entries: inventory.entries,
    candidates: [slot],
    isCode,
  });
  expect(code?.enumerated).toBe(1);
  expect(code?.resolvable).toBe(1);
});

test('an address in no section is not a global and says so', () => {
  const inventory = assemble({ references: [reference({ address: 0x7fff0000 })] });
  expect(inventory.entries).toEqual([]);
  expect(inventory.deferrals).toEqual([
    {
      address: 0x7fff0000,
      what: 'identity',
      reason:
        '0x7fff0000 is in no section of the subject, so there is nothing there to declare',
    },
  ]);
});
