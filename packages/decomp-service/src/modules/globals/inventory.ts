/**
 * One answer per address, from all four kinds of evidence.
 *
 * This is where the inventory is DECIDED: which addresses are globals, how
 * big each one is, what it is called, and whether it holds an address. The
 * evidence itself is recorded separately and in full, so every answer here is
 * re-derivable from rows a reader can inspect -- and every question the
 * evidence does not settle comes out as a deferral naming the reason, rather
 * than as a plausible default.
 *
 * TWO RULES THIS FILE EXISTS TO ENFORCE
 * -------------------------------------
 * A CONFLICT IS NOT RESOLVED BY A VOTE. Seven addresses are accessed as a
 * dword by one instruction and as a byte by another; two addresses are named
 * differently by two library members. Picking the commoner answer would
 * destroy the finding -- a byte read at the start of a dword is a flag inside
 * a word, and that is worth knowing. Both are kept, the answer is withheld,
 * and the reason says what disagreed.
 *
 * AN IMPORT SLOT IS NOT A GLOBAL. The import address table sits in `.rdata`
 * and is read by exactly the instructions a global is read by. `import_slots`
 * already answers those 255 addresses, and the answer is a different SHAPE:
 * 51 of them serve several APIs because SafeDisc's dispatcher resolves on the
 * caller's return address. Giving them a `globals` row would both double-count
 * them and assert the one thing known to be false about them.
 */
import { Option } from 'effect';
import { readsAsFloat } from './code-references';
import type {
  Deferral,
  Evidence,
  GlobalEntry,
  GlobalReference,
  Holds,
  HoldsBasis,
  LibrarySymbol,
  PointerCandidate,
  SizeBasis,
} from './interface';

const hex = (value: number): string => `0x${(value >>> 0).toString(16)}`;

export interface InventoryInput {
  readonly references: ReadonlyArray<GlobalReference>;
  /** Functions proved byte-exact under the configuration in force. A
   *  reference from one of these is a fact about verified bytes. */
  readonly provenFunctions: ReadonlySet<number>;
  readonly librarySymbols: ReadonlyArray<LibrarySymbol>;
  readonly pointerCandidates: ReadonlyArray<PointerCandidate>;
  /** Addresses the subject's import descriptors declare as slots. */
  readonly importSlots: ReadonlySet<number>;
  readonly sectionOf: (va: number) => string | undefined;
  readonly isCode: (va: number) => boolean;
}

export interface Inventory {
  readonly entries: ReadonlyArray<GlobalEntry>;
  readonly deferrals: ReadonlyArray<Deferral>;
  readonly importSlotsSkipped: number;
}

interface Accumulated {
  readonly address: number;
  readonly references: GlobalReference[];
  readonly symbols: LibrarySymbol[];
  readonly candidates: PointerCandidate[];
}

export const assembleInventory = (input: InventoryInput): Inventory => {
  const byAddress = new Map<number, Accumulated>();
  const at = (address: number): Accumulated => {
    const existing = byAddress.get(address);
    if (existing !== undefined) return existing;
    const fresh: Accumulated = { address, references: [], symbols: [], candidates: [] };
    byAddress.set(address, fresh);
    return fresh;
  };
  for (const reference of input.references) at(reference.address).references.push(reference);
  for (const symbol of input.librarySymbols) at(symbol.address).symbols.push(symbol);
  for (const candidate of input.pointerCandidates) at(candidate.address).candidates.push(candidate);

  // A pointer dword is a DECLARATION only where its run begins.
  //
  // A vtable is a run of consecutive aligned dwords pointing into code, and
  // its interior slots are fields of that one table -- not 11,402 separate
  // variables. Filing them as globals would make the inventory's own count
  // meaningless and assert a declaration boundary at every four bytes, which
  // is the opposite of what a vtable is. They keep their row in
  // `global_pointer_candidates`, where the browser build reads them, and get
  // an `identity` deferral naming the table they belong to.
  const runStarts = new Map<number, number>();
  for (const candidate of input.pointerCandidates) {
    runStarts.set(candidate.runStart, candidate.runLength);
  }
  const interiorOfRun = new Map<number, PointerCandidate>();
  for (const candidate of input.pointerCandidates) {
    if (candidate.address !== candidate.runStart) interiorOfRun.set(candidate.address, candidate);
  }

  const entries: GlobalEntry[] = [];
  const deferrals: Deferral[] = [];
  let importSlotsSkipped = 0;
  const defer = (address: number, what: Deferral['what'], reason: string): void => {
    deferrals.push({ address, what, reason });
  };

  for (const accumulated of [...byAddress.values()].sort((a, b) => a.address - b.address)) {
    const { address } = accumulated;

    if (input.importSlots.has(address)) {
      importSlotsSkipped += 1;
      defer(
        address,
        'identity',
        `${hex(address)} is a declared import slot, so import_slots answers it and this ` +
          'inventory does not: one slot can serve several APIs, which no single global can',
      );
      continue;
    }

    const section = input.sectionOf(address);
    if (section === undefined) {
      defer(
        address,
        'identity',
        `${hex(address)} is in no section of the subject, so there is nothing there to declare`,
      );
      continue;
    }

    const evidence = strongestEvidence(accumulated, input.provenFunctions);
    const interior = interiorOfRun.get(address);
    if (evidence === 'pointer-dword' && interior !== undefined) {
      defer(
        address,
        'identity',
        `it is dword ${(address - interior.runStart) / 4} of the ${interior.runLength}-entry ` +
          `table at ${hex(interior.runStart)}, so it is a field of that global rather than a ` +
          'declaration of its own -- global_pointer_candidates still carries it, with the ' +
          'address it holds',
      );
      continue;
    }
    const sized = resolveSize(accumulated, runStarts, defer);
    const named = resolveName(accumulated, defer);
    const holding = resolveHolds({
      accumulated,
      size: sized.size,
      isCode: input.isCode,
      defer,
    });

    const functions = [
      ...new Set(
        accumulated.references.flatMap((r) =>
          Option.isSome(r.containingFunction) ? [r.containingFunction.value] : [],
        ),
      ),
    ].sort((a, b) => a - b);

    entries.push({
      address,
      section,
      evidence,
      size: sized.size,
      sizeBasis: sized.basis,
      name: named.name,
      nameFrom: named.from,
      holds: holding.holds,
      holdsBasis: holding.basis,
      pointsTo: holding.pointsTo,
      functions,
      references: accumulated.references.length,
    });
  }

  return { entries, deferrals, importSlotsSkipped };
};

/**
 * The strongest thing known about this address.
 *
 * A reference from a currently-proven function outranks a library symbol,
 * because it is a fact about bytes this project has reproduced, where the
 * library route rests on a byte-match that is strong but is still a match.
 * "Currently" is the operative word: whether a function is proven is read
 * from the `proven` view, which only counts verdicts made under the
 * configuration in force, so this ranking moves as the compiler changes
 * rather than being frozen when a row was written.
 */
const strongestEvidence = (
  accumulated: Accumulated,
  proven: ReadonlySet<number>,
): Evidence => {
  const fromProven = accumulated.references.some(
    (r) => Option.isSome(r.containingFunction) && proven.has(r.containingFunction.value),
  );
  if (fromProven) return 'proven-literal';
  if (accumulated.symbols.length > 0) return 'library-symbol';
  if (accumulated.references.length > 0) return 'decoded-literal';
  return 'pointer-dword';
};

interface ResolvedSize {
  readonly size: Option.Option<number>;
  readonly basis: Option.Option<SizeBasis>;
}

/**
 * How big it is.
 *
 * The library's own table first: it states the size of the declaration, where
 * an instruction states only the size of one access. Then the pointer run,
 * because an address that begins a table of pointers is the whole table, not
 * its first element. Then the access width, which is a real size only for a
 * scalar.
 *
 * An `indexed` or `immediate`-only address is deliberately left unsized: the
 * code took its address and the extent is decided by whatever reads it, which
 * nothing here observes.
 */
const resolveSize = (
  accumulated: Accumulated,
  runStarts: ReadonlyMap<number, number>,
  defer: (address: number, what: Deferral['what'], reason: string) => void,
): ResolvedSize => {
  const { address } = accumulated;
  const stated = accumulated.symbols.filter((s) => Option.isSome(s.size));
  if (stated.length > 0) {
    const distinct = new Set(stated.map((s) => Option.getOrThrow(s.size)));
    if (distinct.size > 1) {
      defer(
        address,
        'size',
        `the libraries state ${[...distinct].sort((a, b) => a - b).join(' and ')} bytes for ` +
          `${stated.map((s) => s.name).join(' / ')}, so they do not agree on its extent`,
      );
    } else {
      // Prefer the exact basis when both routes reached it.
      const exact = stated.find((s) => Option.getOrNull(s.sizeBasis) === 'library-section');
      const chosen = exact ?? stated[0]!;
      return { size: chosen.size, basis: chosen.sizeBasis };
    }
  }

  // A run of two or more is a TABLE, and a table's extent is the whole run:
  // the first element's own four bytes are not its size.
  const run = runStarts.get(address);
  if (run !== undefined && run >= 2) {
    return { size: Option.some(run * 4), basis: Option.some('pointer-run') };
  }

  const widths = new Set(
    accumulated.references.flatMap((r) =>
      r.form === 'absolute' && Option.isSome(r.width) ? [r.width.value] : [],
    ),
  );
  if (widths.size === 1) {
    return { size: Option.some([...widths][0]!), basis: Option.some('access-width') };
  }
  if (widths.size > 1) {
    defer(
      address,
      'size',
      `it is accessed as ${[...widths].sort((a, b) => a - b).join(' and ')} bytes by different ` +
        'instructions, so no one width is its size -- a narrower access inside a wider ' +
        'variable is a field, and which it is cannot be read off the accesses',
    );
    return { size: Option.none(), basis: Option.none() };
  }

  // An isolated pointer dword occupies the four bytes that hold the address,
  // and the evidence says nothing beyond them. Recorded as four with that
  // basis, and the uncertainty about where the DECLARATION ends is deferred
  // under `identity` rather than smuggled into a larger size.
  if (run === 1) {
    defer(
      address,
      'identity',
      'it holds an address and nothing reads it, so four bytes is all the evidence covers: ' +
        'this may be a pointer variable of its own or a pointer field of a larger object ' +
        'nothing here identifies',
    );
    return { size: Option.some(4), basis: Option.some('pointer-run') };
  }

  const forms = new Set(accumulated.references.map((r) => r.form));
  defer(
    address,
    'size',
    accumulated.references.length === 0
      ? 'nothing reads it and its bytes are not an address, so no evidence states its extent'
      : `every reference is ${[...forms].sort().join(' / ')}, which takes its address without ` +
          'stating how much of it is read',
  );
  return { size: Option.none(), basis: Option.none() };
};

interface ResolvedName {
  readonly name: Option.Option<string>;
  readonly from: Option.Option<string>;
}

/**
 * What it is called.
 *
 * Only the libraries name anything: a name read from a library's symbol table
 * is the library's own statement, and nothing else available states a name at
 * all. Two members naming one address differently is a finding -- the two are
 * then about different code and one placement is wrong -- so the name is
 * withheld and both are kept in the evidence rows.
 */
const resolveName = (
  accumulated: Accumulated,
  defer: (address: number, what: Deferral['what'], reason: string) => void,
): ResolvedName => {
  if (accumulated.symbols.length === 0) {
    defer(
      accumulated.address,
      'name',
      'no library relocation names it, and the compiler discarded every name the game\'s own ' +
        'programmers wrote',
    );
    return { name: Option.none(), from: Option.none() };
  }
  const distinct = new Set(accumulated.symbols.map((s) => s.name));
  if (distinct.size > 1) {
    defer(
      accumulated.address,
      'name',
      `${[...distinct].sort().join(' and ')} are both placed here, so one of the two ` +
        'placements is wrong and neither name can be trusted',
    );
    return { name: Option.none(), from: Option.none() };
  }
  const chosen = accumulated.symbols[0]!;
  return { name: Option.some(chosen.name), from: Option.some(chosen.member) };
};

interface ResolvedHolds {
  readonly holds: Option.Option<Holds>;
  readonly basis: Option.Option<HoldsBasis>;
  readonly pointsTo: Option.Option<number>;
}

/**
 * Whether its value is an address, and whose.
 *
 * The instruction outranks the bytes. `call dword ptr [X]` says X holds a
 * code pointer whatever X currently contains -- the dump was taken at one
 * moment and a function pointer may well have been null then. The bytes are
 * used only where no instruction says: a dword whose value is a valid address
 * is evidence about THIS IMAGE, which is exactly what the browser build needs
 * to resolve, and is also the weakest thing here.
 */
const resolveHolds = (input: {
  readonly accumulated: Accumulated;
  readonly size: Option.Option<number>;
  readonly isCode: (va: number) => boolean;
  readonly defer: (address: number, what: Deferral['what'], reason: string) => void;
}): ResolvedHolds => {
  const { accumulated, size, isCode, defer } = input;
  const dereferenced = accumulated.references.filter((r) => r.form === 'absolute');
  if (dereferenced.some((r) => r.mnemonic === 'call')) {
    return {
      holds: Option.some('code-pointer'),
      basis: Option.some('indirect-call'),
      pointsTo: Option.none(),
    };
  }
  if (dereferenced.some((r) => r.mnemonic === 'jmp')) {
    return {
      holds: Option.some('code-pointer'),
      basis: Option.some('indirect-jump'),
      pointsTo: Option.none(),
    };
  }
  if (dereferenced.some((r) => readsAsFloat(r.mnemonic))) {
    return {
      holds: Option.some('float'),
      basis: Option.some('x87-access'),
      pointsTo: Option.none(),
    };
  }
  const candidate = accumulated.candidates[0];
  if (candidate !== undefined) {
    // A global the evidence sizes below four bytes cannot hold an address,
    // whatever the four bytes starting there happen to spell.
    if (Option.isSome(size) && size.value < 4) {
      defer(
        accumulated.address,
        'holds',
        `the four bytes here spell ${hex(candidate.value)}, which is a valid address, but the ` +
          `evidence sizes this global at ${size.value} byte(s), so the dword is not its value`,
      );
      return { holds: Option.none(), basis: Option.none(), pointsTo: Option.none() };
    }
    return {
      holds: Option.some(isCode(candidate.value) ? 'code-pointer' : 'data-pointer'),
      basis: Option.some('stored-address'),
      pointsTo: Option.some(candidate.value),
    };
  }
  defer(
    accumulated.address,
    'holds',
    'no instruction dereferences it and its own bytes are not a valid address, so nothing ' +
      'says whether its value is a pointer, an integer or a float',
  );
  return { holds: Option.none(), basis: Option.none(), pointsTo: Option.none() };
};

/**
 * Pointer dwords the inventory accounts for.
 *
 * `enumerated` is every candidate: the address of the dword and the address
 * it holds, which is what a relocation table would have stated and what the
 * browser build must resolve one by one.
 *
 * `attributed` is the subset falling inside a global the PROGRAM names -- one
 * evidenced by a literal in its own code or by a library's symbol table, and
 * sized. A global evidenced only by the pointer values is excluded on
 * purpose: its extent was inferred from the very dwords being counted, so
 * including it would make this number measure nothing and report 100%.
 *
 * `resolvable` is the subset falling inside ANY global with a settled extent,
 * pointer-derived ones included, and it is a different question that was
 * being answered nowhere.
 *
 * The distinction matters because the two were being conflated. `attributed`
 * reads 110 of 1,875 for data, and that was reported -- including by me, to
 * the project's owner -- as the browser build's worst-covered dependency.
 * It is not: the build resolves an address through `GPTR(address)` and needs
 * an extent to resolve INTO, which is `resolvable`, and that is 1,874 of
 * 1,875 for data and 13,259 of 13,259 for code. The single exception is
 * 0x682090, a 4-byte CRT pointer in the hole between `__pctype` and
 * `__ctype` that no archive member names.
 *
 * So `attributed` measures how much of the data region the CODE names, which
 * is a real question about how well understood the data is, and not a
 * blocker for step 4. Both are reported so neither can be read as the other.
 */
export const pointerCoverage = (input: {
  readonly entries: ReadonlyArray<GlobalEntry>;
  readonly candidates: ReadonlyArray<PointerCandidate>;
  readonly isCode: (va: number) => boolean;
}): ReadonlyArray<{
  readonly target: 'code' | 'data';
  readonly enumerated: number;
  readonly attributed: number;
  readonly resolvable: number;
}> => {
  /**
   * Disjoint spans, because the binary search below requires it.
   *
   * It did not have it. Thirteen of these globals NEST -- a dword read with a
   * stated width inside a library array or a pointer table the code also
   * names -- and a binary search over intervals sorted by `lo` is only
   * correct while none contains another. Sorted spans [10,100), [20,30),
   * [200,300) and a query for 50 lands on [20,30), steps right past
   * [10,100), and answers false.
   *
   * It cost 17 of the data column, which read 93 where an exact test gives
   * 110. Code was unaffected at 11,403 either way, which is what hid it:
   * only one of the two columns was wrong, so nothing looked inconsistent.
   */
  const disjoint = (
    ranges: ReadonlyArray<{ lo: number; hi: number }>,
  ): ReadonlyArray<{ lo: number; hi: number }> => {
    const sorted = [...ranges].sort((a, b) => a.lo - b.lo || a.hi - b.hi);
    const out: Array<{ lo: number; hi: number }> = [];
    for (const r of sorted) {
      const last = out[out.length - 1];
      if (last !== undefined && r.lo <= last.hi) last.hi = Math.max(last.hi, r.hi);
      else out.push({ lo: r.lo, hi: r.hi });
    }
    return out;
  };
  const containing = (
    spans: ReadonlyArray<{ lo: number; hi: number }>,
  ): ((va: number) => boolean) => (va: number): boolean => {
    let lo = 0;
    let hi = spans.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const span = spans[mid]!;
      if (va < span.lo) hi = mid - 1;
      else if (va >= span.hi) lo = mid + 1;
      else return true;
    }
    return false;
  };

  const sized = input.entries.flatMap((e) =>
    Option.isSome(e.size) ? [{ lo: e.address, hi: e.address + e.size.value, ev: e.evidence }] : [],
  );
  const named = containing(disjoint(sized.filter((s) => s.ev !== 'pointer-dword')));
  const anyExtent = containing(disjoint(sized));

  const tally = {
    code: { enumerated: 0, attributed: 0, resolvable: 0 },
    data: { enumerated: 0, attributed: 0, resolvable: 0 },
  };
  for (const candidate of input.candidates) {
    const bucket = tally[input.isCode(candidate.value) ? 'code' : 'data'];
    bucket.enumerated += 1;
    if (named(candidate.address)) bucket.attributed += 1;
    if (anyExtent(candidate.address)) bucket.resolvable += 1;
  }
  return [
    { target: 'code' as const, ...tally.code },
    { target: 'data' as const, ...tally.data },
  ];
};
