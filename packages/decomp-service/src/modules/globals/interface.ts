import { Option, Schema } from 'effect';
import type { EffectGen } from 'effective-modules';
import type { DbError } from '../db/interface';
import type { DisasmError } from '../disasm/interface';
import type { NoCurrentSubject, SubjectIoError, SubjectParseError } from '../subject/interface';

/**
 * The inventory of the subject's global variables.
 *
 * WHY THIS EXISTS
 * ---------------
 * The reconstructions reach global state by raw address: a line reads
 * `#define g_flag (*(Flag **)0x684480)` -- "the pointer stored at 0x684480".
 * Natively that works, and it is part of what makes the compiled bytes match
 * the shipped game, so those lines stay in the proven sources.
 *
 * For WebAssembly there is no address 0x684480. Mapping the whole data region
 * onto one extracted block works for plain data and fails for any dword in
 * that data which is itself an address, because moving the block changes what
 * the address means -- and the subject carries NO relocation table
 * (IMAGE_DIRECTORY_ENTRY_BASERELOC is rva 0, size 0), so nothing in the
 * binary says which dwords those are. 13,259 aligned dwords in the data
 * region hold an address inside the executable span and 1,875 hold one inside
 * the data region; every one of them is a value the browser build has to
 * resolve rather than copy.
 *
 * Recovering globals as declared variables is what lets the linker resolve
 * them. That needs an inventory, and this module is it.
 *
 * THE EVIDENCE MODEL, STRONGEST FIRST
 * -----------------------------------
 * Function discovery was once a single pass of hand-written rules whose
 * first-byte whitelist rejected 14% of this project's own byte-exact
 * functions. It was replaced by evidence ranked by how checkable it is. The
 * same ranking applies here:
 *
 *   `proven-literal`  a literal data address in the operands of a function
 *                     whose bytes we have REPRODUCED EXACTLY. We compiled
 *                     source that emits those bytes, so the instruction is
 *                     not a guess about where a boundary falls -- it is a
 *                     fact about verified bytes. The instruction also states
 *                     the ACCESS WIDTH, and sometimes the kind: `call dword
 *                     ptr [X]` says X holds a code pointer, `fld qword ptr
 *                     [X]` says X holds a double.
 *
 *   `library-symbol`  a `Dir32` relocation in a CRT library object whose
 *                     bytes are confirmed in the image. The object's own
 *                     relocation table NAMES the data each field refers to,
 *                     and the library's own symbol table states its size.
 *                     This is where `_XcptActTab` at 0x682670 and
 *                     `__error_mode` at 0x792B2C come from.
 *
 *   `decoded-literal` the same kind of literal, in a function we have NOT
 *                     proven. It depends on that decode being right.
 *
 *   `pointer-dword`   an aligned dword in the data region whose value is a
 *                     valid code or data address. The weakest, because an
 *                     integer can look like an address -- 0x6ACFC0 is both a
 *                     plausible byte count and an address inside `.data`.
 *
 * NOTHING IS DISCARDED. An address whose size, name or contents cannot be
 * determined is recorded with the reason, exactly as function discovery now
 * defers rather than rejects. A rule that turns out to be wrong can then be
 * revisited against what it excluded, instead of costing globals nobody can
 * see.
 *
 * WHAT THIS MODULE DOES NOT OWN
 * -----------------------------
 * Import slots. 255 addresses in `.rdata` are the import address table, and
 * `import_slots` / `import_slot_apis` already answer what each one is. They
 * are referenced from code exactly as a global is, so they would otherwise be
 * counted twice -- and the answer for them is genuinely different: 51 slots
 * serve SEVERAL APIs because SafeDisc's dispatcher resolves on the caller's
 * return address, so "one address, one thing" is false there. A slot gets no
 * `globals` row; its references are still recorded, and the address is
 * deferred with that reason, so the overlap is visible rather than silent.
 */

export class GlobalsFailed extends Schema.TaggedError<GlobalsFailed>()('GlobalsFailed', {
  reason: Schema.String,
}) {}

export type GlobalsError =
  | DbError
  | DisasmError
  | SubjectIoError
  | SubjectParseError
  | NoCurrentSubject
  | GlobalsFailed;

// ------------------------------------------------------------ domain values

/** How an instruction names a data address.
 *
 *  `absolute`  `[0x684480]` on its own -- a scalar access of exactly the
 *              instruction's own width at that address.
 *  `indexed`   `[eax + 0x684480]` or `[eax*4 + 0x684480]` -- the address is
 *              the BASE of an array or a struct, and the extent is not stated.
 *  `immediate` the address as an immediate operand, `push 0x684480`. The
 *              address itself is taken, so the global is at least as big as
 *              whatever the callee reads -- which this says nothing about.
 */
export type ReferenceForm = 'absolute' | 'indexed' | 'immediate';

/** One confirmed reference from an instruction to a data address. */
export interface GlobalReference {
  /** Address of the referencing instruction. */
  readonly site: number;
  readonly address: number;
  readonly form: ReferenceForm;
  /** Bytes the instruction accesses, from its own operand size. None for an
   *  immediate, which carries the address and reads nothing. */
  readonly width: Option.Option<number>;
  readonly mnemonic: string;
  /** The operand text, so the claim is checkable against the disassembly. */
  readonly opStr: string;
  /** The inventory function the site belongs to. None when the site is in a
   *  stretch of the executable span the inventory attributes to no function:
   *  such a reference is still a fact about bytes, but nothing ties it to a
   *  function that could be proven. */
  readonly containingFunction: Option.Option<number>;
}

/** How strong the evidence for an address is. Ordered, strongest first. */
export type Evidence = 'proven-literal' | 'library-symbol' | 'decoded-literal' | 'pointer-dword';

export const EVIDENCE_ORDER: ReadonlyArray<Evidence> = [
  'proven-literal',
  'library-symbol',
  'decoded-literal',
  'pointer-dword',
];

/**
 * How a size was arrived at.
 *
 * `library-section`      the symbol is the only one in a library section
 *                        whose bytes are confirmed in the image, so the
 *                        section's size IS the symbol's size.
 * `library-next-symbol`  bounded by the next symbol in that section. An UPPER
 *                        BOUND: the gap may include alignment padding.
 * `pointer-run`          the address begins a run of consecutive aligned
 *                        pointer dwords -- a vtable, a jump table, a string
 *                        table -- and the run's length is the array's extent.
 * `access-width`         every absolute access to the address agrees on one
 *                        width, so it is a scalar of that width.
 */
export type SizeBasis =
  | 'library-section'
  | 'library-next-symbol'
  | 'pointer-run'
  | 'access-width';

/** What the evidence says the global's VALUE is. Absent means nothing says --
 *  which is not the same as "an integer", and is recorded as a deferral. */
export type Holds = 'code-pointer' | 'data-pointer' | 'float';

/**
 * `indirect-call`  an instruction calls through the address, so it holds a
 *                  code pointer whatever the bytes there currently say.
 * `indirect-jump`  likewise, through a `jmp`.
 * `x87-access`     an x87 instruction loads or stores it as a float. `fild`
 *                  and `fist` are excluded: those convert an INTEGER.
 * `stored-address` the dword at the address is a valid code or data address.
 *                  Value-level, so it is evidence about this image's bytes
 *                  and not about the declaration.
 */
export type HoldsBasis = 'indirect-call' | 'indirect-jump' | 'x87-access' | 'stored-address';

/** One global, as the inventory answers it. */
export interface GlobalEntry {
  readonly address: number;
  /** The section it sits in, from the subject's own section table. */
  readonly section: string;
  readonly evidence: Evidence;
  readonly size: Option.Option<number>;
  readonly sizeBasis: Option.Option<SizeBasis>;
  readonly name: Option.Option<string>;
  /** The library member whose relocation named it. */
  readonly nameFrom: Option.Option<string>;
  readonly holds: Option.Option<Holds>;
  readonly holdsBasis: Option.Option<HoldsBasis>;
  /** The address its value refers to, when it holds one. */
  readonly pointsTo: Option.Option<number>;
  /** Inventory functions with at least one reference to it. */
  readonly functions: ReadonlyArray<number>;
  readonly references: number;
}

/** Something about an address the evidence does not settle. A gap that is
 *  written down can be closed; one that is not, cannot. */
export type Deferred = 'identity' | 'size' | 'name' | 'holds';

export interface Deferral {
  readonly address: number;
  readonly what: Deferred;
  readonly reason: string;
}

/** A data symbol a library's own relocation table names in the image. */
export interface LibrarySymbol {
  readonly address: number;
  /** As the library's symbol table spells it, undecorated by nothing: a CRT
   *  global is `__pctype` in the object and `_pctype` in C, and the stored
   *  form is the one the evidence actually carries. */
  readonly name: string;
  readonly library: string;
  readonly member: string;
  /** `external-relocation`: the object referred to a symbol it does not
   *  define, and the patched field in the image gives its address.
   *  `placed-data-section`: the object's own data section was located in the
   *  image, so every symbol it defines has an address AND a size. */
  readonly route: 'external-relocation' | 'placed-data-section';
  readonly sectionIndex: number;
  readonly relocationOffset: Option.Option<number>;
  /** The dword the relocation names in the image, and the addend the object
   *  had in that field. The symbol's address is the difference -- which is
   *  what makes `_XcptActTab + 8` name `_XcptActTab` rather than a second
   *  global eight bytes along. */
  readonly fieldValue: Option.Option<number>;
  readonly addend: Option.Option<number>;
  /** The byte of the symbol the reference reaches. Non-zero is a lower bound
   *  on the symbol's size that is independent of the library's own table. */
  readonly offsetReached: number;
  readonly size: Option.Option<number>;
  readonly sizeBasis: Option.Option<SizeBasis>;
}

/** An aligned dword in the data region holding a valid address. */
export interface PointerCandidate {
  readonly address: number;
  readonly value: number;
  readonly section: string;
  readonly targetSection: string;
  /** First address of the maximal run of consecutive aligned pointer dwords
   *  this one belongs to, and that run's length. A run whose first address is
   *  referenced from code is a table the code NAMES; an isolated dword in
   *  `.rsrc` is most likely a resource offset that happens to look like an
   *  address. */
  readonly runStart: number;
  readonly runLength: number;
}

// ------------------------------------------------------------------- report

export interface GlobalsReport {
  readonly subjectSha256: string;
  /** Sections the subject's own flags mark as not executable, which is what
   *  the data region IS. Written out because every count below is relative to
   *  it. */
  readonly dataRegion: ReadonlyArray<{
    readonly name: string;
    readonly lo: number;
    readonly hi: number;
  }>;
  readonly references: number;
  /** References whose operand literal is NOT a 32-bit field of the
   *  instruction's own bytes -- the decoder computed it. None of these
   *  becomes evidence. */
  readonly unconfirmedReferences: number;
  readonly globals: number;
  readonly byEvidence: ReadonlyArray<{ readonly evidence: Evidence; readonly globals: number }>;
  readonly sized: number;
  readonly bySizeBasis: ReadonlyArray<{ readonly basis: SizeBasis; readonly globals: number }>;
  readonly named: number;
  readonly holdsKnown: ReadonlyArray<{ readonly holds: Holds; readonly globals: number }>;
  /** Addresses that are declared import slots, so this module answers
   *  nothing for them. */
  readonly importSlotsSkipped: number;
  readonly deferrals: ReadonlyArray<{ readonly what: Deferred; readonly addresses: number }>;
  /** The question the browser build actually asks: of the dwords in the data
   *  region that hold an address, how many does the inventory account for?
   *
   *  `enumerated` is every one, each with the address it refers to -- what a
   *  relocation table would have said. `attributed` is those that fall inside
   *  a global whose extent the evidence settles, so the build knows WHICH
   *  declared variable holds them and at what offset. The two are reported
   *  separately because they are different claims and the second is much the
   *  smaller. */
  readonly pointers: ReadonlyArray<{
    readonly target: 'code' | 'data';
    readonly enumerated: number;
    readonly attributed: number;
  }>;
  readonly librarySymbols: number;
  readonly libraryRefusals: ReadonlyArray<{ readonly reason: string; readonly count: number }>;
}

// -------------------------------------------------------------------- module

/** The globals surface as scalars, for anything that only needs the counts. */
export interface GlobalsSummary {
  readonly globals: number;
  readonly references: number;
  readonly sized: number;
  readonly named: number;
  readonly holdsKnown: number;
  /** Aligned dwords in the data region that hold an address inside the
   *  executable span, and how many fall inside a global whose extent is
   *  settled. This is the relocation table the binary does not carry. */
  readonly pointers: ReadonlyArray<{
    readonly target: string;
    readonly enumerated: number;
    readonly attributed: number;
  }>;
  readonly byEvidence: ReadonlyArray<{ readonly evidence: string; readonly globals: number }>;
}

export interface IGlobals {
  /**
   * Re-derive the whole inventory from the subject's bytes, the proven set
   * and the CRT libraries, and record it.
   *
   * Runs on a timer, not by hand, because the inventory CONVERGES: every new
   * proof turns the literals in one more function from `decoded-literal` into
   * `proven-literal`, and every newly measured function turns an unattributed
   * reference site into one with a containing function. An inventory produced
   * once would be a snapshot of a proven set that no longer exists -- which
   * is how this project shipped 6,953 blocks of which 1,450 were still proved
   * against the current compiler.
   *
   * Replaces the whole derivation for the subject in one transaction, so a
   * global this run no longer evidences is GONE rather than left looking
   * current. That retracts nothing proved: these are derived facts about the
   * subject's bytes and no verdict rests on them.
   */
  rebuild(): EffectGen<GlobalsReport, GlobalsError>;

  /** What is recorded for the subject in force, without re-deriving it.
   *  Absent when `rebuild` has never run against it. */
  recorded(): EffectGen<Option.Option<GlobalsReport>, GlobalsError>;

  /**
   * The same surface as `recorded()`, as scalars, by SQL alone.
   *
   * `recorded()` assembles the full report: every entry, every deferral and
   * every pointer candidate -- tens of thousands of rows. The dashboard polls
   * every five seconds and needs four numbers, so calling it there would
   * rebuild the whole report twenty times a minute. It also reads zero while
   * a rebuild is between its DELETE and its INSERT, which makes the figure
   * flicker to nothing for no reason the reader can see.
   */
  summary(): EffectGen<GlobalsSummary, GlobalsError>;

  /** One global and every reference to it. Absent when the address carries no
   *  evidence -- ask `deferrals` for whether that is a refusal or a gap. */
  at(address: number): EffectGen<Option.Option<GlobalEntry>, GlobalsError>;

  /** Every global in the inventory, lowest address first. */
  entries(): EffectGen<ReadonlyArray<GlobalEntry>, GlobalsError>;

  /** Everything the derivation could not determine, with the reason. */
  deferrals(): EffectGen<ReadonlyArray<Deferral>, GlobalsError>;
}
