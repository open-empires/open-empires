import type { EffectGen } from 'effective-modules';
import type { DbError } from '../db/interface';
import type { NoCurrentSubject, SubjectIoError, SubjectParseError } from '../subject/interface';

/**
 * API names for the subject's import slots, read out of the libraries' own
 * relocation tables.
 *
 * WHAT IS BROKEN AND WHY GUESSING IS NOT THE ANSWER
 * -------------------------------------------------
 * The subject imports 255 slots. The KERNEL32 and USER32 descriptors have
 * OriginalFirstThunk == 0, so the loader overwrote the only copy of their
 * names in place, and the slots hold SafeDisc stubs rather than API addresses.
 * 150 slots are named from the dump's own SafeDisc cache; 105 are not. The
 * project's standing rule is never to name an API from the shape of a call,
 * because arity and argument kinds only constrain -- they do not identify.
 *
 * THE ROUTE THAT DOES NOT GUESS
 * -----------------------------
 * The image carries prebuilt CRT code from the install's own LIBC.LIB, and
 * `crt_identifications` already names 297 of those addresses by byte-matching
 * library objects against the image. A library object carries a RELOCATION
 * TABLE which names the external symbol each of its `call dword ptr [...]`
 * sites targets -- `__imp__HeapAlloc@12`. So:
 *
 *   1. the identification says where a library section sits in the image;
 *   2. the section's non-relocated bytes are confirmed against the image
 *      there, so the placement is not taken from the stored row alone;
 *   3. the relocation says which four bytes of that section hold a slot
 *      address, and what the library calls the symbol;
 *   4. the image's own bytes at that site are read back: the instruction must
 *      be one that reads through a slot, and its operand must be that slot.
 *
 * The name comes from the library's symbol table. Nothing is inferred from the
 * call's shape, and a step that cannot be confirmed produces a refusal with
 * its reason rather than a name.
 *
 * WHY THE PRODUCT IS BINDINGS AND NOT SLOT NAMES
 * ----------------------------------------------
 * An API is keyed by (slot, call site). 51 slots serve several APIs because
 * SafeDisc's dispatcher resolves on the caller's return address, and this
 * derivation demonstrates it from a second, independent direction: 11 slots
 * the dump named from a cache that agreed with itself are referenced by CRT
 * call sites that link against a DIFFERENT API. Those are not disagreements
 * about a call site -- the two sources name disjoint sets of sites -- they are
 * proof that a slot-level name drawn from a partial set of call sites is
 * incomplete.
 *
 * So a slot is given a `name` only where the whole evidence for it, from both
 * sources, names exactly one API. Everywhere else the slot stays unnamed and
 * its call sites are named individually, which is the strongest true claim
 * available.
 */

// ------------------------------------------------------------ domain values

/**
 * How the image reads the slot at a confirmed reference.
 *
 * `call-indirect` `FF 15 disp32` -- `call dword ptr [slot]`
 * `jmp-indirect`  `FF 25 disp32` -- `jmp dword ptr [slot]`, a thunk
 * `load-pointer`  `8B /r disp32` -- `mov reg, dword ptr [slot]`
 * `push-pointer`  `FF 35 disp32` -- `push dword ptr [slot]`
 *
 * The first two ARE the call site. The last two read the slot and the call
 * happens elsewhere through the register, so they name the slot without naming
 * a call site, and are recorded as references rather than as bindings.
 */
export type ReferenceForm = 'call-indirect' | 'jmp-indirect' | 'load-pointer' | 'push-pointer';

/** One reference from a library object's relocation table to an import slot,
 *  confirmed against the image's own bytes at the referencing instruction. */
export interface LibraryImportReference {
  readonly site: number;
  readonly slot: number;
  /** Undecorated, as the loader resolves it. */
  readonly api: string;
  /** The symbol exactly as the object names it: `__imp__HeapAlloc@12`. */
  readonly decorated: string;
  readonly library: string;
  readonly member: string;
  readonly sectionIndex: number;
  readonly sectionBase: number;
  readonly relocationOffset: number;
  readonly form: ReferenceForm;
}

/** A relocation, or a whole section, that produced no name, and why. */
export interface LibraryImportRefusal {
  readonly library: string;
  readonly member: string;
  readonly sectionIndex: number;
  /** Absent as -1 when the refusal is of the whole section. */
  readonly relocationOffset: number;
  readonly decorated: string;
  readonly reason: string;
}

/**
 * A slot whose two sources of evidence name different APIs.
 *
 * Reported, never reconciled. Both values and the sites each rests on are
 * carried, because picking one would destroy the finding: a slot serving
 * several APIs is what the copy protection does, and the sets of call sites
 * the two sources see are disjoint.
 */
export interface SlotApiDisagreement {
  readonly slot: number;
  readonly dll: string;
  /** What `import_slots.name` says, from the dump's SafeDisc cache. */
  readonly storedName: string;
  /** Every API the libraries' relocations name through this slot. */
  readonly libraryApis: ReadonlyArray<string>;
  /** Call sites the dump's cache recorded for this slot. */
  readonly cachedSites: number;
  /** Sites the libraries' relocations name, all confirmed in the image. */
  readonly librarySites: number;
}

export interface ImportNameReport {
  /** Identifications read, and how many were usable as a section placement. */
  readonly identifications: number;
  readonly sectionsPlaced: number;
  /** `__imp_` relocations seen in those sections. */
  readonly relocations: number;
  readonly referencesConfirmed: number;
  readonly refusals: number;
  readonly refusalReasons: ReadonlyArray<{ readonly reason: string; readonly count: number }>;
  readonly formCounts: ReadonlyArray<{ readonly form: ReferenceForm; readonly count: number }>;
  /** (slot, call site) rows written: the `call-indirect`/`jmp-indirect` ones
   *  the dump's own cache does not already answer. */
  readonly bindingsWritten: number;
  /** (slot, call site) pairs the dump's SafeDisc cache names TOO, where the
   *  library's symbol and the cached export agree. The strongest check there
   *  is: two unrelated sources naming the same call site the same thing. */
  readonly bindingsReproduced: number;
  /**
   * Pairs where the two sources name the SAME ADDRESS by different names.
   *
   * Wine's kernel32 publishes several exports at one entry point -- ordinals
   * 600 `LockResource` and 787 `SetHandleCount` are both 0x7C80CD37 -- so the
   * dump can only say which address was reached, and picks one of the names
   * at it. The library's relocation says which one the call site was linked
   * against, so this is the dump's name being disambiguated, not contradicted.
   */
  readonly bindingsAliasResolved: ReadonlyArray<{
    readonly slot: number;
    readonly callSite: number;
    readonly cachedApi: string;
    readonly libraryApi: string;
    /** Every export the guest publishes at the cached address. */
    readonly cachedTargetExports: ReadonlyArray<string>;
  }>;
  /**
   * Pairs where the cached address is NOT an entry point the library's name
   * belongs to. One of the two derivations is wrong about this call site.
   *
   * Nothing is written for these and nothing is overwritten. Both values are
   * carried, with every export name at the cached address, so the reader can
   * see that the two are genuinely different code and not two names for one.
   */
  readonly bindingDisagreements: ReadonlyArray<{
    readonly slot: number;
    readonly callSite: number;
    readonly cachedApi: string;
    readonly cachedTarget: number;
    readonly cachedTargetExports: ReadonlyArray<string>;
    readonly libraryApi: string;
  }>;
  readonly slotsReferenced: number;
  /** Slots that had no name and now have one, because all their evidence agrees. */
  readonly slotsNamed: ReadonlyArray<{ readonly slot: number; readonly name: string }>;
  /** Referenced slots still unnamed, with what blocks each one. */
  /**
   * Slots this run actually wrote a name onto.
   *
   * `slotsNamed` is the derivation's full answer -- every slot the libraries
   * name -- and it is the right input for working out what remains unnamed.
   * It is the wrong thing to report as work done: the UPDATE only writes
   * where the name is still NULL, so on every run after the first the answer
   * is the same list and nothing changes. The worker logged "10 slot(s) named
   * from library relocations" with identical slots every twenty minutes.
   */
  readonly slotsNewlyNamed: ReadonlyArray<{
    readonly slot: number;
    readonly name: string;
  }>;

  readonly slotsStillUnnamed: ReadonlyArray<{
    readonly slot: number;
    readonly apis: ReadonlyArray<string>;
    readonly reason: string;
  }>;
  /** Already-named slots this derivation reproduces exactly. The agreement
   *  check across the 150 named slots is the strongest validation available. */
  readonly slotsReproduced: ReadonlyArray<{ readonly slot: number; readonly name: string }>;
  readonly disagreements: ReadonlyArray<SlotApiDisagreement>;
}

export type ImportNamesError = DbError | NoCurrentSubject | SubjectIoError | SubjectParseError;

// -------------------------------------------------------------------- module

export interface IImportNames {
  /**
   * Name import slots and their call sites from the libraries' relocations,
   * record the evidence and every refusal, and report what agrees with the
   * names the dump already produced.
   *
   * Idempotent: it rebuilds its own rows from the libraries and the image
   * each time, and touches no row that another module owns -- an
   * already-named slot keeps the dump's name even where this derivation
   * names a second API through it, because that is a finding and not a
   * correction.
   */
  nameImportSlots(): EffectGen<ImportNameReport, ImportNamesError>;

  /** The last derivation, as recorded. Readable without re-deriving it. */
  references(): EffectGen<ReadonlyArray<LibraryImportReference>, ImportNamesError>;
}
