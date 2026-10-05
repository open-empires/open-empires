import { Data, Option, Schema } from 'effect';
import type { EffectGen } from 'effective-modules';
import type { DbError } from '../db/interface';

// ----------------------------------------------------------------- failures

/** An input artifact could not be opened or mapped. */
export class SubjectIoError extends Schema.TaggedError<SubjectIoError>()('SubjectIoError', {
  path: Schema.String,
  reason: Schema.String,
}) {}

/** Bytes that had to be a given structure are not that structure. */
export class SubjectParseError extends Schema.TaggedError<SubjectParseError>()(
  'SubjectParseError',
  { what: Schema.String, reason: Schema.String },
) {}

/**
 * A page needed to answer the question is not resident in the RAM image.
 *
 * This is raised only where absence is a failure. Where absence is an answer
 * -- "this import was never called, so the dump records no name for it" -- it
 * is reported as absence instead, never as zeros: `00 00` is a valid x86
 * instruction, and unreadable bytes silently became 64 phantom code blocks
 * once already.
 */
export class GuestReadError extends Schema.TaggedError<GuestReadError>()('GuestReadError', {
  va: Schema.Number,
  reason: Schema.String,
}) {}

/**
 * Nothing is currently configured as the subject, so there is no span to
 * measure against and no set of proofs in force.
 *
 * Raised by the whole-corpus audits, which only ever measure the configuration
 * CURRENTLY in force: an audit that fell back to "whatever file is on disk"
 * would report a number about a subject nobody had chosen.
 */
export class NoCurrentSubject extends Schema.TaggedError<NoCurrentSubject>()(
  'NoCurrentSubject',
  { reason: Schema.String },
) {}

/** The guest's own structures do not say what they must say to be trusted. */
export class GuestMapError extends Schema.TaggedError<GuestMapError>()('GuestMapError', {
  reason: Schema.String,
}) {}

export type SubjectError = SubjectIoError | SubjectParseError | GuestReadError | GuestMapError;

// ------------------------------------------------------------ domain values

/** 32-bit paging, with or without PAE. Pinned by evidence, never assumed. */
export type PagingMode = 'legacy' | 'pae';

export interface Section {
  readonly name: string;
  readonly va: number;
  readonly virtualSize: number;
  readonly rawOffset: number;
  readonly rawSize: number;
  /**
   * The section's own flags. Carried so "is this section code" is read from
   * the bytes rather than from a list of section names written down
   * somewhere: `THIS_COD` is executable and is not called `.text`, and the
   * globals inventory must not treat a SafeDisc code section as data.
   */
  readonly characteristics: number;
}

/** IMAGE_SCN_MEM_EXECUTE. */
export const SECTION_EXECUTABLE = 0x20000000;

/**
 * One `@comp.id` record of the subject's Rich header: a tool that produced it,
 * and how many object files it contributed.
 */
export interface CompIdRecord {
  /** Position in the Rich header, so the record is traceable to its bytes. */
  readonly index: number;
  /** The raw dword, from which prodId and build are the two halves. */
  readonly compId: number;
  readonly prodId: number;
  readonly build: number;
  readonly objects: number;
}

export interface RichHeader {
  readonly dansOffset: number;
  readonly richOffset: number;
  readonly xorKey: number;
  readonly records: ReadonlyArray<CompIdRecord>;
}

export interface Subject {
  readonly sha256: string;
  readonly path: string;
  readonly size: number;
  readonly imageBase: number;
  /** The .text section's bounds, from the section header. */
  readonly textLo: number;
  readonly textHi: number;
  readonly sections: ReadonlyArray<Section>;
  readonly rich: RichHeader;
}

export interface GuestModuleTotals {
  readonly pagingMode: PagingMode;
  readonly modules: number;
  readonly exports: number;
  readonly named: number;
  readonly ordinalOnly: number;
  readonly forwarders: number;
  /** Named, not counted: a module with no export directory is a fact to read. */
  readonly withoutExportDirectory: ReadonlyArray<{
    readonly base: number;
    readonly name: string;
    readonly reason: string;
  }>;
}

/**
 * How a slot was answered. Every slot gets exactly one of these and no other
 * outcome is possible.
 *
 * `export-exact`        the slot, or every call site through it, reaches one
 *                       export entry point.
 * `multiple-apis`       the slot is a SafeDisc stub several different APIs are
 *                       reached through. The slot has no single name; that is
 *                       an answer, not a gap.
 * `no-cached-call-site` the slot is a SafeDisc stub whose cache is empty: the
 *                       import was never called before the snapshot, so the
 *                       dump records nothing about what it resolves to.
 * `not-an-export`       the slot holds an address inside a mapped module that
 *                       is not an export entry point. Reported with its
 *                       containing export and offset, never rounded to a name.
 */
export type SlotResolutionKey =
  | 'export-exact'
  | 'multiple-apis'
  | 'no-cached-call-site'
  | 'not-an-export';

/**
 * What independently corroborates a (slot, call site) binding.
 *
 * `call-operand-verified`          the six-byte `call dword ptr [disp32]` at
 *                                  the call site names this very slot.
 * `record-entry`                   the call site lands inside earlier
 *                                  instructions (a two-byte `call reg`), so
 *                                  there is no operand to read back.
 * `call-operand-names-another-slot` there is an operand and it names a
 *                                  different slot. A disagreement, reported.
 */
export type BindingEvidence =
  | 'call-operand-verified'
  | 'record-entry'
  | 'call-operand-names-another-slot';

export interface ImportMapTotals {
  readonly firstSlot: number;
  readonly lastSlot: number;
  readonly slots: number;
  readonly unreadableSlots: number;
  readonly resolutions: Readonly<Record<SlotResolutionKey, number>>;
  /**
   * (slot, call site) pairs. An API is keyed by the pair, never by the slot:
   * SafeDisc's dispatcher resolves on the caller's return address minus six,
   * so one slot serves several APIs.
   */
  readonly bindings: number;
  readonly namedBindings: number;
  readonly evidence: Readonly<Record<BindingEvidence, number>>;
  readonly distinctApis: number;
  readonly moduleIndexToDll: ReadonlyArray<{ readonly moduleIndex: number; readonly dll: string }>;
}

export interface CrtIdentificationTotals {
  readonly sectionsPlacedUniquely: number;
  /** Refused for lack of a unique placement. An ambiguity is never guessed. */
  readonly sectionsRefused: number;
  readonly addressesNamed: number;
  readonly declaredFunctionsIdentified: number;
}

/**
 * What the project declares lives at an address. A relocation whose target is
 * `Unknown` is the only interesting case: every other answer means the
 * reference leaves for somewhere real.
 */
export type AddressClass = Data.TaggedEnum<{
  /** Address zero, from an `fs:[0]` exception registration. Not a dangling
   *  pointer: it is a segment offset, and every /GX prologue has two. */
  ExceptionRegistration: {};
  FunctionEntry: {};
  ImportSlot: {};
  /** Inside .text but not a declared entry: compiler-generated handler thunks
   *  live here and were deliberately kept out of the inventory. */
  TextNonEntry: {};
  Data: { readonly section: string };
  Unknown: {};
}>;
export const AddressClass = Data.taggedEnum<AddressClass>();

// -------------------------------------------------------------------- module

export interface ISubject {
  /**
   * Hash the subject image, derive its layout and the compiler builds that
   * produced it from its own bytes, record all of it, and make it the
   * configuration verdicts are measured against.
   *
   * Idempotent: an unchanged file hashes to the same subject and re-records
   * the same facts. A changed file is a DIFFERENT subject, which retires every
   * verdict proved against the old one through the `superseded` view rather
   * than by anything this method does.
   */
  ingest(): EffectGen<Subject, SubjectIoError | SubjectParseError | DbError>;

  /**
   * The compiler builds that produced the subject, as recorded. This is the
   * measurement that separates code the project can reproduce from code it
   * cannot: a build number read from the Rich header is a fact about the
   * bytes, where "linker 6.0" is not specific enough to act on.
   */
  compIds(): EffectGen<
    ReadonlyArray<{ readonly prodId: number; readonly build: number; readonly objects: number }>,
    SubjectIoError | SubjectParseError | DbError
  >;

  /** The subject verdicts are currently measured against. */
  current(): EffectGen<Option.Option<Subject>, SubjectIoError | SubjectParseError | DbError>;

  /**
   * Subject image bytes for a virtual address range. Absent when the range
   * leaves the image, which the caller must handle: the subject's own bytes do
   * not cover the DLLs mapped alongside it.
   */
  /**
   * The subject's raw bytes, as the file holds them.
   *
   * `bytesAt` maps a VIRTUAL address into a section and is the right call for
   * reading a function. This is the whole image, which a decoder needs
   * because it indexes by `va - imageBase` and must also see the headers and
   * the gaps between sections.
   */
  imageBytes(): EffectGen<Uint8Array, SubjectIoError | SubjectParseError>;

  bytesAt(input: {
    readonly va: number;
    readonly length: number;
  }): EffectGen<Option.Option<Uint8Array>, SubjectIoError | SubjectParseError>;

  /**
   * Guest virtual memory, through the dumped machine's own page tables.
   * Absent means the page is not resident in the image -- an explicit absence
   * the caller handles, never zeros and never a plausible default.
   */
  readGuest(input: {
    readonly va: number;
    readonly length: number;
  }): EffectGen<Option.Option<Uint8Array>, SubjectIoError | SubjectParseError | GuestMapError>;

  /**
   * Every module mapped in the guest and every export each one publishes,
   * from the PEB loader list -- the operating system's own record, so a module
   * cannot be missed, counted twice, or given a size guessed from its headers.
   *
   * Recorded in full because every recovered import name must be traceable to
   * an export directory entry that was actually read.
   */
  mapGuestModules(): EffectGen<GuestModuleTotals, SubjectError | DbError>;

  /**
   * Name every slot of the subject's import address table, and say what blocks
   * the rest.
   *
   * The game's KERNEL32 and USER32 descriptors have OriginalFirstThunk == 0,
   * so the loader overwrote the only copy of 186 names in place. Those slots
   * hold SafeDisc stubs rather than APIs, and SafeDisc resolves per call site,
   * so the answer is one row per (slot, call site) and the slot alone is not a
   * key.
   */
  mapImports(): EffectGen<ImportMapTotals, SubjectError | DbError>;

  /**
   * Identify CRT functions by placing the shipped library's own objects in the
   * subject. An identification names the function and shows its bytes came
   * from that object, which is a stronger claim than reconstructing source
   * that happens to compile to the same thing.
   */
  identifyCrtFunctions(): EffectGen<CrtIdentificationTotals, SubjectIoError | SubjectParseError | DbError>;

  /**
   * What the project declares lives at each address. Batched because the
   * answer is drawn from the whole declared symbol set, which is read once.
   */
  classifyAddresses(
    vas: ReadonlyArray<number>,
  ): EffectGen<ReadonlyArray<AddressClass>, SubjectIoError | SubjectParseError | DbError>;
}
