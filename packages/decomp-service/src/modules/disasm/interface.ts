import { Option, Schema } from 'effect';
import type { EffectGen } from 'effective-modules';

/**
 * The one place this service decodes x86.
 *
 * Everything downstream -- the function inventory, entry discovery, shape
 * clustering, sibling ranking, the work batches an agent reads -- is derived
 * from instruction boundaries, so a second decoder would be a second answer to
 * "where does this instruction end". There is exactly one.
 *
 * WHAT THIS MODULE DOES NOT DO
 * ---------------------------
 * It does not decide byte-exactness and it does not compute the relocation
 * mask, which needs per-operand displacement and immediate offsets. Both
 * belong to the gate, which owns the comparison. `listing` will render the
 * mask column when the gate hands it a mask, and omits it otherwise.
 *
 * It holds no files. Where the Python tooling read functions.json, parked.json
 * and a tree of batch directories, every one of those is an argument here and
 * the database is the system of record.
 */

/** A decoded instruction, with `address` ABSOLUTE in the subject's address
 *  space. The decoder's own call takes the base address as an option, not a
 *  positional argument, and reports offsets from the buffer start when it is
 *  left out -- which silently produces listings whose branch targets name the
 *  wrong instruction. Nothing in this module may construct an Instruction
 *  without the base address. */
export interface Instruction {
  /** Decoder instruction id. Stable within one decoder build; used only to
   *  compare against ids this module derives from canonical bytes, never
   *  hard-coded. */
  readonly id: number;
  readonly address: number;
  readonly size: number;
  readonly bytes: Uint8Array;
  readonly mnemonic: string;
  readonly opStr: string;
}

/**
 * The binary under reconstruction, as bytes.
 *
 * The subject is a RAM image indexed from its own image base, so a file offset
 * equals an RVA and `va - imageBase` indexes `bytes` directly.
 *
 * This shape belongs to the subject module once that lands; it is declared
 * here because the decoder cannot work without it and there is nowhere else
 * for it to live yet.
 */
export interface SubjectImage {
  readonly sha256: string;
  readonly bytes: Uint8Array;
  readonly imageBase: number;
  /**
   * First and one-past-last address of the executable span, which must be
   * read from the subject's own section table and never written down.
   *
   * The Python tooling wrote it down twice and the two copies disagree: the
   * inventory used the section table (0x401000..0x62847D, from vaddr 0x1000
   * and vsize 0x22747D), while the discoverer carried a literal 0x62607D and
   * so could not see the last 9,216 bytes of code -- 472 functions the
   * inventory does find.
   */
  readonly textLo: number;
  readonly textHi: number;
}

export interface FunctionExtent {
  readonly va: number;
  readonly size: number;
}

/** What makes an address a function entry. A clean decode is NOT evidence: a
 *  prologue scan over this subject produced 1,043 entries, none of which was a
 *  direct call target. Only a reference counts. */
export type EvidenceKind = 'call' | 'rdata-pointer';

export interface DiscoveredFunction extends FunctionExtent {
  readonly evidence: ReadonlyArray<EvidenceKind>;
}

/** Why a referenced address was not emitted as a function. Kept because a
 *  count answers "how many" and this answers "which, and why". */
export type RejectionReason =
  | 'no-prologue'
  | 'no-decode'
  | 'no-terminator'
  | 'discontiguous-decode'
  | 'compiler-generated';

export interface Rejection {
  readonly va: number;
  readonly reason: RejectionReason;
}

export interface Discovery {
  readonly found: ReadonlyArray<DiscoveredFunction>;
  readonly rejected: ReadonlyArray<Rejection>;
}

export interface Inventory {
  readonly subjectSha256: string;
  readonly textLo: number;
  readonly textHi: number;
  readonly functions: ReadonlyArray<FunctionExtent>;
  readonly coveredBytes: number;
  /** How many entries each seed source contributed, before extents. Direct
   *  calls alone reach 71% of the span; the rest is reached only through
   *  vtables, which appear as aligned dwords elsewhere in the image. */
  readonly seedsFromDirectCalls: number;
  readonly seedsFromPointerTables: number;
}

/** Shape keys a function is clustered and matched on. */
export interface Fingerprint {
  /** Mnemonics and operands with every hex constant replaced by K. An exact
   *  match is the same source shape with different numbers. */
  readonly shape: string;
  /** Mnemonics alone, which catches families differing by one extra store or
   *  a trailing call. */
  readonly coarseShape: string;
  /** Offsets reached off ecx -- the object's own fields. Functions sharing
   *  these are probably methods of one class. */
  readonly thisOffsets: ReadonlyArray<number>;
}

export interface Sibling extends FunctionExtent {
  readonly exactShape: boolean;
  /** Character-level similarity of the two mnemonic sequences, on the same
   *  measure the Python reference used. */
  readonly mnemonicSimilarity: number;
  readonly addressDistance: number;
}

/** Bytes of subject code one agent is given. Work scales with the code to
 *  reconstruct, not the number of functions: a fixed count per agent handed
 *  one agent 24 trivial accessors while 3,005 functions holding 1.63 MB were
 *  never assignable at all. */
export const DEFAULT_BUDGET_BYTES = 1500;

/** Most functions one agent may receive from a single shape cluster. */
export const DEFAULT_CLUSTER_CAP = 24;

export const DEFAULT_MIN_SIZE = 4;

export interface BatchRound {
  /** Whatever the caller stores a round under. It is printed in the batch
   *  text so a batch states its own identity: an agent given batch1 opened
   *  batch0 instead and redid six functions another agent was writing. */
  readonly id: string;
  readonly vas: ReadonlyArray<number>;
}

export interface BatchRequest {
  readonly roundId: string;
  /** The live inventory. */
  readonly functions: ReadonlyArray<FunctionExtent>;
  /** Solved, parked, and proven-to-be-shipped-CRT addresses. Handing an agent
   *  any of these asks it to redo finished work. */
  readonly settled: ReadonlyArray<number>;
  /** Every round still live. Two are live at once whenever a new one is cut
   *  while the previous one is finishing, so protecting only the newest is
   *  not enough. */
  readonly rounds: ReadonlyArray<BatchRound>;
  readonly agentCount: number;
  readonly budgetBytes: number;
  readonly clusterCap: number;
  readonly minSize: number;
  readonly maxSize: number;
}

export interface BatchEntry extends FunctionExtent {
  readonly thisOffsets: ReadonlyArray<number>;
  /** True when this entry is a one-off packed in to fill the byte budget
   *  rather than a member of the batch's family. */
  readonly padding: boolean;
}

export interface Batch {
  readonly index: number;
  readonly entries: ReadonlyArray<BatchEntry>;
  /** The listing the agent reads, with the ADDRESS of every instruction. An
   *  agent without them misread `je 0x441d31` as targeting the adjacent
   *  instruction and would have reconstructed a wrong algorithm from a
   *  correct listing. */
  readonly text: string;
  readonly inFamilies: number;
  readonly maxBytes: number;
  readonly distinctShapes: number;
}

export interface BatchPlan {
  readonly batches: ReadonlyArray<Batch>;
  /** Addresses excluded from this plan, said out loud: a silent exclusion set
   *  is how parked functions got reassigned when an edit meant to add them
   *  matched nothing and failed quietly. */
  readonly excluded: number;
  /** Rounds whose every function is settled or has left the inventory, so the
   *  caller may retire them. A round held open by one function that resisted
   *  pinned its directory and kept that address claimed for good. */
  readonly retirableRounds: ReadonlyArray<string>;
  /** Candidates dropped before clustering, and why. */
  readonly skipped: ReadonlyArray<{ readonly va: number; readonly reason: 'no-clean-decode' | 'thunk' }>;
}

export interface CodeBytes {
  readonly bytes: Uint8Array;
  /** Absolute address the first byte sits at. */
  readonly address: number;
}

export class DecoderUnavailable extends Schema.TaggedError<DecoderUnavailable>()(
  'DecoderUnavailable',
  { reason: Schema.String },
) {}

export class OutsideImage extends Schema.TaggedError<OutsideImage>()('OutsideImage', {
  va: Schema.Number,
  size: Schema.Number,
}) {}

export type DisasmError = DecoderUnavailable | OutsideImage;

export interface IDisasm {
  /** Whatever decodes from these bytes, stopping where the decoder does.
   *  Instruction addresses are absolute, counted from `address`. */
  decodeBytes(code: CodeBytes): EffectGen<ReadonlyArray<Instruction>, DecoderUnavailable>;

  /** The function's instructions, or None when the bytes do not decode into
   *  instructions that exactly cover `size`. A partial decode is not a
   *  function: a wrong size costs an agent its whole budget on an impossible
   *  target. */
  decodeFunction(
    subject: SubjectImage,
    fn: FunctionExtent,
  ): EffectGen<Option.Option<ReadonlyArray<Instruction>>, DisasmError>;

  /** The single instruction at `va`. None when nothing decodes there. */
  decodeAt(
    subject: SubjectImage,
    va: number,
  ): EffectGen<Option.Option<Instruction>, DisasmError>;

  /**
   * One function's annotated disassembly, for a human.
   *
   * `relocationMask` is one byte per code byte, non-zero where the linker
   * fixes the value up; those bytes are marked `*`. The gate owns the mask,
   * because the gate owns the comparison the mask exists for -- pass
   * Option.none() and the column is omitted.
   *
   * None where the bytes do not decode into exactly `size` bytes. The Python
   * reference printed a truncated listing in that case, with nothing to say
   * it was truncated, which is how a reader ends up reconstructing most of a
   * function and calling it whole.
   */
  listing(
    subject: SubjectImage,
    fn: FunctionExtent,
    relocationMask: Option.Option<Uint8Array>,
  ): EffectGen<Option.Option<string>, DisasmError>;

  fingerprint(
    subject: SubjectImage,
    fn: FunctionExtent,
  ): EffectGen<Option.Option<Fingerprint>, DisasmError>;

  /**
   * Enumerate function entries from the call graph and from pointer tables,
   * and measure each one's extent.
   *
   * Prologue matching is NOT used: this binary is MSVC 6 with frame-pointer
   * omission, where only 229 functions across 2.2 MB emit
   * `push ebp; mov ebp, esp`.
   */
  buildInventory(subject: SubjectImage): EffectGen<Inventory, DisasmError>;

  /**
   * Find entries the inventory never listed.
   *
   * An entry requires REFERENCE EVIDENCE -- a direct call, or a dword OUTSIDE
   * the executable span holding the address, which is what a vtable slot is.
   * A clean decode proves nothing on its own, because x86 decodes almost any
   * byte sequence.
   */
  discover(
    subject: SubjectImage,
    inventory: ReadonlyArray<FunctionExtent>,
  ): EffectGen<Discovery, DisasmError>;

  /**
   * Addresses in the given set that are code the COMPILER emitted, which has
   * no source to recover.
   *
   * This is the only authority on what may be in the inventory, so it is also
   * the only thing that can say what no longer belongs in it: the caller
   * retires exactly what this returns, and never from a separate script.
   * Under /GX, MSVC emits unwind funclets and `__ehhandler` stubs past the end
   * of a function and references them from the unwind map in .rdata, which is
   * the same evidence a vtable slot provides. Six agents transcribed 96 of
   * them as assembly before this was caught.
   */
  compilerGenerated(
    subject: SubjectImage,
    functions: ReadonlyArray<FunctionExtent>,
  ): EffectGen<ReadonlyArray<number>, DisasmError>;

  /**
   * Already-solved functions worth reading before starting on this one,
   * best first: identical shape, then mnemonic similarity, then address
   * proximity.
   *
   * Sibling reuse is the biggest measured win in this project -- whole
   * families have been finished by changing one offset in a solved file.
   */
  rankSiblings(
    subject: SubjectImage,
    target: FunctionExtent,
    solved: ReadonlyArray<FunctionExtent>,
  ): EffectGen<ReadonlyArray<Sibling>, DisasmError>;

  /**
   * True when two encodings differ only by substitutions MSVC 6 and clang are
   * known to disagree on.
   *
   * This is weaker than byte-exactness and must never be counted as it: it
   * says "the same program modulo a substitution we have observed", which is
   * only useful while the real compiler is unavailable.
   */
  equivalentModuloIdioms(a: CodeBytes, b: CodeBytes): EffectGen<boolean, DecoderUnavailable>;

  /**
   * Cluster unassigned functions into one batch per agent.
   *
   * Shapes are grouped so one agent writes a whole family, and the singletons
   * that remain are packed by the `this` offsets they touch so one agent owns
   * one object's layout. Three agents separately derived the same 93-byte
   * exception-frame constructor before clusters were kept whole.
   */
  planBatches(subject: SubjectImage, request: BatchRequest): EffectGen<BatchPlan, DisasmError>;
}
