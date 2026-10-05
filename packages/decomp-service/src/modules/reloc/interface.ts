import type { EffectGen } from 'effective-modules';
import type { DbError } from '../db/interface';
import type { DisasmError } from '../disasm/interface';
import type { GateUnavailable } from '../gate/interface';
import type {
  AddressClass,
  NoCurrentSubject,
  SubjectIoError,
  SubjectParseError,
} from '../subject/interface';

/**
 * Relocation verification.
 *
 * Both the gate and the composition proof take relocation bytes from the
 * subject, which makes those four-byte fields match by construction. That is
 * honest about the surrounding code, but it leaves every call target and global
 * address in the reconstructed set UNVERIFIED: a reconstruction could name any
 * callee at all and the bytes would still agree.
 *
 * This closes most of that gap without a symbol map. For each relocation site
 * the intended target is DERIVED from the subject's own bytes -- a rel32
 * resolves against its own address, a DIR32 is already absolute -- and then
 * classified against what the project declares: a function entry, an import
 * slot, a data section, an exception registration, compiler-generated code
 * inside .text. Anything else is dangling.
 *
 * WHAT IT DOES NOT PROVE
 * ----------------------
 * It does not prove a reconstruction named the RIGHT callee; that needs a
 * symbol map. It proves every reference leaves for somewhere real, which is
 * what a wrong function boundary or a bogus extern would break.
 *
 * TWO THINGS THE PYTHON GOT WRONG HERE
 * ------------------------------------
 * It hardcoded .text as ending at 0x62607D. That is `max(va + size)` over an
 * old inventory, not a section bound: the section header says 0x62847D, so
 * 9,216 bytes of real code were classified as "not in any section". The span
 * comes from the subject here and is never written down.
 *
 * Its own count of bad references added up `unknown` and a key spelled
 * `"inside .text, not an entry"` that its classifier never produced -- it
 * returned `"EH handler / .text non-entry"`. The second term was always zero.
 * A pattern that matches nothing is worse than a missing one, so there is one
 * term here: `Unknown`.
 */

/** One four-byte relocation field in one reconstruction. */
export interface RelocationField {
  /** The function the field belongs to. */
  readonly va: number;
  /** Byte offset of the field inside that function. */
  readonly offset: number;
  /** The value the subject holds there. */
  readonly stored: number;
  /**
   * `rel32` when the field is the displacement of a direct `call`/`jmp`, so the
   * target is relative to the end of the instruction; `absolute` otherwise.
   *
   * Decided from the DECODED instruction containing the field, not from the
   * relocation record: MSVC 6 objects use REL32 for both a near call and a
   * `mov eax, dword ptr [addr]` built against a fixed address, and guessing
   * from the record alone turns every global read into a reference 4 bytes
   * past wherever the instruction happened to end.
   */
  readonly kind: 'rel32' | 'absolute';
  readonly target: number;
  readonly classification: AddressClass;
}

export interface RelocationReport {
  /** Reconstructions in force when this ran. */
  readonly considered: number;
  /**
   * Reconstructions whose stored source still compiles to the subject's bytes
   * at the function's entry, which is the only case where the object's
   * relocation records describe the subject's fields.
   */
  readonly reproduced: number;
  /** The rest, named rather than dropped: the Python returned an empty list
   *  for them, so a corpus that had stopped reproducing would have reported
   *  "0 dangling" and looked like a pass. */
  readonly notReproduced: number;
  readonly fields: number;
  /** Fields whose target lands on something the project declares. */
  readonly explained: number;
  readonly byClass: ReadonlyArray<{ readonly label: string; readonly fields: number }>;
  /** Fields whose target is in no declared symbol and no section. By address,
   *  because a count of dangling references cannot be investigated. */
  readonly dangling: ReadonlyArray<RelocationField>;
}

export type RelocFailure =
  | DbError
  | DisasmError
  | GateUnavailable
  | NoCurrentSubject
  | SubjectIoError
  | SubjectParseError;

export interface IReloc {
  /** Derive and classify every relocation field in every reconstruction in
   *  force. */
  check(): EffectGen<RelocationReport, RelocFailure>;
}
