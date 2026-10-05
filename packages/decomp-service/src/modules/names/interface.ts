import { Option } from 'effect';
import type { EffectGen } from 'effective-modules';
import type { DbError } from '../db/interface';
import type { DisasmError } from '../disasm/interface';
import type {
  NoCurrentSubject,
  SubjectIoError,
  SubjectParseError,
} from '../subject/interface';

/**
 * Original function names, recovered from the subject's own strings.
 *
 * The compiler discarded every name the programmers wrote, so a reconstructed
 * function is `sub_00448EB0` with fields called `f20`. A few names survived
 * anyway: the game hands its own function names to internal bookkeeping AS
 * TEXT, and those strings are still in the image. This module reads them back.
 *
 * WHAT MAKES A STRING A NAME
 * --------------------------
 * Not that the function mentions it. 651 of the 866 references found are the
 * containing function passing some other string somewhere, and a function that
 * mentions a name is not named by it.
 *
 * A name is evidenced when the containing function passes the string as the
 * FIRST pushed argument -- the tag -- to one of two known call pairs:
 *
 *   0x465BA0 lock(tag, wait) / 0x465C20 unlock(tag)      -> `lock-tag`
 *   0x465C60 acquire(tag)    / 0x465CB0 release(tag)     -> `self-named-other`
 *
 * Both take a scoped lock on a surface the caller loads out of its own `this`.
 * Neither is a profiler, and the tag is the scope's label, which for this
 * codebase is the enclosing function's name.
 *
 * TWO PATTERNS THAT LOOK THE SAME AND ARE NOT, WITH THE EVIDENCE
 * -------------------------------------------------------------
 * 0x428190 is `report(hresult, where)`, called from 39 sites. Eight of its
 * `where` strings are shaped exactly like function names -- and
 * `sub_00437200` passes THREE of them, so the string names the call site, not
 * the function. All 39 are `referenced-only`.
 *
 * 0x4FBDC0 is a single `ret` -- a logger stubbed out for retail, called from
 * 583 sites whose arguments are log messages, not names.
 *
 * WHY 13 CANDIDATES ARE WITHHELD
 * ------------------------------
 * A string that is the tag at two different places cannot name both, so it
 * names neither: `diam_map::draw_objects` is the tag at 0x00448F5D inside
 * function 0x00448F50 and again at 0x005DB5F7, 980 KB away in a region the
 * inventory does not attribute to any function. A function that passes
 * SEVERAL distinct tags is the same problem from the other side: the tags
 * label sub-regions of one body and nothing says which is the body's own
 * name.
 *
 * Both are withheld WITH THE REASON, because a withheld name is evidence and
 * not an absence. Any version of this that skipped the check would ship a
 * wrong name into `functions.name` and nothing downstream would catch it.
 *
 * WHAT IS NOT AVAILABLE, CHECKED RATHER THAN ASSUMED
 * -------------------------------------------------
 * The richer sources are all absent from this image: the export, debug,
 * exception, base-relocation, TLS and load-config directories are every one
 * of them rva=0 size=0; the COFF symbol table pointer and count are 0; there
 * is no `.?AV`/`.?AU` RTTI descriptor, no `type_info`, and no `RSDS`/`NB10`
 * codeview signature anywhere in the image. Confirmed by reading the bytes,
 * not taken on trust -- and not a capability here: PE structure belongs to the
 * subject module, which owns the headers. One source path does survive, at
 * 0x66C4D8: `C:\work\age2_x1 korean\Com_hand.cpp`.
 */

// ----------------------------------------------------------------- failures

export type NamesError =
  | DbError
  | DisasmError
  | NoCurrentSubject
  | SubjectIoError
  | SubjectParseError;

// ------------------------------------------------------------ domain values

/**
 * What one reference is, as evidence.
 *
 * `lock-tag`          the containing function passes this string as the tag to
 *                     the 0x465BA0 / 0x465C20 pair.
 * `self-named-other`  the same, for the 0x465C60 / 0x465CB0 pair.
 * `referenced-only`   the string is merely mentioned here. This does NOT name
 *                     the containing function, and is kept because "which
 *                     references were not evidence, and why" is the question a
 *                     count of them cannot answer.
 */
export type ReferenceRole = 'lock-tag' | 'self-named-other' | 'referenced-only';

/** The two roles that can name a function. */
export type NameConfidence = 'lock-tag' | 'self-named-other';

/**
 * The member the consuming call's `this` was loaded from.
 *
 * Read backwards from the CALL, not from the push: the first instruction
 * before the call that writes `ecx` decides, and it counts only when that
 * instruction is `mov ecx, dword ptr [<base> + <disp>]` on a base that is
 * neither `esp` nor `ebp` -- a stack slot is a local, not a member. Anchoring
 * on the push instead attributes a load that a later `mov ecx, eax` has
 * already overwritten, which put a spurious `+0x0` on two classes.
 */
export interface SurfaceLoad {
  readonly at: number;
  readonly memberOffset: number;
  readonly instruction: string;
}

/** One instruction in the executable span whose immediate operand is the
 *  address of an identifier-shaped string. */
export interface StringReference {
  /** Address of the referencing instruction. */
  readonly site: number;
  readonly stringVa: number;
  readonly text: string;
  readonly mnemonic: string;
  /**
   * True when the site came from an inventory function whose body decodes to
   * exactly its recorded size, so the instruction boundary is a fact.
   *
   * False means the site came from a resynchronising sweep of a region with no
   * known boundary -- a gap between inventory functions, or a function whose
   * body does not decode cleanly. 138 of the 866 are of this kind, and in such
   * a region a different starting alignment yields a different answer: this is
   * the one place a reference here is a reading rather than a fact.
   */
  readonly anchored: boolean;
  /** Absent when the site is in a .text region the inventory attributes to no
   *  function. Such a reference still COUNTS AGAINST a name, because a tag
   *  pushed from an unattributed region is a second place it is pushed from. */
  readonly containingFunction: Option.Option<number>;
  /**
   * The first direct call reached from the site, which is what consumes the
   * string. Indirect calls are stepped over, not stopped at: a tag is
   * regularly pushed, a virtual call made to produce the receiver, and the tag
   * then consumed by the direct call after it -- stopping at the indirect call
   * loses 0x465C60 as the consumer and with it one real name.
   *
   * Where a direct call intervenes that takes no stack arguments this names
   * that call rather than the eventual consumer. It is exact for the four
   * callees the naming patterns rest on, which take their tag as argument 0.
   */
  readonly consumer: Option.Option<number>;
  readonly consumedAt: Option.Option<number>;
  /** Pushes between this reference and the consuming call. Zero means this
   *  string is the call's first argument. */
  readonly argIndex: Option.Option<number>;
  readonly surface: Option.Option<SurfaceLoad>;
  readonly role: ReferenceRole;
}

export interface RecoveredName {
  readonly va: number;
  readonly name: string;
  /** The part before `::`. Absent for the four names that carry no class --
   *  `PtrClear`, `PtrSpanCopy`, `OverlayMemCopy`, `take_snapshot`. */
  readonly className: Option.Option<string>;
  readonly confidence: NameConfidence;
  readonly stringVa: number;
  readonly refSites: ReadonlyArray<number>;
  readonly surfaceMemberOffsets: ReadonlyArray<number>;
}

/** A name the evidence reaches but cannot attribute. Stored, because an
 *  absence and a refusal are different answers. */
export interface WithheldName {
  readonly va: number;
  readonly candidates: ReadonlyArray<string>;
  readonly reason: string;
}

export interface NameClass {
  readonly className: string;
  /** Every `::`-qualified string with this prefix, named or not. A method seen
   *  only as a string is still vocabulary: it says the class HAS that method
   *  even when no address can be shown to be it. */
  readonly methodsSeen: ReadonlyArray<string>;
  readonly namedFunctions: ReadonlyArray<{ readonly va: number; readonly name: string }>;
  readonly surfaceMemberOffsets: ReadonlyArray<number>;
}

/**
 * The independent check on the lock-tag reading.
 *
 * If these strings really are the names of methods on real classes, the
 * classes should look like classes -- and they do: the great majority load the
 * surface they lock from the same member of their own object, across class
 * names that share no prefix and were derived independently of each other.
 *
 * `contradicting` is the honest bound on how much this proves. A class that
 * loads from somewhere else is not a contradiction of the convention, only an
 * absence of it; nothing in this evidence could show two classes DISAGREEING
 * about what `this+0x20` is, because each class's offsets are observed on its
 * own functions. The figure is reported as "classes whose observed surface is
 * never the common member", which is what can actually be counted.
 */
export interface SurfaceCorroboration {
  readonly classes: number;
  readonly withObservedSurface: number;
  /** The member the convention uses, derived as the most common one rather
   *  than written down. */
  readonly commonMemberOffset: Option.Option<number>;
  readonly agreeing: number;
  readonly contradicting: ReadonlyArray<{
    readonly className: string;
    readonly memberOffsets: ReadonlyArray<number>;
  }>;
  readonly withoutObservedSurface: ReadonlyArray<string>;
}

export interface NameReport {
  readonly subjectSha256: string;
  readonly references: number;
  /** References whose site came from a resynchronising sweep rather than a
   *  clean function decode. */
  readonly unanchoredReferences: number;
  readonly distinctStrings: number;
  readonly qualifiedStrings: number;
  readonly namedFunctions: number;
  readonly byConfidence: ReadonlyArray<{
    readonly confidence: NameConfidence;
    readonly functions: number;
  }>;
  readonly referencedOnly: number;
  readonly names: ReadonlyArray<RecoveredName>;
  readonly withheld: ReadonlyArray<WithheldName>;
  readonly classes: ReadonlyArray<NameClass>;
  readonly surface: SurfaceCorroboration;
}

// -------------------------------------------------------------------- module

export interface INames {
  /**
   * Read every identifier-shaped string reference out of the executable span,
   * decide which of them name their containing function, and record all of it.
   *
   * Re-runnable as the inventory grows: the whole derivation for the current
   * subject is replaced inside one transaction, so a name this run no longer
   * derives is GONE rather than left looking current. That is not a
   * retraction of anything proved -- these are derived facts about the
   * subject's bytes, and no verdict depends on them.
   */
  recover(): EffectGen<NameReport, NamesError>;

  /** What is recorded for the current subject, without re-deriving it. Absent
   *  when `recover` has not run against this subject. */
  recorded(): EffectGen<Option.Option<NameReport>, NamesError>;
}
