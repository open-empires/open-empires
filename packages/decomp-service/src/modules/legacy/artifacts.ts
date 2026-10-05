import { Option, Schema } from 'effect';
import path from 'node:path';
import { LEGACY_ROOT, type Bucket } from './paths';

/**
 * The shapes of the Python tooling's files, exactly as they are on disk.
 *
 * Decoded rather than probed: these files are the only record of two days of
 * work and a field read with the wrong name would import a silent gap. Keys
 * stay in the snake_case the files use, because this is a description of
 * someone else's format, not a domain model -- the domain model is the
 * database.
 */

/** `decomp/subject.json`. */
export const Subject = Schema.Struct({
  path: Schema.NonEmptyString,
  sha256: Schema.NonEmptyString,
  size: Schema.Number,
  image_base: Schema.Number,
});
export type Subject = Schema.Schema.Type<typeof Subject>;

/**
 * `decomp/functions.json`.
 *
 * Its `count` field is NOT read: it says 5,565 while the array holds 6,570,
 * because `discover.py` rewrites the array and leaves the scalar behind. The
 * array is the fact; a stored count that disagrees with the rows it counts is
 * exactly the kind of second source of truth this import exists to remove.
 */
export const Inventory = Schema.Struct({
  subject_sha256: Schema.NonEmptyString,
  functions: Schema.Array(
    Schema.Struct({
      va: Schema.Number,
      size: Schema.Number,
      /** Free text: how the entry got here, or how its bounds were corrected.
       *  The schema has no column for it -- see the import's `unexpressed`. */
      note: Schema.OptionFromOptionalNullOr(Schema.String),
    }),
  ),
});
export type Inventory = Schema.Schema.Type<typeof Inventory>;

/** `decomp/fn_verdicts.json`: the addresses the last gate run found exact. */
export const Verdicts = Schema.Struct({
  exact: Schema.Array(Schema.Number),
});
export type Verdicts = Schema.Schema.Type<typeof Verdicts>;

/** `decomp/gate_report.json`: everything else that run measured. */
export const GateReport = Schema.Struct({
  /** The run's own clock. The only honest timestamp available for anything it
   *  decided, since nothing recorded when each individual proof was made. */
  at: Schema.Number,
  subject_sha256: Schema.NonEmptyString,
  exact: Schema.Number,
  bytes_exact: Schema.Number,
  /** `0x62607D - 0x401000`, the span the gate compares. */
  text_span: Schema.Number,
  inventory_functions: Schema.Number,
  crt_identified: Schema.Number,
  by_bucket: Schema.Record(
    Schema.String,
    Schema.Struct({ exact: Schema.Number, total: Schema.Number, flags: Schema.NonEmptyString }),
  ),
  /**
   * The functions whose match leans hardest on excused relocation bytes, and
   * the only per-function `masked`/`compared` figures the run persisted. It
   * computed them for every function and wrote down these.
   */
  weak_detail: Schema.Array(
    Schema.Struct({ va: Schema.NonEmptyString, masked: Schema.Number, total: Schema.Number }),
  ),
});
export type GateReport = Schema.Schema.Type<typeof GateReport>;

/**
 * `decomp/names.json`.
 *
 * `functions` is keyed by 8-digit hex VA. `classes` is keyed by class name and
 * names the functions attributed to each one; five classes have a method name
 * observed in the strings but no address to attribute it to, so they appear
 * here with nothing under `named_functions`.
 */
export const Names = Schema.Struct({
  subject_sha256: Schema.NonEmptyString,
  functions: Schema.Record(
    Schema.String,
    Schema.Struct({ name: Schema.NonEmptyString, confidence: Schema.NonEmptyString }),
  ),
  classes: Schema.Record(
    Schema.String,
    Schema.Struct({
      named_functions: Schema.OptionFromOptionalNullOr(
        Schema.Record(Schema.String, Schema.String),
      ),
    }),
  ),
});
export type Names = Schema.Schema.Type<typeof Names>;

/**
 * `decomp/import_names.json`.
 *
 * A slot carries a descriptor-resolved `name` when the loader left one
 * readable. A SafeDisc stub carries none and is answered per call site
 * instead, because the dispatcher resolves on the caller's return address --
 * so one slot serves several APIs and the slot alone is not a key.
 */
export const ImportMap = Schema.Struct({
  subject: Schema.NonEmptyString,
  slots: Schema.Array(
    Schema.Struct({
      slot: Schema.NonEmptyString,
      dll: Schema.OptionFromOptionalNullOr(Schema.String),
      target: Schema.OptionFromOptionalNullOr(Schema.String),
      resolution: Schema.NonEmptyString,
      name: Schema.OptionFromOptionalNullOr(Schema.String),
      /** What the subject's own import descriptor said, where the loader left
       *  it readable. 61 of 255 slots still have it. */
      descriptor_name: Schema.OptionFromOptionalNullOr(Schema.String),
      descriptor_ordinal: Schema.OptionFromOptionalNullOr(Schema.Number),
      /** Why this slot has no name. "Never called before the snapshot" and
       *  "resolves to several APIs" are different answers, not gaps. */
      blocked_by: Schema.OptionFromOptionalNullOr(Schema.String),
      safedisc: Schema.OptionFromOptionalNullOr(
        Schema.Struct({
          call_sites: Schema.Array(
            Schema.Struct({
              call_site: Schema.NonEmptyString,
              name: Schema.NonEmptyString,
              evidence: Schema.NonEmptyString,
              /** The address the dispatcher had cached for this call site. */
              target: Schema.NonEmptyString,
              /** Which of the record's 101 cache buckets held it. */
              bucket: Schema.Number,
              /** Other export names publishing the same address: `_hread` and
               *  `_lread` are one function. Read so the loss is countable. */
              address_shared_by: Schema.OptionFromOptionalNullOr(Schema.Array(Schema.String)),
            }),
          ),
        }),
      ),
    }),
  ),
});
export type ImportMap = Schema.Schema.Type<typeof ImportMap>;

/**
 * `decomp/port_status.json`.
 *
 * `refused` is a COUNT with no address list: `portable.py` prints which files
 * it refused and persists only how many. `needs_globals` names the converted
 * files that still hold literal image addresses.
 */
export const PortStatus = Schema.Struct({
  converted: Schema.Number,
  refused: Schema.Number,
  needs_globals: Schema.Array(Schema.NonEmptyString),
});
export type PortStatus = Schema.Schema.Type<typeof PortStatus>;

/**
 * `decomp/crt_identified.json`: hex VA to the CRT symbol at that address and
 * the library object its bytes came from.
 */
export const CrtIdentifications = Schema.Record(
  Schema.String,
  Schema.Struct({ name: Schema.NonEmptyString, member: Schema.NonEmptyString }),
);
export type CrtIdentifications = Schema.Schema.Type<typeof CrtIdentifications>;

export type Slot = ImportMap['slots'][number];
export type CallSite = Schema.Schema.Type<
  typeof ImportMap
>['slots'][number]['safedisc'] extends Option.Option<infer S>
  ? S extends { readonly call_sites: ReadonlyArray<infer C> }
    ? C
    : never
  : never;

/**
 * The hash of a reconstruction's text.
 *
 * Taken from the bytes that are stored and nothing else: a hash sourced from
 * anywhere but the stored bytes was wrong for 1,445 blocks once, and no
 * offline check could tell.
 */
export const sha256 = (text: string): string =>
  new Bun.CryptoHasher('sha256').update(text).digest('hex');

/** Relative to the legacy tree, so a reported path is short and recognisable. */
export const shortPath = (absolute: string): string => path.relative(LEGACY_ROOT, absolute);

/** An address as these files write it: 8 hex digits, no prefix. */
export const addressOf = (digits: string): number => Number.parseInt(digits, 16);

/** An address as a report writes it. The inverse of `addressOf`, kept beside
 *  it so the two cannot drift. */
export const hexOf = (va: number): string => `0x${va.toString(16).padStart(8, '0')}`;

/** The call sites a slot records, or none when it is not a SafeDisc stub. */
export const callSitesOf = (slot: Slot): ReadonlyArray<CallSite> =>
  Option.match(slot.safedisc, { onNone: () => [], onSome: (s) => s.call_sites });

// ------------------------------------------- the whole tree, as one value

/**
 * One reconstruction file as it sits on disk.
 *
 * `flags` is the bucket's, not the file's: the gated directories' flags come
 * from the gate's own report, and `wip/` is not a gate bucket so nothing
 * recorded any for it.
 */
export interface Reconstruction {
  readonly bucket: Bucket;
  readonly file: string;
  readonly va: number;
  readonly source: string;
  readonly sourceSha: string;
  readonly flags: string;
}

/** Everything the legacy tree says, read once and checked against itself. */
export interface LegacyState {
  readonly subject: Subject;
  readonly inventory: Inventory;
  readonly verdicts: Verdicts;
  readonly report: GateReport;
  readonly names: Names;
  readonly imports: ImportMap;
  readonly port: PortStatus;
  readonly crt: CrtIdentifications;
  readonly reconstructions: ReadonlyArray<Reconstruction>;
  /** Base names present in `decomp/port/`: what the portability pass produced. */
  readonly ported: ReadonlySet<string>;
}

/**
 * The class each named address is attributed to, keyed by upper-case hex VA.
 *
 * Taken from names.json's own class records rather than from the shape of the
 * name: five classes are known only as a method name seen in the strings, and
 * splitting `pnl_btn::draw` on `::` would invent an attribution for an address
 * nothing attributed.
 */
export const classOf = (names: Names): ReadonlyMap<string, string> => {
  const byVa = new Map<string, string>();
  for (const [className, record] of Object.entries(names.classes)) {
    const attributed = Option.getOrElse(
      record.named_functions,
      () => ({}) as Record<string, string>,
    );
    for (const va of Object.keys(attributed)) byVa.set(va.toUpperCase(), className);
  }
  return byVa;
};
