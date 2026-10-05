import path from 'node:path';

/**
 * Where the Python tooling's own files live.
 *
 * Resolved once so no other part of this module reads the environment for
 * itself. Only LOCATIONS belong here; every fact the import records is read
 * from the bytes at these paths.
 *
 * Nothing here is deleted by the import. The files stay as the reference the
 * generated ports are checked against until every port agrees with them;
 * removing them is a separate, later step.
 */
const WORK_ROOT = path.resolve(
  process.env.DECOMP_WORK ?? path.join(import.meta.dir, '../../../../aoe2-in-browser'),
);

export const LEGACY_ROOT = path.join(WORK_ROOT, 'decomp');

/** The subject's hash, path, size and image base, as the Python side recorded them. */
export const SUBJECT_JSON = path.join(LEGACY_ROOT, 'subject.json');
/** One entry per function in the subject: address and size. */
export const INVENTORY_JSON = path.join(LEGACY_ROOT, 'functions.json');
/** The addresses the Python gate last found byte-exact. */
export const VERDICTS_JSON = path.join(LEGACY_ROOT, 'fn_verdicts.json');
/** Everything else that gate run measured, including its own timestamp. */
export const GATE_REPORT_JSON = path.join(LEGACY_ROOT, 'gate_report.json');
/** Original function and class names recovered from the subject's strings. */
export const NAMES_JSON = path.join(LEGACY_ROOT, 'names.json');
/** The import address table: one record per slot, with its call sites. */
export const IMPORT_NAMES_JSON = path.join(LEGACY_ROOT, 'import_names.json');
/** Counts and the needs-globals list from the portability pass. */
export const PORT_STATUS_JSON = path.join(LEGACY_ROOT, 'port_status.json');
/** Addresses whose bytes were matched to an object in the shipped CRT libraries. */
export const CRT_IDENTIFIED_JSON = path.join(LEGACY_ROOT, 'crt_identified.json');
/** The generated portable tree. Its contents say which sources converted. */
export const PORT_DIR = path.join(LEGACY_ROOT, 'port');

/**
 * A directory of reconstructions and what a file in it claims.
 *
 * `gated` is the whole distinction: a file in a gated directory claims its
 * address is byte-exact and the gate checks it every run, so a near-miss left
 * there would make "all exact" stop meaning anything.
 */
export interface Bucket {
  /** The key `gate_report.json` reports this directory's counts under. */
  readonly name: string;
  readonly dir: string;
  readonly gated: boolean;
}

export const BUCKETS: ReadonlyArray<Bucket> = [
  { name: 'fn', dir: path.join(LEGACY_ROOT, 'src/fn'), gated: true },
  { name: 'fn-o1', dir: path.join(LEGACY_ROOT, 'src/fn-o1'), gated: true },
  { name: 'wip', dir: path.join(LEGACY_ROOT, 'src/wip'), gated: false },
];

/** `sub_004012F0.cpp` and nothing else. A README in the same directory is not
 *  a reconstruction and must not be read as one. */
export const RECONSTRUCTION_FILE = /^sub_([0-9A-Fa-f]{1,8})\.cpp$/;

/**
 * The span of the subject the Python gate compares, hardcoded in
 * `decomp/verify.py` as `0x62607D - 0x401000` and reported by it as
 * `text_span`.
 *
 * This is NOT the .text section's extent. The section header runs to
 * 0x62847D, 9,216 bytes further, and the two must not be conflated: one is
 * what the gate measured its coverage against, the other is what the image
 * says. The import writes this one and asserts it against the gate's own
 * reported span, so a subject row cannot claim a coverage denominator no run
 * ever used.
 */
export const GATE_TEXT_LO = 0x401000;
export const GATE_TEXT_HI = 0x62607d;
