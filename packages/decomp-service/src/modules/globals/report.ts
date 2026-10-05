import { Option } from 'effect';
import { pointerCoverage } from './inventory';
import {
  EVIDENCE_ORDER,
  type Deferral,
  type Deferred,
  type GlobalEntry,
  type GlobalsReport,
  type Holds,
  type PointerCandidate,
  type SizeBasis,
} from './interface';

const SIZE_BASES: ReadonlyArray<SizeBasis> = [
  'library-section',
  'library-next-symbol',
  'pointer-run',
  'access-width',
];
const HOLDS: ReadonlyArray<Holds> = ['code-pointer', 'data-pointer', 'float'];
const DEFERRED: ReadonlyArray<Deferred> = ['identity', 'size', 'name', 'holds'];

/**
 * The report, from the facts it is a report about.
 *
 * One place, used by the derivation and by the read-back alike: a count
 * `rebuild` computed in its own way would be free to disagree with the same
 * count read out of the database afterwards, and nothing would say which was
 * right.
 */
export const assemble = (input: {
  readonly subjectSha256: string;
  readonly dataRegion: GlobalsReport['dataRegion'];
  readonly references: number;
  readonly unconfirmedReferences: number;
  readonly entries: ReadonlyArray<GlobalEntry>;
  readonly deferrals: ReadonlyArray<Deferral>;
  readonly candidates: ReadonlyArray<PointerCandidate>;
  readonly isCode: (va: number) => boolean;
  readonly importSlotsSkipped: number;
  readonly librarySymbols: number;
  readonly libraryRefusalReasons: ReadonlyArray<string>;
}): GlobalsReport => {
  const { entries } = input;
  const refusals = new Map<string, number>();
  for (const reason of input.libraryRefusalReasons) {
    refusals.set(reason, (refusals.get(reason) ?? 0) + 1);
  }
  return {
    subjectSha256: input.subjectSha256,
    dataRegion: input.dataRegion,
    references: input.references,
    unconfirmedReferences: input.unconfirmedReferences,
    globals: entries.length,
    byEvidence: EVIDENCE_ORDER.map((evidence) => ({
      evidence,
      globals: entries.filter((e) => e.evidence === evidence).length,
    })),
    sized: entries.filter((e) => Option.isSome(e.size)).length,
    bySizeBasis: SIZE_BASES.map((basis) => ({
      basis,
      globals: entries.filter((e) => Option.getOrNull(e.sizeBasis) === basis).length,
    })),
    named: entries.filter((e) => Option.isSome(e.name)).length,
    holdsKnown: HOLDS.map((holds) => ({
      holds,
      globals: entries.filter((e) => Option.getOrNull(e.holds) === holds).length,
    })),
    importSlotsSkipped: input.importSlotsSkipped,
    deferrals: DEFERRED.map((what) => ({
      what,
      addresses: new Set(input.deferrals.filter((d) => d.what === what).map((d) => d.address)).size,
    })),
    pointers: pointerCoverage({
      entries,
      candidates: input.candidates,
      isCode: input.isCode,
    }),
    librarySymbols: input.librarySymbols,
    libraryRefusals: [...refusals.entries()]
      .sort(([, a], [, b]) => b - a)
      .map(([reason, count]) => ({ reason, count })),
  };
};
