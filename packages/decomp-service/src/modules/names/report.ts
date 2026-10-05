import { corroborate, classesOf } from './vocabulary';
import type {
  NameConfidence,
  NameReport,
  RecoveredName,
  StringReference,
  WithheldName,
} from './interface';

const CONFIDENCES: ReadonlyArray<NameConfidence> = ['lock-tag', 'self-named-other'];

/**
 * The report, from the facts it is a report about.
 *
 * One place, used by the derivation and by the read-back alike: a count that
 * `recover` computed in its own way would be free to disagree with the same
 * count read out of the database afterwards, and nothing would say which was
 * right.
 */
export const assemble = (input: {
  readonly subjectSha256: string;
  readonly references: ReadonlyArray<StringReference>;
  readonly names: ReadonlyArray<RecoveredName>;
  readonly withheld: ReadonlyArray<WithheldName>;
}): NameReport => {
  const { subjectSha256, references, names, withheld } = input;
  const distinct = new Set(references.map((r) => r.text));
  const classes = classesOf(references, names);
  return {
    subjectSha256,
    references: references.length,
    unanchoredReferences: references.filter((r) => !r.anchored).length,
    distinctStrings: distinct.size,
    qualifiedStrings: [...distinct].filter((s) => s.includes('::')).length,
    namedFunctions: names.length,
    byConfidence: CONFIDENCES.map((confidence) => ({
      confidence,
      functions: names.filter((n) => n.confidence === confidence).length,
    })),
    referencedOnly: references.filter((r) => r.role === 'referenced-only').length,
    names: [...names].sort((a, b) => a.va - b.va),
    withheld: [...withheld].sort((a, b) => a.va - b.va),
    classes,
    surface: corroborate(classes),
  };
};

