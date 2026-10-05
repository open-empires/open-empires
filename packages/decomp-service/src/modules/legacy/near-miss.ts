import { Option } from 'effect';

/**
 * The header of a `wip/` reconstruction, read back.
 *
 * The agent guide asks for "a header naming what differs and what you
 * eliminated" and fixes no format, so 82 authors wrote 82 shapes. Two of the
 * three columns can therefore only be filled where the author used an explicit
 * label, and the whole header is kept verbatim so a header this cannot parse
 * loses nothing.
 *
 * Nothing here infers a class from prose. Reading "register allocation
 * differs" and writing `blocked_class = 'register allocation'` would make the
 * column hold a classification nobody made, which is worse than a null: a null
 * asks the question, a guess answers it wrongly and is indistinguishable from
 * a real answer afterwards.
 */
export interface NearMissHeader {
  /**
   * The author's own `Class:` label. The guide asks agents to name the class
   * of blocker; only an explicit label proves one was named.
   */
  readonly blockedClass: Option.Option<string>;
  /** What the author reports having ruled out, from the label to the end of
   *  the header. */
  readonly eliminated: Option.Option<string>;
  /** The whole header, verbatim, comment markers and all. */
  readonly note: string;
}

/** `Class: shared-tail with a value in each arm` -- the explicit label. */
const CLASS_LABEL = /(?:^|[\s(])class:[ \t]*([^\n]+)/i;

/**
 * Where an elimination list starts. The wording varies -- "Ruled out",
 * "Eliminated", "swept", "Tried:" -- and all of them introduce the same thing:
 * the spellings the author compiled and rejected.
 */
const ELIMINATION_LABEL = /(?:^|[\s(*\-|])(ruled out|eliminat\w*|swept|tried)\b/i;

/** The leading run of `//` lines. The header ends at the first line of code. */
const headerOf = (source: string): string => {
  const lines = source.split('\n');
  let end = 0;
  while (end < lines.length && lines[end]!.trimStart().startsWith('//')) end += 1;
  return lines.slice(0, end).join('\n');
};

const trimmed = (text: string): Option.Option<string> => {
  const value = text.trim().replace(/[\s.,;:]+$/, '');
  return value === '' ? Option.none() : Option.some(value);
};

export const parseNearMissHeader = (source: string): NearMissHeader => {
  const note = headerOf(source);
  const classMatch = CLASS_LABEL.exec(note);
  const elimination = ELIMINATION_LABEL.exec(note);
  return {
    blockedClass: classMatch === undefined || classMatch === null
      ? Option.none()
      : trimmed(classMatch[1] ?? ''),
    // From the label onwards: the list runs to the end of the header, often
    // over many lines, and cutting it at the first newline would keep the word
    // "Eliminated" and drop everything it introduces.
    eliminated: elimination === undefined || elimination === null
      ? Option.none()
      : trimmed(note.slice(elimination.index)),
    note,
  };
};
