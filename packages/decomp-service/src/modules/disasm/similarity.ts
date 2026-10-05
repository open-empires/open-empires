/**
 * Sequence similarity on the same measure Python's `difflib.SequenceMatcher`
 * reports, because the sibling ranking this project already relies on was
 * tuned against that number and a different one would silently reorder it.
 *
 * The ratio is 2*M/(len(a)+len(b)), where M is the total length of the
 * matching blocks the recursive longest-match search finds. Two details
 * change the answer and are therefore reproduced exactly:
 *
 *   - the search is greedy and recursive: the longest match splits the range,
 *     and each side is searched independently
 *   - for a sequence of 200 elements or more, any element occurring in more
 *     than 1% of `b` is dropped from the index, so it can extend a match but
 *     can never start one
 */

const AUTOJUNK_MIN_LENGTH = 200;

/** Indices of each element of `b`, ascending, with popular elements dropped. */
const indexElements = (b: ReadonlyArray<string>): Map<string, number[]> => {
  const b2j = new Map<string, number[]>();
  for (let j = 0; j < b.length; j += 1) {
    const elt = b[j]!;
    const at = b2j.get(elt);
    if (at === undefined) b2j.set(elt, [j]);
    else at.push(j);
  }
  if (b.length >= AUTOJUNK_MIN_LENGTH) {
    const threshold = Math.floor(b.length / 100) + 1;
    for (const [elt, at] of [...b2j]) {
      if (at.length > threshold) b2j.delete(elt);
    }
  }
  return b2j;
};

interface Match {
  readonly ai: number;
  readonly bj: number;
  readonly size: number;
}

const longestMatch = (
  a: ReadonlyArray<string>,
  b: ReadonlyArray<string>,
  b2j: Map<string, number[]>,
  alo: number,
  ahi: number,
  blo: number,
  bhi: number,
): Match => {
  let besti = alo;
  let bestj = blo;
  let bestsize = 0;
  let runs = new Map<number, number>();
  for (let i = alo; i < ahi; i += 1) {
    const next = new Map<number, number>();
    for (const j of b2j.get(a[i]!) ?? []) {
      if (j < blo) continue;
      if (j >= bhi) break;
      const k = (runs.get(j - 1) ?? 0) + 1;
      next.set(j, k);
      if (k > bestsize) {
        besti = i - k + 1;
        bestj = j - k + 1;
        bestsize = k;
      }
    }
    runs = next;
  }
  // A popular element is absent from the index but may still sit inside a
  // match, so the block is extended over equal elements in both directions.
  while (besti > alo && bestj > blo && a[besti - 1] === b[bestj - 1]) {
    besti -= 1;
    bestj -= 1;
    bestsize += 1;
  }
  while (
    besti + bestsize < ahi &&
    bestj + bestsize < bhi &&
    a[besti + bestsize] === b[bestj + bestsize]
  ) {
    bestsize += 1;
  }
  return { ai: besti, bj: bestj, size: bestsize };
};

/** Total length of the matching blocks. The published ratio only needs the
 *  sum, and merging adjacent blocks -- which the reference does before
 *  returning them -- cannot change it. */
const matchingSize = (a: ReadonlyArray<string>, b: ReadonlyArray<string>): number => {
  const b2j = indexElements(b);
  const queue: Array<[number, number, number, number]> = [[0, a.length, 0, b.length]];
  let total = 0;
  while (queue.length > 0) {
    const [alo, ahi, blo, bhi] = queue.pop()!;
    const { ai, bj, size } = longestMatch(a, b, b2j, alo, ahi, blo, bhi);
    if (size === 0) continue;
    total += size;
    if (alo < ai && blo < bj) queue.push([alo, ai, blo, bj]);
    if (ai + size < ahi && bj + size < bhi) queue.push([ai + size, ahi, bj + size, bhi]);
  }
  return total;
};

/** Similarity of two strings, compared character by character, in [0, 1]. */
export const matchRatio = (a: string, b: string): number => {
  const total = a.length + b.length;
  if (total === 0) return 1;
  return (2 * matchingSize([...a], [...b])) / total;
};
