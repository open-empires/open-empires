import { coarseShape, compareOffsets, shape, thisOffsets } from './fingerprint';
import { functionName, renderBatchInstruction } from './listing';
import type { Batch, BatchEntry, BatchPlan, BatchRound, Instruction } from './interface';

/**
 * Assigning work so none of it is done twice.
 *
 * Three sources of duplicated effort, each addressed here:
 *
 * AGENTS COLLIDING. A round's contents are fixed when it is cut and never
 * rewritten. Batch files regenerated while earlier agents were still reading
 * them had two agents reconstruct the same six functions.
 *
 * REDISCOVERING THE SAME SHAPE. Functions are clustered by their disassembly
 * with every constant replaced by K, so one agent sees all the variants of a
 * shape at once and writes them as a family. Measured: 2,860 functions fall
 * into 2,140 shapes, so reuse ACROSS rounds is nearly worthless -- the win is
 * grouping within one round, where the largest clusters held 30, 29 and 18.
 *
 * REDISCOVERING THE SAME OBJECT. Several agents independently worked out the
 * same struct offsets, so the singletons that remain are grouped by the `this`
 * offsets they touch and one agent owns one object's layout.
 *
 * Pure: the caller decodes, stores the round, and delivers the text.
 */

export interface Candidate {
  readonly va: number;
  readonly size: number;
  readonly instructions: ReadonlyArray<Instruction>;
}

export interface PlanInput {
  readonly roundId: string;
  readonly agentCount: number;
  readonly budgetBytes: number;
  readonly clusterCap: number;
  /** Unclaimed functions that decode cleanly, in inventory order. */
  readonly candidates: ReadonlyArray<Candidate>;
  readonly skipped: BatchPlan['skipped'];
  /** Every address withheld from this plan: settled, or owned by a live
   *  round. */
  readonly claimed: ReadonlySet<number>;
  readonly settled: ReadonlySet<number>;
  readonly liveVas: ReadonlySet<number>;
  readonly rounds: ReadonlyArray<BatchRound>;
}

/** How many functions of THIS size fit one agent's budget. */
const capFor = (group: ReadonlyArray<Candidate>, budget: number, clusterCap: number): number => {
  const sizes = group.map((c) => c.size).sort((a, b) => a - b);
  const median = sizes[Math.floor(group.length / 2)]!;
  return Math.max(1, Math.min(clusterCap, Math.floor(budget / Math.max(1, median))));
};

const groupBy = (
  items: ReadonlyArray<Candidate>,
  key: (c: Candidate) => string,
): Array<Array<Candidate>> => {
  const by = new Map<string, Array<Candidate>>();
  for (const c of items) {
    const k = key(c);
    const at = by.get(k);
    if (at === undefined) by.set(k, [c]);
    else at.push(c);
  }
  return [...by.values()];
};

/** Descending by group size. Stable, so the same inventory always produces the
 *  same plan. */
const biggestFirst = (groups: Array<Array<Candidate>>): Array<Array<Candidate>> =>
  [...groups].sort((a, b) => b.length - a.length);

/**
 * True when every function in a round is settled or has left the inventory.
 *
 * An address no longer in the inventory was dropped or renamed by an
 * inventory correction, so it can never be "solved" under its old name and
 * must not pin its round open. A round held open by one function that
 * resisted kept that address claimed for good.
 */
const roundIsComplete = (
  vas: ReadonlyArray<number>,
  settled: ReadonlySet<number>,
  live: ReadonlySet<number>,
): boolean => vas.every((va) => settled.has(va) || !live.has(va));

const renderBatch = (
  roundId: string,
  index: number,
  members: ReadonlyArray<Candidate>,
  padded: ReadonlySet<number>,
): { entries: ReadonlyArray<BatchEntry>; text: string } => {
  const lines: string[] = [
    `THIS IS ${roundId}/batch${index} -- the only batch you may work on.`,
    `It holds ${members.length} functions. Report back on exactly these.`,
    '',
  ];
  const shapesHere = new Set(members.map((c) => shape(c.instructions)));
  if (shapesHere.size < members.length) {
    lines.push('NOTE: several of these share one shape -- solve it once,');
    lines.push('then write the variants by changing only the offsets.\n');
  }
  const entries: BatchEntry[] = [];
  let firstPad = true;
  for (const c of members) {
    const isPad = padded.has(c.va);
    if (isPad && firstPad) {
      firstPad = false;
      lines.push('-- below here: unrelated one-off shapes, no family --\n');
    }
    const offs = thisOffsets(c.instructions);
    entries.push({ va: c.va, size: c.size, thisOffsets: offs, padding: isPad });
    lines.push(
      `${functionName(c.va)}  (${c.size} bytes)` +
        (offs.length > 0
          ? `   this-> offsets: ${offs.map((o) => `0x${o.toString(16)}`).join(', ')}`
          : ''),
    );
    for (const i of c.instructions) lines.push(renderBatchInstruction(i));
    lines.push('');
  }
  return { entries, text: lines.join('\n') };
};

export const planBatches = (input: PlanInput): BatchPlan => {
  const { budgetBytes, clusterCap, agentCount, roundId } = input;

  // Cluster on the exact shape key, biggest family first: one agent writes the
  // whole family.
  const exact = biggestFirst(groupBy(input.candidates, (c) => shape(c.instructions)));
  // Singletons under the exact key are re-clustered on mnemonics alone, so a
  // near-family still reaches one agent. An agent given three "one-offs"
  // reported they shared a shape tighter than most labelled families.
  const coarse = biggestFirst(
    groupBy(
      exact.filter((g) => g.length === 1).map((g) => g[0]!),
      (c) => coarseShape(c.instructions),
    ),
  );
  const ordered = [
    ...exact.filter((g) => g.length > 1),
    ...coarse.filter((g) => g.length > 1),
  ].sort((a, b) => b.length - a.length);
  const singles = coarse.filter((g) => g.length === 1).map((g) => g[0]!);
  singles.sort((x, y) => {
    const byOffsets = compareOffsets(thisOffsets(x.instructions), thisOffsets(y.instructions));
    return byOffsets !== 0 ? byOffsets : x.va - y.va;
  });

  // A cluster is its own batch, up to the cap. Filling batches to a fixed
  // size instead split clusters across batches, and three agents separately
  // derived the same 93-byte exception-frame constructor from scratch.
  const batches: Array<Array<Candidate>> = [];
  for (const group of ordered) {
    if (batches.length >= agentCount) break;
    const cap = capFor(group, budgetBytes, clusterCap);
    for (let k = 0; k < group.length; k += cap) {
      if (batches.length >= agentCount) break;
      batches.push(group.slice(k, k + cap));
    }
  }

  /** Pull singletons until the byte budget is spent, always at least one. */
  const take = (budget: number): Array<Candidate> => {
    const out: Array<Candidate> = [];
    let spent = 0;
    while (singles.length > 0 && (out.length === 0 || spent + singles[0]!.size <= budget)) {
      const next = singles.shift()!;
      out.push(next);
      spent += next.size;
    }
    return out;
  };

  // A cluster of 5 does not fill an agent, and clusters are mostly small, so
  // each batch is padded with singletons -- grouped by shared `this` offsets,
  // so the padding is itself one object's methods where possible -- and
  // labelled in the text so the agent knows which part is a family.
  const padded = new Set<number>();
  for (const batch of batches) {
    const left = budgetBytes - batch.reduce((n, c) => n + c.size, 0);
    if (left <= 0 || singles.length === 0) continue;
    for (const c of take(left)) {
      padded.add(c.va);
      batch.push(c);
    }
  }
  while (batches.length < agentCount && singles.length > 0) batches.push(take(budgetBytes));

  return {
    batches: batches.map((members, index): Batch => {
      const { entries, text } = renderBatch(roundId, index, members, padded);
      const shapes = new Map<string, number>();
      for (const c of members) {
        const k = shape(c.instructions);
        shapes.set(k, (shapes.get(k) ?? 0) + 1);
      }
      let inFamilies = 0;
      for (const n of shapes.values()) if (n > 1) inFamilies += n;
      return {
        index,
        entries,
        text,
        inFamilies,
        maxBytes: members.reduce((n, c) => Math.max(n, c.size), 0),
        distinctShapes: shapes.size,
      };
    }),
    excluded: input.claimed.size,
    retirableRounds: input.rounds
      .filter((r) => roundIsComplete(r.vas, input.settled, input.liveVas))
      .map((r) => r.id),
    skipped: input.skipped,
  };
};
