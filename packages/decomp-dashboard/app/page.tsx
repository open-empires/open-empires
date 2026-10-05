'use client';

/** The decomp service. It owns the database, the compiler and the queue;
 *  this page is a pure client of it. */
const SERVICE = process.env.NEXT_PUBLIC_SERVICE ?? 'http://127.0.0.1:8787';

import { useEffect, useState } from 'react';

/* ------------------------------------------------------------------ types */

interface Counted { key: string; n: number }
interface OptionLike<T> { _tag: 'Some' | 'None'; value?: T }

interface Status {
  now: number;
  phase2: {
    inventory: number; proven: number; near: number; open: number;
    bytesProven: number; textSpan: number; pctText: number;
    weak: number; crt: number; reconstructions: number; superseded: number;
  };
  gate: OptionLike<{ id: number; at: number; exact: number; bytesExact: number }>;
  composition: OptionLike<{
    runId: number; placed: number; placedBytes: number;
    maskedBytes: number; diffBytes: number; spanBytes: number;
  }>;
  blocked: Counted[];
  progress: { at: number; proven: number; bytes: number }[];
  queue: { depth: number; claimed: number };
  globals: {
    globals: number; references: number; sized: number; named: number;
    holdsKnown: number;
    pointers: { target: string; enumerated: number; attributed: number }[];
    byEvidence: { evidence: string; globals: number }[];
  };
  blockers: {
    parked: { cause: string; functions: number; bytes: number }[];
    parkedWithoutCause: number;
    unfoundCodeBytes: number;
    unfoundCodeStretches: number;
    undecodableEntries: number;
    unansweredImportSlots: number;
    importSlotsTotal: number;
    unattributedDataPointers: number;
    dataPointersTotal: number;
    strandedLiterals: number;
    strandedInFunctions: number;
  };
  /** Prose, written by whoever is working. Null until the first note. */
  workingOn: { note: string; updatedAt: number } | null;
  inventory: {
    audit: OptionLike<{
      at: number; entries: number; workable: number;
      undecodable: number; undecodableProven: number; repaired: number;
    }>;
    rejected: number;
    gaps: OptionLike<{
      at: number; textBytes: number; coveredBytes: number;
      paddingBytes: number; residueGaps: number; residueBytes: number;
    }>;
    byEvidence: { evidence: string; functions: number; proven: number }[];
  };
  imports: {
    slots: number; byResolution: Counted[]; bindings: number;
    bindingsVerified: number; distinctApis: number; byDll: Counted[];
  };
  symbols: { named: number; classes: number; byConfidence: Counted[] };
  port: Counted[];
  /**
   * PLAIN values, not Option wrappers.
   *
   * The service encodes these with `Schema.OptionFromNullOr`, which puts the
   * value or null straight on the wire -- unlike `gate` or `composition`,
   * which arrive as `{_tag: 'Some', value}`. Typing them as the wrapper made
   * `some()` return undefined for every one, so the agents table showed a dash
   * in the "doing" column while the agents were reporting perfectly well. Two
   * shapes reach this page and only one of them is an Option.
   */
  agents: {
    id: string; role: string | null; started: number; beats: number;
    state: 'live' | 'gone' | 'finished'; silentFor: number | null;
    note: string | null;
    doing: string | null;
    doingAt: number | null;
  }[];
}

const some = <T,>(o: OptionLike<T> | undefined): T | undefined =>
  o && o._tag === 'Some' ? o.value : undefined;

const f = (n: number | undefined) =>
  n == null ? '—' : Math.round(n).toLocaleString();

const ago = (t: number | undefined) => {
  if (!t) return 'never';
  const s = Math.max(0, Date.now() / 1000 - t);
  if (s < 60) return `${Math.round(s)}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${(s / 3600).toFixed(1)}h ago`;
  return `${(s / 86400).toFixed(1)}d ago`;
};

const pick = (rows: Counted[], key: string) =>
  rows.find((r) => r.key === key)?.n ?? 0;

/* ----------------------------------------------------------- presentation */

/** The evidence names are how the service records them; these are the English. */
const evidenceLabel = (k: string): string =>
  k === 'pre-existing'
    ? 'found before this system existed'
    : k === 'data-pointer'
      ? 'found via a table of function addresses'
      : k === 'proven-call'
        ? 'found by a call inside a rebuilt function'
        : k === 'decoded-call'
          ? 'found by a call inside an unrebuilt function'
          : k;

const evidenceExplain = (k: string): string =>
  k === 'pre-existing'
    ? 'Carried over from the earlier scripts, which is why some of their lengths are wrong.'
    : k === 'data-pointer'
      ? 'The game keeps tables of function addresses so it can call one of several versions of the same operation. An address sitting in such a table is a function start, whatever its first instruction looks like.'
      : k === 'proven-call'
        ? 'The strongest evidence there is: we have already rebuilt the surrounding function byte-for-byte, so the instruction making this call is a fact about verified bytes rather than a guess about where instructions begin.'
        : k === 'decoded-call'
          ? 'A call instruction inside a function we have not rebuilt yet, so it depends on having read the instruction boundaries correctly.'
          : '';

/**
 * The note is rewritten about every 30 minutes while work is going on, so
 * anything past 45 is behind. Marked rather than hidden: a stale note that
 * reads as current is worse than no note, and the mark is also the only thing
 * that makes a lapse in the cadence visible to the person writing it.
 */
const noteIsStale = (updatedAt: number): boolean =>
  Date.now() / 1000 - updatedAt > 45 * 60;

/**
 * The clock time, then how long ago in parentheses.
 *
 * "2m ago" alone cannot be checked against anything: a reader who comes back
 * to the page later has no way to tell whether they are looking at a fresh
 * render or a stale tab. The wall-clock time is the fact; the relative form
 * is the convenience.
 */
const stampedAgo = (at: number): string => {
  const when = new Date(at * 1000).toLocaleTimeString([], {
    hour: 'numeric',
    minute: '2-digit',
    timeZoneName: 'short',
  });
  return `${when} (${ago(at)})`;
};

/** A percentage from the newest gap scan, or a dash before the first one. */
const gapPct = <T,>(o: OptionLike<T> | undefined, pick: (g: T) => number): string => {
  const g = some(o);
  return g === undefined ? '—' : pick(g).toFixed(2);
};

function Card({
  label, value, prov, stale,
}: { label: string; value: string; prov?: string; stale?: boolean }) {
  return (
    <div className="card">
      <div className="lbl">{label}</div>
      <div className="big">{value}</div>
      {prov ? <div className={stale ? 'prov stale' : 'prov'}>{prov}</div> : null}
    </div>
  );
}

function Section({
  title, explain, children,
}: { title: string; explain: React.ReactNode; children: React.ReactNode }) {
  return (
    <section>
      <h2>{title}</h2>
      <p className="explain">{explain}</p>
      {children}
    </section>
  );
}

function Chart({ series }: { series: Status['progress'] }) {
  const pts = series.filter((p) => p.proven > 0);
  if (pts.length < 2) {
    return (
      <div className="chartwrap">
        <div className="empty">
          Not enough history yet. The line fills in as functions are accepted.
        </div>
      </div>
    );
  }
  const W = 940, H = 230, P = { t: 12, r: 14, b: 26, l: 60 };
  const xs = pts.map((p) => p.at);
  const ys = pts.map((p) => p.proven);
  const x0 = Math.min(...xs), x1 = Math.max(...xs);
  const lo = Math.min(...ys), hi = Math.max(...ys);
  const y0 = Math.max(0, lo - (hi - lo) * 0.15 - 1);
  const y1 = hi + (hi - lo) * 0.12 + 1;
  const X = (t: number) => P.l + ((t - x0) / Math.max(1, x1 - x0)) * (W - P.l - P.r);
  const Y = (v: number) => H - P.b - ((v - y0) / Math.max(1, y1 - y0)) * (H - P.t - P.b);

  const grid = [0, 1, 2, 3, 4].map((i) => {
    const v = y0 + ((y1 - y0) * i) / 4;
    return (
      <g key={`g${i}`}>
        <line x1={P.l} x2={W - P.r} y1={Y(v)} y2={Y(v)} stroke="var(--line)" />
        <text x={P.l - 8} y={Y(v) + 3.5} textAnchor="end" fontSize="9.5" fill="var(--dim)">
          {f(v)}
        </text>
      </g>
    );
  });
  const ticks = [0, 1, 2, 3, 4].map((i) => {
    const t = x0 + ((x1 - x0) * i) / 4;
    return (
      <text key={`t${i}`} x={X(t)} y={H - P.b + 15} textAnchor="middle"
            fontSize="9.5" fill="var(--dim)">
        {new Date(t * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
      </text>
    );
  });
  const d = pts
    .map((p, i) => `${i === 0 ? 'M' : 'L'}${X(p.at)},${Y(p.proven)}`)
    .join(' ');
  const last = pts[pts.length - 1]!;
  const area = `${d} L${X(last.at)},${H - P.b} L${X(pts[0]!.at)},${H - P.b} Z`;

  return (
    <div className="chartwrap">
      <svg viewBox={`0 0 ${W} ${H}`} role="img"
           aria-label="functions proven byte-exact over time">
        {grid}
        {ticks}
        <path d={area} fill="var(--ok)" opacity="0.08" />
        <path d={d} fill="none" stroke="var(--ok)" strokeWidth="1.8" strokeLinejoin="round" />
        <circle cx={X(last.at)} cy={Y(last.proven)} r="3" fill="var(--ok)" />
      </svg>
      <div className="legend">
        <span><i style={{ background: 'var(--ok)' }} />
          functions proven byte-exact — {f(last.proven)}</span>
        <span className="mut">
          derived from each function&apos;s own solved-at timestamp, not sampled
        </span>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------- the page */

export default function Page() {
  const [s, setS] = useState<Status | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        // This page holds no database and computes nothing. Every figure is
        // a query the service already answered.
        const r = await fetch(`${SERVICE}/api/status`, { cache: 'no-store' });
        if (!r.ok) throw new Error(`status ${r.status}`);
        const j = (await r.json()) as Status;
        if (alive) { setS(j); setErr(null); }
      } catch (e) {
        if (alive) setErr(e instanceof Error ? e.message : String(e));
      }
    };
    void tick();
    const h = setInterval(() => void tick(), 5000);
    return () => { alive = false; clearInterval(h); };
  }, []);

  if (err && !s) return <div className="wrap"><p className="explain">Cannot reach the service — {err}</p></div>;
  if (!s) return <div className="wrap"><p className="explain">Loading…</p></div>;

  const gate = some(s.gate);
  const gateStale = gate ? Date.now() / 1000 - gate.at > 1800 : true;
  const live = s.agents.filter((a) => a.state === 'live').length;
  const gone = s.agents.filter((a) => a.state === 'gone').length;
  
  return (
    <div className="wrap">
      <header>
        <h1>open-empires · decompilation</h1>
        <span className={live > 0 ? 'pill live' : 'pill'}>
          {live > 0 ? `${live} agent${live === 1 ? '' : 's'} working` : 'no agents working'}
        </span>
        <span className={gateStale ? 'pill stale' : 'pill'}>
          proof last run {ago(gate?.at)}
        </span>
      </header>
      <p className="sub">
        {f(s.phase2.inventory)} functions in the game · refreshed{' '}
        {new Date().toLocaleTimeString()}
      </p>

      <Section
        title="What this is"
        explain={
          <>
            Age of Empires II shipped in 1999 as a Windows program — machine code, with
            the original source long gone. This project is rebuilding that source and
            making it run in a browser. <strong>The test for &quot;correct&quot; is not
            that the code looks right: it is that compiling our C++ with the same
            compiler Microsoft shipped in 1998 produces byte-for-byte the same machine
            code as the real game.</strong> Everything below is measured against that
            test.
          </>
        }
      >
        <Chart series={s.progress} />
      </Section>

      <Section
        title="Currently working on"
        explain={
          <>
            Every number on this page is derived from evidence, which is what makes
            them trustworthy and also what makes them silent about intent: a count of
            rebuilt functions cannot tell you why the work queue was reordered this
            morning, or what is blocking the next step.{' '}
            <strong>This is the part a person writes.</strong> If the timestamp below
            is old, treat the text as history rather than as the current state.
          </>
        }
      >
        {s.workingOn === null ? (
          <p className="explain">
            Nothing has been written yet. It is set through the service, not edited
            here, so this page stays a view of recorded facts rather than a place
            anything is stored.
          </p>
        ) : (
          <div className="note">
            <div className={noteIsStale(s.workingOn.updatedAt) ? 'prov stale' : 'prov'}>
              last updated {stampedAgo(s.workingOn.updatedAt)}
              {noteIsStale(s.workingOn.updatedAt)
                ? ' — behind the half-hourly cadence, so it may no longer describe what is happening'
                : ''}
            </div>
            {s.workingOn.note.split(/\n\s*\n/).map((para, i) => (
              <p key={i} className="notepara">
                {para}
              </p>
            ))}
          </div>
        )}
      </Section>

      <Section
        title="Risks, blockers and bottlenecks"
        explain={
          <>
            Every other figure on this page says what has been achieved. These say
            what has not, and why, which is the only thing that decides what to do
            next. Each carries the size of what it holds up, because{' '}
            <strong>a blocker sitting on a quarter of a megabyte of the game and one
            sitting on a hundred bytes are not the same problem</strong>, however
            alike they read. All of it is counted from the record rather than
            written by hand, so none of it can quietly go out of date.
          </>
        }
      >
        <div className="grid">
          <Card
            label="code we cannot find"
            value={f(s.blockers.unfoundCodeBytes)}
            stale={s.blockers.unfoundCodeBytes > 0}
            prov={`bytes, in ${f(s.blockers.unfoundCodeStretches)} stretches between known routines. Every way we have of finding routines follows a reference from somewhere else, so a routine nothing refers to cannot be found at all. Needs a different method, not more of the same`}
          />
          <Card
            label="Windows calls still unnamed"
            value={`${f(s.blockers.unansweredImportSlots)} / ${f(s.blockers.importSlotsTotal)}`}
            stale={s.blockers.unansweredImportSlots > 0}
            prov="slots the copy protection has never filled in, because the game has not called through them in any recording we have taken. Playing further no longer reaches them — they are error and edge paths, so they must be read out of the code that calls them"
          />
          <Card
            label="stored pointers unresolved"
            value={`${f(s.blockers.unattributedDataPointers)} / ${f(s.blockers.dataPointersTotal)}`}
            stale={s.blockers.unattributedDataPointers > 0}
            prov="pointers inside the game's data that we cannot yet place inside a variable of known extent. The browser build has to resolve every one. This only closes as more routines are rebuilt — there is no shortcut"
          />
          <Card
            label="addresses the browser build cannot resolve"
            value={f(s.blockers.strandedLiterals)}
            stale={s.blockers.strandedLiterals > 0}
            prov={`in ${f(s.blockers.strandedInFunctions)} rebuilt routines. The original refers to its variables by bare address; the browser version rewrites each into an offset inside the loaded data. These are the ones the rewrite does not catch, and each would read memory that does not exist there`}
          />
          <Card
            label="routines nobody can read"
            value={f(s.blockers.undecodableEntries)}
            stale={s.blockers.undecodableEntries > 0}
            prov="entries whose recorded length does not decode, so whoever picks one up gets no readable body. Each is either a length that cuts an instruction in half or a routine ending in a switch table"
          />
        </div>

        <p className="explain">
          Routines that were attempted, got close, and were set aside — grouped by
          what stopped them, largest first by how much of the game they hold. A
          cause shared by several is worth solving once:
        </p>
        <table style={{ marginTop: 10 }}>
          <tbody>
            <tr>
              <th>what stopped it</th>
              <th className="r">routines</th>
              <th className="r">bytes</th>
            </tr>
            {s.blockers.parked.slice(0, 8).map((b) => (
              <tr key={b.cause}>
                <td className="mut">{b.cause}</td>
                <td className="r">{f(b.functions)}</td>
                <td className="r">{f(b.bytes)}</td>
              </tr>
            ))}
            {s.blockers.parkedWithoutCause > 0 ? (
              <tr>
                <td className="mut stale">
                  set aside with no stated cause — cannot be grouped, so invisible to
                  any decision about what to fix
                </td>
                <td className="r">{f(s.blockers.parkedWithoutCause)}</td>
                <td className="r">—</td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </Section>

      <Section
        title="Phase 2 · Recovering the source"
        explain={
          <>
            Each of the game&apos;s {f(s.phase2.inventory)} functions has to be
            written back out as C++. A function counts only when MSVC 6.0 —
            the compiler Microsoft shipped in 1998 — turns that source into
            the <strong>exact same bytes</strong> as the shipped game. So these
            are proofs, not estimates, and a function either passes or does
            not.{' '}
            <strong>Two things the test cannot check</strong>, both tracked
            below: addresses the linker fills in are skipped, and where several
            different ways of writing the source compile to identical bytes,
            the bytes cannot say which one the authors wrote.
          </>
        }      >
        <div className="grid">
          <Card label="proven byte-exact" value={f(s.phase2.proven)}
                prov={`the compiler reproduced these exactly, last answered ${ago(gate?.at)}`}
                stale={gateStale} />
          <Card label="of the game covered" value={`${s.phase2.pctText.toFixed(2)}%`}
                prov={`${f(s.phase2.bytesProven)} of ${f(s.phase2.textSpan)} bytes of executable code. Measured in BYTES, not functions — the remaining functions are on average much larger`} />
          <Card label="near-misses" value={f(s.phase2.near)}
                prov="the logic is understood and the program would behave identically; the compiler just arranged a few bytes differently. Each one records exactly which bytes and what was already ruled out" />
          <Card label="still untouched" value={f(s.phase2.open)}
                prov="no source attempted yet. This is the queue agents draw from" />
          <Card label="written by hand" value={f(s.phase2.reconstructions)}
                prov={`C++ someone actually wrote. The other ${f(s.phase2.crt)} were identified by matching Microsoft's own 1998 library, so they needed no reconstruction`} />
          <Card label="retired proofs" value={f(s.phase2.superseded)}
                prov="were accepted once but no longer count, because the compiler or the binary they were checked against changed. Shown rather than hidden: a shrinking count after a toolchain change is correct" />
          <Card label="weakly verified" value={f(s.phase2.weak)}
                prov="byte-exact, but over a quarter of their bytes are addresses the linker fills in, which the test must skip. Still proofs — just resting on fewer compared bytes" />
        </div>
      </Section>

      {s.blocked.length > 0 && (
        <Section
          title="Why the near-misses are stuck"
          explain={
            <>
              In these functions we know exactly what the code does — the logic is
              right. What differs is how the compiler arranged its output: which CPU
              register held which value, what order it wrote things in. One wrong
              choice and the bytes no longer match, even though the program would
              behave identically. They are grouped by the reason, because a fix for one
              usually unlocks the rest of its group.
            </>
          }
        >
          <table>
            <tbody>
              <tr><th>reason</th><th className="r">functions</th></tr>
              {s.blocked.map((b) => (
                <tr key={b.key}>
                  <td>{b.key}</td>
                  <td className="r">{b.n}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>
      )}

      <Section
        title="Is the list of functions trustworthy?"
        explain={
          <>
            Before anything can be rebuilt, we need a list of where each function
            starts and how long it is. That list came from several sources over
            months, and some entries are wrong — an address that is not really the
            start of a function, or a length that stops in the middle of an
            instruction. A wrong length is the dangerous kind:{' '}
            <strong>the function then arrives with no readable body at all</strong>,
            and nothing anywhere reports it, so the address simply sits in the queue
            forever. Two functions were stuck that way, recorded 436 and 482 bytes
            short of their real length. These figures are re-measured from the
            game&apos;s own bytes every 15 minutes.
          </>
        }
      >
        <div className="grid">
          <Card
            label="functions we can read"
            value={f(some(s.inventory.audit)?.workable)}
            prov={`of ${f(some(s.inventory.audit)?.entries)} in the list. Their recorded length matches what the bytes actually decode to, so the function can be read and worked on`}
          />
          <Card
            label="functions we cannot read"
            value={f(some(s.inventory.audit)?.undecodable)}
            stale={(some(s.inventory.audit)?.undecodable ?? 0) > 0}
            prov="their recorded length does not decode. Each is either a length that cuts an instruction in half, or a function ending in a switch table, which is data the disassembler cannot read. Until that is settled they are refused rather than handed over as a guess"
          />
          <Card
            label="addresses ruled out"
            value={f(s.inventory.rejected)}
            prov="addresses recorded as NOT the start of a function, each stored with the decode that proves it — one of them is a CPU halt instruction. Kept as a record rather than deleted, because deleting one only means the next pass adds it back"
          />
          <Card
            label="lengths corrected automatically"
            value={f(some(s.inventory.audit)?.repaired)}
            prov="in the most recent pass. Only ever where the stored length already failed to decode, and never for a function already proved, whose length a proof depends on"
          />
        </div>
        <p className="explain">
          And the other half of the question — not whether the functions we have are
          sound, but whether we have found them all. Every method of finding them
          follows a reference: a call from a function we already have, or an address
          sitting in a table.{' '}
          <strong>A function that nothing refers to cannot be found that way at
          all</strong>, however long we keep looking, so the space between known
          functions is measured directly:
        </p>
        <div className="grid">
          <Card
            label="of the code accounted for"
            value={`${gapPct(s.inventory.gaps, (g) => (100 * g.coveredBytes) / g.textBytes)}%`}
            prov="executable bytes that belong to a function we have on the list. The rest is either padding the compiler inserted between functions, or code we have not found"
          />
          <Card
            label="unfound code"
            value={`${gapPct(s.inventory.gaps, (g) => (100 * g.residueBytes) / g.textBytes)}%`}
            stale
            prov={`${f(some(s.inventory.gaps)?.residueBytes)} bytes in ${f(some(s.inventory.gaps)?.residueGaps)} stretches between known functions, holding bytes that are not padding. Their opening bytes are unmistakably the start of a function — one begins with the exact instruction pair Microsoft's compiler emits to set up error handling`}
          />
          <Card
            label="padding between functions"
            value={f(some(s.inventory.gaps)?.paddingBytes)}
            prov="bytes of filler the compiler inserted to align each function. Not missing code — correctly accounted for as nothing"
          />
        </div>
        <p className="explain">
          Those stretches are recorded rather than added to the list, because we can
          see where each one starts and not yet where it ends. The rule that measures
          a function&apos;s length needs the filler that normally follows it, and in a
          dense stretch one function&apos;s last instruction runs straight into the
          next function&apos;s first.{' '}
          <strong>A wrong length is worse than a missing entry</strong> — it reaches
          whoever picks up the work as a function with no readable body.
        </p>
        <p className="explain">
          Where each function in the list came from, and how many of each kind have
          been rebuilt so far:
        </p>
        <div className="grid">
          {s.inventory.byEvidence.map((e) => (
            <Card
              key={e.evidence}
              label={evidenceLabel(e.evidence)}
              value={f(e.functions)}
              prov={`${f(e.proven)} of these have been rebuilt byte-for-byte. ${evidenceExplain(e.evidence)}`}
            />
          ))}
        </div>
      </Section>

      <Section
        title="The data the game keeps"
        explain={
          <>
            Code is only half of it. The game also holds about 1.5MB of
            variables — the player list, the terrain, every unit — and the
            rebuilt code has to refer to the same ones. The original binary does
            not say where any of them start or stop: the compiler turned each
            name into a bare address, and the game is full of bare addresses. So
            we work backwards from how the code uses them.{' '}
            <strong>A pointer stored in that data is the hardest part</strong>:
            the browser build has to resolve each one, and the binary carries no
            list of where they are, so we rebuild that list too.
          </>
        }
      >
        <div className="grid">
          <Card label="variables found" value={f(s.globals.globals)}
                prov={`distinct addresses the code actually reads or writes, from ${f(s.globals.references)} places in the code that touch one`} />
          <Card label="we know how big" value={f(s.globals.sized)}
                prov="their extent is settled — from a library's own symbol table, from the width of every instruction that accesses them, or from the run of pointers they contain. Without a size we cannot tell one variable from the next" />
          <Card label="we know the original name" value={f(s.globals.named)}
                prov="read out of the standard C library's symbol tables, which name their own variables. The game's own names were not kept by the 1999 compiler and cannot be recovered" />
          <Card label="we know what they hold" value={f(s.globals.holdsKnown)}
                prov="a pointer to code, a pointer to data, or a floating-point number — determined from the instructions that use the value, not guessed from the bytes" />
        </div>
        <p className="explain">
          Pointers stored inside the data, and how many we can place inside a
          variable whose extent we have settled. The gap is what the browser
          build still cannot resolve:
        </p>
        <div className="grid">
          {s.globals.pointers.map((p) => (
            <Card
              key={p.target}
              label={p.target === 'code' ? 'pointers to code' : 'pointers to data'}
              value={`${f(p.attributed)} / ${f(p.enumerated)}`}
              stale={p.enumerated > 0 && p.attributed / p.enumerated < 0.5}
              prov={
                p.target === 'code'
                  ? "mostly tables of function addresses, which the game uses to call one of several versions of the same operation. These are well covered because the code that builds them names the table"
                  : "single pointer fields inside larger structures that nothing in the code bounds. Only rebuilding more functions closes this — each new one turns its addresses from a guess into a fact"
              }
            />
          ))}
        </div>
      </Section>

      <Section
        title="Phase 3 · Replacing Windows"
        explain={
          <>
            The game constantly asks Windows to do things — draw to the screen, play a
            sound, open a file. To run in a browser, every one of those calls needs a
            browser-native replacement, so first we have to know which Windows function
            each call actually goes to. The game&apos;s 1999 copy protection deliberately
            scrambled that list, so we rebuild it from a memory dump of the game
            running. <strong>The catch: one entry can serve several different Windows
            functions depending on which part of the game is calling</strong>, so each
            is identified per call site rather than per entry.
          </>
        }
      >
        <div className="grid">
          <Card label="call sites identified" value={f(s.imports.bindings)}
                prov={`places in the game where we know which Windows function is being called. ${f(s.imports.bindingsVerified)} of them cross-checked against the instruction that makes the call`} />
          <Card label="distinct Windows functions" value={f(s.imports.distinctApis)}
                prov="each matched exactly to an entry in a real system library read out of the memory dump — not inferred from how it is used" />
          <Card label="entries with one answer" value={f(pick(s.imports.byResolution, 'export-exact'))}
                prov={`of ${f(s.imports.slots)} entries in the game's import table. These behave normally: one entry, one Windows function`} />
          <Card label="entries serving several" value={f(pick(s.imports.byResolution, 'multiple-apis'))}
                prov="the copy protection routes several different Windows functions through one entry, picking by which part of the game is calling. These can only be resolved per call site" />
          <Card label="not yet observed"
                value={f(pick(s.imports.byResolution, 'no-cached-call-site'))}
                prov="the protection only records an entry once the game actually calls it, and the game had not reached these when the memory dump was taken. Playing further would capture them" />
        </div>
      </Section>

      <Section
        title="Original names"
        explain={
          <>
            Compilers throw away the names programmers write, so recovered code starts
            out as <span className="mut">sub_00448EB0</span> with fields called{' '}
            <span className="mut">f20</span>. Some names survive anyway: the game passes
            its own function names as text to internal bookkeeping code, and that text
            is still in the file. These are the real names its authors used.
          </>
        }
      >
        <div className="grid">
          <Card label="functions with a real name" value={f(s.symbols.named)}
                prov="recovered from text the game itself carries. Every one is attributed to exactly one function; where a name appeared in two places it was withheld rather than guessed" />
          <Card label="real class names" value={f(s.symbols.classes)}
                prov="e.g. diam_map, pnl_lst, scr_game — the words the original authors used, which also tell us how the code was organised" />
          {s.symbols.byConfidence.map((c) => (
            <Card key={c.key} label={c.key.replace(/-/g, ' ')} value={f(c.n)}
                  prov={c.key === 'lock-tag'
                    ? 'the function passes its own name to internal bookkeeping code, which still runs in the shipped build'
                    : 'named through a second, separate bookkeeping call with the same shape'} />
          ))}
        </div>
      </Section>

      <Section
        title="Phase 4 · Running in a browser"
        explain={
          <>
            The recovered source targets a 1998 Windows compiler, which a browser cannot
            use. This step converts it to portable C++ that compiles to WebAssembly.{' '}
            <strong>Refused</strong> files contain hand-written x86 assembly, which has
            no browser equivalent and must be rewritten as ordinary code.{' '}
            <strong>Needs globals</strong> means the function reaches a fixed memory
            address from the original program, so it only works once the game&apos;s data
            is loaded into the right place.
          </>
        }
      >
        <div className="grid">
          {s.port.map((p) => (
            <Card key={p.key} label={p.key.replace(/_/g, ' ')} value={f(p.n)} />
          ))}
        </div>
      </Section>

      <Section
        title="Agents"
        explain={
          <>
            The work is done by AI agents running in parallel. Each one{' '}
            <strong>registers itself when it starts</strong> and checks in every time it
            runs the proof — so a row here means an agent really started, not just that
            one was asked to. If an agent goes quiet for ten minutes we mark it{' '}
            <span className="state-gone">gone</span>: agents run inside another process,
            so silence is the only way to tell that one has died.
          </>
        }
      >
        <div className="grid">
          <Card label="working now" value={f(live)} prov="checked in within 10 minutes" />
          <Card label="finished" value={f(s.agents.filter((a) => a.state === 'finished').length)}
                prov="deregistered cleanly" />
          <Card label="gone" value={f(gone)} prov="stopped checking in without finishing" />
        </div>
        {s.agents.length > 0 && (
          <table style={{ marginTop: 10 }}>
            <tbody>
              <tr>
                <th>agent</th><th>doing</th><th className="r">check-ins</th>
                <th>started</th><th>state</th>
              </tr>
              {s.agents.slice(0, 20).map((a) => (
                <tr key={a.id}>
                  <td>{a.id}</td>
                  <td className="mut">
                    {a.doing ?? a.role ?? '—'}
                    {a.doingAt !== null ? (
                      <span className="prov"> said {ago(a.doingAt)}</span>
                    ) : null}
                  </td>
                  <td className="r">{a.beats}</td>
                  <td className="mut">{ago(a.started)}</td>
                  <td className={`state-${a.state}`}>{a.state}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>

      <Section
        title="Where these numbers come from"
        explain={
          <>
            Everything on this page is a database query. The database holds one row per
            real thing — per function, per Windows call site, per agent — and the figures
            are counted from those rows, so a new question is a new query rather than new
            plumbing. The graph works the same way: each function records when it first
            passed the proof, so progress over time is read from those timestamps instead
            of being sampled, and it spans the whole record rather than a sliding
            window. It begins partway up because the work done before this service
            existed was imported all at once and carries a single timestamp — the
            record genuinely does not know when each of those was finished, and
            spreading them out would be an invention. <strong>One thing this service
            deliberately does not do is
            decide whether a function is correct</strong> — that is settled only by
            compiling it and comparing bytes, and this page reports that verdict rather
            than forming its own.
          </>
        }
      >
        <></>
      </Section>
    </div>
  );
}
