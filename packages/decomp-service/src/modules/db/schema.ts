/**
 * The system of record for the Age of Empires II decompilation.
 *
 * This database IS the project's state, not a view of it. Reconstruction
 * source lives here. Verdicts live here. Nothing is derived from loose files
 * that could be deleted, edited behind the service's back, or left stale.
 *
 * THE RULE THAT SHAPES EVERYTHING BELOW
 * -------------------------------------
 * A proof is only a proof against the thing that proved it. The project has
 * already shipped 6,953 "verified" blocks of which 1,450 were real, because
 * proofs carried no prover identity and nothing retired them when the prover
 * changed. So:
 *
 *   - every verdict names the `gate_run` that produced it
 *   - every `gate_run` names the SUBJECT it compared against and the
 *     TOOLCHAIN that compiled it, both by hash
 *   - a verdict whose toolchain or subject is no longer current is SUPERSEDED,
 *     which is computed, never stored as a flag someone has to remember to set
 *
 * The second rule: a refresh is not a retraction. Re-reading the world must
 * never widen into "everything is unproven until proved again" -- that undoes
 * verification faster than verification can happen. Only a change of prover
 * retracts, and that is expressed by the superseded view, not by UPDATE.
 */

/**
 * One schema change.
 *
 * `verify`, when present, is a query run INSIDE the migration's own
 * transaction after its `sql`. If it does not return what `verifyExpects`
 * says, the transaction rolls back and the migration is not recorded.
 *
 * It exists because "recorded as applied" and "actually did something" turned
 * out to be different claims. Migration 018 updated a parent key that three
 * tables reference while PRAGMA foreign_keys was ON: SQLite silently changed
 * nothing AND raised nothing, so the migration committed, was recorded, and
 * its effect was entirely absent. Nothing could have noticed -- the text
 * matched its stored hash, so the drift check passed too.
 */
export interface Migration {
  readonly id: string;
  readonly sql: string;
  /** A query whose result proves the change landed. */
  readonly verify?: string;
  /** `nonzero` requires the first column of the first row to be non-zero;
   *  `zero` requires it to be zero. */
  readonly verifyExpects?: 'nonzero' | 'zero';
}

export const MIGRATIONS: ReadonlyArray<Migration> = [
  {
    id: '001-core',
    sql: `
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- ---------------------------------------------------------------- identity

-- The binary under reconstruction. Hashed, because every verdict is relative
-- to a specific subject and swapping the subject invalidates all of them.
CREATE TABLE subjects (
    sha256     TEXT PRIMARY KEY,
    path       TEXT NOT NULL,
    size       INTEGER NOT NULL,
    image_base INTEGER NOT NULL,
    text_lo    INTEGER NOT NULL,
    text_hi    INTEGER NOT NULL,
    added_at   REAL NOT NULL
);

-- The compiler that decides byte-exactness. Identified by the hash of cl.exe
-- itself plus the flags, so "the same compiler" is a fact about bytes rather
-- than a version banner anyone can misread.
CREATE TABLE toolchains (
    id         TEXT PRIMARY KEY,      -- sha256(cl.exe) + ':' + flags
    cl_sha256  TEXT NOT NULL,
    flags      TEXT NOT NULL,
    comp_id    TEXT,                  -- @comp.id the compiler stamps in objects
    added_at   REAL NOT NULL
);

-- Exactly one row marks the configuration currently in force. Anything proved
-- under a different one is superseded by computation, not by a stored flag.
CREATE TABLE current_config (
    only_row     INTEGER PRIMARY KEY CHECK (only_row = 1),
    subject_sha  TEXT NOT NULL REFERENCES subjects(sha256),
    toolchain_id TEXT NOT NULL REFERENCES toolchains(id),
    set_at       REAL NOT NULL
);

-- ---------------------------------------------------------------- the work

-- One row per function in the subject. Facts about the BINARY only; nothing
-- about our attempts to reconstruct it.
CREATE TABLE functions (
    subject_sha TEXT NOT NULL REFERENCES subjects(sha256),
    va          INTEGER NOT NULL,
    size        INTEGER NOT NULL,
    discovered_by TEXT,               -- call | rdata-pointer | inventory
    name        TEXT,                 -- recovered original name, if known
    class_name  TEXT,
    name_confidence TEXT,
    PRIMARY KEY (subject_sha, va)
);
CREATE INDEX functions_va ON functions(va);

-- One row per attempt to reconstruct a function. Source lives HERE: the
-- service owns it, so there is no on-disk copy to drift from the verdict.
CREATE TABLE attempts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_sha  TEXT NOT NULL,
    va           INTEGER NOT NULL,
    source       TEXT NOT NULL,
    source_sha   TEXT NOT NULL,       -- dedupes resubmission of identical text
    flags        TEXT NOT NULL,       -- the bucket: /O2 ... or /O1 ...
    author       TEXT,                -- agent id
    created_at   REAL NOT NULL,
    FOREIGN KEY (subject_sha, va) REFERENCES functions(subject_sha, va)
);
CREATE UNIQUE INDEX attempts_dedupe ON attempts(subject_sha, va, source_sha, flags);
CREATE INDEX attempts_fn ON attempts(subject_sha, va);

-- ------------------------------------------------------------- the verdict

-- One row per execution of the gate. The prover's identity.
CREATE TABLE gate_runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_sha  TEXT NOT NULL REFERENCES subjects(sha256),
    toolchain_id TEXT NOT NULL REFERENCES toolchains(id),
    started_at   REAL NOT NULL,
    finished_at  REAL,
    attempted    INTEGER NOT NULL DEFAULT 0,
    exact        INTEGER NOT NULL DEFAULT 0
);

-- One row per (attempt, gate run). A verdict is never updated in place: a new
-- run writes a new row, so the history of what was believed and when is
-- intact and a bad run can be discarded without taking the good ones with it.
CREATE TABLE verdicts (
    attempt_id   INTEGER NOT NULL REFERENCES attempts(id),
    gate_run_id  INTEGER NOT NULL REFERENCES gate_runs(id),
    exact        INTEGER NOT NULL,     -- 1 | 0
    compiled     INTEGER NOT NULL,     -- 0 means it did not build
    emitted_size INTEGER,
    masked       INTEGER,              -- relocation bytes NOT compared
    compared     INTEGER,
    first_diff   INTEGER,              -- byte offset of the first difference
    detail       TEXT,
    decided_at   REAL NOT NULL,
    PRIMARY KEY (attempt_id, gate_run_id)
);
CREATE INDEX verdicts_run ON verdicts(gate_run_id);

-- The one place "is this function proved RIGHT NOW" is answered. A verdict
-- counts only if its gate run used the configuration currently in force --
-- so changing compiler or subject retires every stale proof at once, with no
-- flag to set and nothing to remember.
CREATE VIEW proven AS
SELECT a.subject_sha, a.va, a.id AS attempt_id, a.flags, a.author,
       v.gate_run_id, v.decided_at, v.masked, v.compared,
       f.size
FROM verdicts v
JOIN attempts  a ON a.id = v.attempt_id
JOIN gate_runs g ON g.id = v.gate_run_id
JOIN functions f ON f.subject_sha = a.subject_sha AND f.va = a.va
JOIN current_config c ON c.only_row = 1
WHERE v.exact = 1
  AND g.subject_sha  = c.subject_sha
  AND g.toolchain_id = c.toolchain_id;

-- Proofs that WERE accepted but were made under a configuration no longer in
-- force. Visible on purpose: a shrinking proven count after a toolchain change
-- is correct, and hiding it is how the project shipped proofs from compilers
-- that no longer existed.
CREATE VIEW superseded AS
SELECT a.subject_sha, a.va, v.gate_run_id, g.toolchain_id, g.subject_sha AS proved_against
FROM verdicts v
JOIN attempts  a ON a.id = v.attempt_id
JOIN gate_runs g ON g.id = v.gate_run_id
JOIN current_config c ON c.only_row = 1
WHERE v.exact = 1
  AND (g.subject_sha != c.subject_sha OR g.toolchain_id != c.toolchain_id);

-- When each function FIRST became proved under the current configuration.
-- Progress over time is a query against this, not a sampled counter.
CREATE VIEW solved_at AS
SELECT subject_sha, va, MIN(decided_at) AS at FROM proven GROUP BY subject_sha, va;

-- ----------------------------------------------------------- near-misses

CREATE TABLE near_misses (
    subject_sha   TEXT NOT NULL,
    va            INTEGER NOT NULL,
    attempt_id    INTEGER REFERENCES attempts(id),
    blocked_class TEXT,
    eliminated    TEXT,               -- what the author ruled out
    note          TEXT,
    updated_at    REAL NOT NULL,
    PRIMARY KEY (subject_sha, va)
);

-- ------------------------------------------------------------ phase 3 / 4

CREATE TABLE import_slots (
    subject_sha TEXT NOT NULL,
    slot        INTEGER NOT NULL,
    dll         TEXT,
    target      INTEGER,
    resolution  TEXT,
    name        TEXT,
    PRIMARY KEY (subject_sha, slot)
);
-- An API is keyed by (slot, call site): SafeDisc's dispatcher resolves on the
-- caller's return address, so one slot serves several APIs.
CREATE TABLE import_bindings (
    subject_sha TEXT NOT NULL,
    slot        INTEGER NOT NULL,
    call_site   INTEGER NOT NULL,
    api         TEXT NOT NULL,
    evidence    TEXT NOT NULL,
    PRIMARY KEY (subject_sha, slot, call_site)
);

CREATE TABLE port_files (
    subject_sha TEXT NOT NULL,
    va          INTEGER NOT NULL,
    state       TEXT NOT NULL,        -- converted | refused | needs_globals
    reason      TEXT,
    PRIMARY KEY (subject_sha, va)
);

-- ---------------------------------------------------------------- workers

-- An agent registers itself, so a row means one really started. Silence is
-- the only death signal: agents run inside a host process with no pid to
-- watch.
CREATE TABLE agents (
    id        TEXT PRIMARY KEY,
    role      TEXT,
    started   REAL NOT NULL,
    last_beat REAL NOT NULL,
    beats     INTEGER NOT NULL DEFAULT 0,
    finished  REAL,
    note      TEXT
);

-- A lease, not an assignment: work claimed by an agent that dies must return
-- to the queue by expiring rather than by anyone noticing.
CREATE TABLE claims (
    subject_sha TEXT NOT NULL,
    va          INTEGER NOT NULL,
    agent_id    TEXT NOT NULL REFERENCES agents(id),
    claimed_at  REAL NOT NULL,
    expires_at  REAL NOT NULL,
    released_at REAL,
    PRIMARY KEY (subject_sha, va, agent_id, claimed_at)
);
CREATE INDEX claims_open ON claims(subject_sha, va, released_at, expires_at);
`,
  },
  {
    id: '002-subject-evidence',
    sql: `
-- ------------------------------------------------ what produced the subject

-- One row per @comp.id record in the subject's Rich header: a tool that
-- contributed object files, and how many it contributed. The counts ARE the
-- finding -- 153 and 16 objects from build 8168 against 2 and 304 from 8447 is
-- what established that the game's own code is entirely our compiler's and the
-- 8168 objects are the prebuilt CRT. A table holding only "which compilers"
-- would have lost it. comp_id is the raw dword, so prod_id and build are
-- re-derivable from the stored bytes rather than trusted.
CREATE TABLE subject_comp_ids (
    subject_sha  TEXT NOT NULL REFERENCES subjects(sha256),
    record_index INTEGER NOT NULL,     -- position in the header
    comp_id      INTEGER NOT NULL,
    prod_id      INTEGER NOT NULL,
    build        INTEGER NOT NULL,
    objects      INTEGER NOT NULL,
    PRIMARY KEY (subject_sha, record_index)
);

-- --------------------------------------------- the guest the subject ran in

-- Modules mapped alongside the subject, from the PEB loader list -- the
-- operating system's own record, so a module cannot be missed, counted twice,
-- or given a size guessed from its headers. export_error is why a module
-- publishes no exports here; it is a fact to read, and distinguishing it from
-- "publishes nothing" is the whole point of storing it.
CREATE TABLE guest_modules (
    subject_sha  TEXT NOT NULL REFERENCES subjects(sha256),
    base         INTEGER NOT NULL,
    size         INTEGER NOT NULL,
    path         TEXT NOT NULL,
    name         TEXT NOT NULL,
    export_error TEXT,
    PRIMARY KEY (subject_sha, base)
);

-- Every export directory entry that was actually read. Every recovered import
-- name must be traceable to one of these rows: an address that is not exactly
-- an entry point is never rounded to the nearest name, and the only way to
-- hold anyone to that is to keep the entries the names came from.
CREATE TABLE guest_exports (
    subject_sha TEXT NOT NULL REFERENCES subjects(sha256),
    module_base INTEGER NOT NULL,
    ordinal     INTEGER NOT NULL,
    name        TEXT,                  -- null: published by ordinal only
    va          INTEGER,               -- null: a forwarder has no code here
    forwarder   TEXT,                  -- "OTHERDLL.Name" or "OTHERDLL.#13"
    PRIMARY KEY (subject_sha, module_base, ordinal)
);
CREATE INDEX guest_exports_va ON guest_exports(subject_sha, va);

-- One SafeDisc redirection record per redirected slot. The record is what ties
-- a slot to the dispatcher's tables, so the bindings below have something to
-- be traceable to.
CREATE TABLE safedisc_records (
    subject_sha      TEXT NOT NULL REFERENCES subjects(sha256),
    slot             INTEGER NOT NULL,
    module_index     INTEGER NOT NULL,
    import_index     INTEGER NOT NULL,
    record_va        INTEGER NOT NULL,
    stub_va          INTEGER NOT NULL,
    placeholder      INTEGER NOT NULL, -- the imm32 the dispatcher overwrites
    remapped_index   INTEGER NOT NULL,
    resolved_address INTEGER,          -- null: never written, so never called
    PRIMARY KEY (subject_sha, slot)
);

-- --------------------------------------------------- import map, elaborated

-- What the subject's own descriptor said, and why a slot has no name. A slot
-- that produces nothing must record the reason: "never called before the
-- snapshot" and "resolves to several APIs" are different answers and neither
-- is a gap.
ALTER TABLE import_slots ADD COLUMN descriptor_name TEXT;
ALTER TABLE import_slots ADD COLUMN descriptor_ordinal INTEGER;
ALTER TABLE import_slots ADD COLUMN blocked_by TEXT;

-- import_bindings is rebuilt rather than extended because its api was NOT
-- NULL, which made an unnamed binding unrecordable -- and a binding that
-- cannot be stored is a binding silently dropped. It now keeps the address the
-- name was derived from, the bucket that proves the entry's own hash, the
-- operand that independently corroborates the call site, and the reason when
-- there is no name.
ALTER TABLE import_bindings RENAME TO import_bindings_001;
CREATE TABLE import_bindings (
    subject_sha   TEXT NOT NULL REFERENCES subjects(sha256),
    slot          INTEGER NOT NULL,
    call_site     INTEGER NOT NULL,
    api           TEXT,                -- null: the target is not an export
    evidence      TEXT NOT NULL,
    target        INTEGER NOT NULL,    -- the resolved address, as cached
    bucket        INTEGER NOT NULL,
    call_operand  INTEGER,             -- set only when it names another slot
    blocked_by    TEXT,
    PRIMARY KEY (subject_sha, slot, call_site)
);
INSERT INTO import_bindings(subject_sha, slot, call_site, api, evidence, target, bucket)
SELECT subject_sha, slot, call_site, api, evidence, 0, 0 FROM import_bindings_001;
DROP TABLE import_bindings_001;

-- ------------------------------------------------------- CRT identification

-- A CRT function identified by placing the shipped library's own object in the
-- subject. Stronger than a byte-exact reconstruction: it names the function
-- and says which archive member its bytes came from, rather than showing that
-- source we invented compiles to the same thing. Kept separate from
-- functions.name because an identification is evidence with a source, and most
-- of these addresses are not declared functions at all.
CREATE TABLE crt_identifications (
    subject_sha  TEXT NOT NULL REFERENCES subjects(sha256),
    va           INTEGER NOT NULL,
    symbol       TEXT NOT NULL,
    library      TEXT NOT NULL,
    member       TEXT NOT NULL,
    section_size INTEGER NOT NULL,
    PRIMARY KEY (subject_sha, va)
);
`,
  },
  {
    id: '003-composition',
    sql: `
-- ------------------------------------------------------ the composition proof
--
-- Every other proof in this project is per-function and in isolation: the gate
-- compiles one reconstruction and compares one function's bytes. None of them
-- says the proofs COMPOSE. Assembling the whole executable span -- each proven
-- function from its compiled bytes, the subject's own bytes everywhere nothing
-- is reconstructed -- and diffing the result against the subject is what shows
-- every reconstruction lands AT ITS REAL ADDRESS, with the size the inventory
-- claims, without overlapping its neighbour.
--
-- Stored, not printed. A run that announced "0 bytes differing" and exited left
-- nothing to interrogate: the number could not be attributed, could not be
-- compared against the next run, and could not be shown to have been made
-- against the compiler currently in force. So a run is a row, it names the
-- configuration it was made under, and a NON-ZERO diff stays visible after the
-- process that found it has gone.
CREATE TABLE composition_runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_sha   TEXT NOT NULL REFERENCES subjects(sha256),
    -- The prover, exactly as a verdict names it. A composition made under a
    -- toolchain that is no longer current says nothing about the current one,
    -- and this is what lets that be seen rather than assumed.
    toolchain_id  TEXT NOT NULL REFERENCES toolchains(id),
    started_at    REAL NOT NULL,
    finished_at   REAL,
    -- The span, from the subject's own section header. Recorded so a run can
    -- be shown to have covered the whole of .text and not a literal somebody
    -- wrote down: the Python carried 0x62607D, which is max(va+size) over an
    -- old inventory and 9,216 bytes short of the real end.
    text_lo       INTEGER NOT NULL,
    text_hi       INTEGER NOT NULL,
    -- Reconstructions in force at the time of the run, and how they fared.
    considered    INTEGER NOT NULL,
    placed        INTEGER NOT NULL,   -- compiled bytes written into the image
    not_built     INTEGER NOT NULL,   -- the compiler refused the stored source
    too_short     INTEGER NOT NULL,   -- emitted fewer bytes than the inventory
    outside_span  INTEGER NOT NULL,   -- the function is not inside .text
    disagreeing   INTEGER NOT NULL,   -- placed, and did NOT reproduce
    placed_bytes  INTEGER NOT NULL,
    masked_bytes  INTEGER NOT NULL,   -- relocation fields taken from the original
    -- Inventory entries whose spans intersect. An overlap makes "which
    -- function owns this byte" ambiguous, which is the defect a per-function
    -- comparison cannot see at all.
    overlaps      INTEGER NOT NULL,
    diff_bytes    INTEGER NOT NULL,
    -- Differing bytes inside the span that no contribution accounts for. The
    -- total and the sum of the parts are stored separately on purpose: equal
    -- is the claim, and only storing both can refute it.
    unattributed_diff_bytes INTEGER NOT NULL
);

-- What each reconstruction contributed to one run.
--
-- This is what makes a non-zero diff a diagnosis instead of a number: the
-- function, how many of its bytes disagreed and where the first one was. Byte
-- values are not stored because they are re-derivable by recompiling that one
-- source, and a truncated sample of them would have been the one thing lost.
CREATE TABLE composition_contributions (
    run_id     INTEGER NOT NULL REFERENCES composition_runs(id),
    va         INTEGER NOT NULL,
    attempt_id INTEGER NOT NULL REFERENCES attempts(id),
    -- placed | not-built | too-short | outside-span
    origin     TEXT NOT NULL,
    size       INTEGER NOT NULL,     -- what the inventory claims
    emitted    INTEGER,              -- the emitted function's own length
    masked     INTEGER NOT NULL,
    diff_bytes INTEGER NOT NULL,
    first_diff INTEGER,
    detail     TEXT,
    PRIMARY KEY (run_id, va)
);
CREATE INDEX composition_contributions_diff
    ON composition_contributions(run_id, diff_bytes);

-- The most recent composition made under the configuration in force. Anything
-- older, or made against another subject or compiler, says nothing about the
-- current one -- the same rule the \`proven\` view applies to verdicts.
CREATE VIEW composition_current AS
SELECT r.*
FROM composition_runs r
JOIN current_config c ON c.only_row = 1
WHERE r.subject_sha = c.subject_sha
  AND r.toolchain_id = c.toolchain_id
  AND r.finished_at IS NOT NULL
ORDER BY r.finished_at DESC
LIMIT 1;
`,
  },
  {
    id: '004-recovered-names',
    sql: `
-- ------------------------------------------------- names recovered from text
--
-- The compiler discarded every name the programmers wrote. A few survived
-- anyway, because the game passes its own function names to internal
-- bookkeeping AS TEXT and those strings are still in the image.
--
-- \`functions.name\`, \`class_name\` and \`name_confidence\` already hold the
-- ANSWER for the 50 functions the evidence names. They cannot hold the three
-- things that make the answer checkable, which is what this migration adds.
--
-- THE REFERENCE LIST. 866 instructions in .text push or move the address of an
-- identifier-shaped string. 651 of them are \`referenced-only\`: the containing
-- function merely mentions the string, which does NOT name it. Keeping only
-- the 50 that worked leaves no way to ask why a name was not found, and no way
-- to see that a pattern stopped matching. 0x428190 is \`report(hresult, where)\`
-- and eight of its \`where\` strings look exactly like function names --
-- \`sub_00437200\` passes three of them, so they name the CALL SITE. That
-- finding is a query over these rows and is unreachable without them.
--
-- THE WITHHELD CANDIDATES, WITH THE REASON. A withheld name is evidence, not
-- an absence. \`diam_map::draw_objects\` is the tag at 0x00448F5D and again at
-- 0x005DB5F7, 980 KB away: a string pushed as the tag from two places cannot
-- name both, so it names neither. Thirteen candidates are refused this way,
-- and without the reason beside them the next reader has no way to tell a
-- refusal from a gap -- and every reason to "fix" it by naming one.
--
-- THE CLASS VOCABULARY. 76 of the strings are \`::\`-qualified across 29
-- classes. Five of those classes are known ONLY as method names, with no
-- address attributable to them; the rest carry methods the strings name but
-- the evidence cannot place. Those are facts about the game's class layout and
-- survive nowhere else.
--
-- The vocabulary is VIEWS, not tables. A class name is the part of a string
-- before \`::\` and nothing else: storing it a second time would be a second
-- answer to "which classes are there", free to drift from the references it is
-- read out of.

CREATE TABLE string_references (
    subject_sha   TEXT NOT NULL REFERENCES subjects(sha256),
    -- Address of the referencing instruction.
    site          INTEGER NOT NULL,
    string_va     INTEGER NOT NULL,
    text          TEXT NOT NULL,
    mnemonic      TEXT NOT NULL,
    -- 1 when the site came from an inventory function whose body decodes to
    -- exactly its recorded size, so the instruction boundary is a fact. 0 when
    -- it came from a resynchronising sweep of a region with no known boundary,
    -- where a different starting alignment gives a different answer. This is
    -- the one column that says a row is a reading rather than a fact, and
    -- 138 of the 866 are of that kind.
    anchored      INTEGER NOT NULL,
    -- Null: a .text region the inventory attributes to no function. Such a
    -- reference still counts AGAINST a name, because a tag pushed from an
    -- unattributed region is a second place it is pushed from.
    containing_function INTEGER,
    -- The first direct call reached from the site, which consumes the string,
    -- and how many pushes separate them. arg_index 0 means the string is that
    -- call's first argument, which is what the naming patterns rest on.
    consumer      INTEGER,
    consumed_at   INTEGER,
    arg_index     INTEGER,
    -- The member the consuming call's \`this\` was loaded from, read backwards
    -- from the CALL. This is the corroboration: classes sharing no name
    -- prefix lock a surface at the same member of their own object.
    receiver_at     INTEGER,
    receiver_offset INTEGER,
    receiver_insn   TEXT,
    -- lock-tag | self-named-other | referenced-only
    role          TEXT NOT NULL,
    PRIMARY KEY (subject_sha, site, string_va),
    FOREIGN KEY (subject_sha, containing_function) REFERENCES functions(subject_sha, va)
);
CREATE INDEX string_references_text ON string_references(subject_sha, text);
CREATE INDEX string_references_fn   ON string_references(subject_sha, containing_function);
CREATE INDEX string_references_role ON string_references(subject_sha, role);

-- One row per function whose name the evidence reaches but cannot attribute.
CREATE TABLE withheld_names (
    subject_sha TEXT NOT NULL REFERENCES subjects(sha256),
    va          INTEGER NOT NULL,
    reason      TEXT NOT NULL,
    PRIMARY KEY (subject_sha, va),
    FOREIGN KEY (subject_sha, va) REFERENCES functions(subject_sha, va)
);

-- The names that were on offer. Separate from the reason because the reason
-- belongs to the refusal and the candidates belong to the function: repeating
-- one reason across three candidate rows would be three copies of it.
CREATE TABLE withheld_name_candidates (
    subject_sha TEXT NOT NULL,
    va          INTEGER NOT NULL,
    name        TEXT NOT NULL,
    PRIMARY KEY (subject_sha, va, name),
    FOREIGN KEY (subject_sha, va) REFERENCES withheld_names(subject_sha, va)
);

-- Every \`::\`-qualified method name the strings carry, named or not. A method
-- seen only as a string still says the class HAS that method.
CREATE VIEW name_class_methods AS
SELECT DISTINCT
       subject_sha,
       substr(text, 1, instr(text, '::') - 1) AS class_name,
       text                                   AS method
FROM string_references
WHERE instr(text, '::') > 1;

-- The class vocabulary itself, with how much is known about each class.
CREATE VIEW name_classes AS
SELECT m.subject_sha,
       m.class_name,
       COUNT(*) AS methods_seen,
       (SELECT COUNT(*) FROM functions f
         WHERE f.subject_sha = m.subject_sha AND f.class_name = m.class_name) AS named_functions
FROM name_class_methods m
GROUP BY m.subject_sha, m.class_name;

-- Where each class loads the surface it locks. The corroboration is that one
-- member recurs across classes that share no name prefix; this is the view
-- that shows it, and shows which classes do not.
CREATE VIEW name_class_surfaces AS
SELECT substr(r.text, 1, instr(r.text, '::') - 1) AS class_name,
       r.subject_sha,
       r.receiver_offset,
       COUNT(*) AS sites
FROM string_references r
WHERE instr(r.text, '::') > 1
  AND r.receiver_offset IS NOT NULL
  AND r.role != 'referenced-only'
GROUP BY 1, 2, 3;
`,
  },  {
    id: '005-proof-integrity',
    sql: `
-- A fragment match is NOT a proof.
--
-- The gate reports where in its emitted object the subject's bytes were
-- found. At offset 0 the compiler produced those bytes for that function. At
-- any other offset they merely occur somewhere inside a larger emission,
-- which says nothing about what the compiler emits AT that address -- the
-- Python gate guarded against exactly this and the port's caller did not.
-- One false proof was recorded (0x5EAF30, matched at offset 2 of a 10-byte
-- emission) before this was caught.
ALTER TABLE verdicts ADD COLUMN matched_at INTEGER;

-- Rebuilt for two reasons.
--
-- 1. matched_at: a verdict only counts at offset 0. NULL is tolerated for the
--    imported rows, whose gate recorded no offset but whose Python gate
--    already enforced entry matching.
-- 2. The PROVER is the compiler BINARY, not the binary plus one flag set.
--    toolchains.id is sha256(cl.exe) + ':' + flags, and current_config names
--    exactly one, so joining on it put every /O1 proof outside the
--    configuration in force -- 8 of them, silently. The flags belong to the
--    attempt, which is where they already are. So the join is on the compiler
--    itself, and a different cl.exe still retires everything.
DROP VIEW proven;
CREATE VIEW proven AS
SELECT a.subject_sha, a.va, a.id AS attempt_id, a.flags, a.author,
       v.gate_run_id, v.decided_at, v.masked, v.compared, f.size
FROM verdicts v
JOIN attempts   a  ON a.id = v.attempt_id
JOIN gate_runs  g  ON g.id = v.gate_run_id
JOIN functions  f  ON f.subject_sha = a.subject_sha AND f.va = a.va
JOIN toolchains tg ON tg.id = g.toolchain_id
JOIN current_config c ON c.only_row = 1
JOIN toolchains tc ON tc.id = c.toolchain_id
WHERE v.exact = 1
  AND (v.matched_at IS NULL OR v.matched_at = 0)
  AND g.subject_sha = c.subject_sha
  AND tg.cl_sha256  = tc.cl_sha256;

DROP VIEW superseded;
CREATE VIEW superseded AS
SELECT a.subject_sha, a.va, v.gate_run_id, g.toolchain_id,
       g.subject_sha AS proved_against,
       CASE WHEN v.matched_at > 0 THEN 'fragment match'
            ELSE 'different subject or compiler' END AS reason
FROM verdicts v
JOIN attempts   a  ON a.id = v.attempt_id
JOIN gate_runs  g  ON g.id = v.gate_run_id
JOIN toolchains tg ON tg.id = g.toolchain_id
JOIN current_config c ON c.only_row = 1
JOIN toolchains tc ON tc.id = c.toolchain_id
WHERE v.exact = 1
  AND (v.matched_at > 0
       OR g.subject_sha != c.subject_sha
       OR tg.cl_sha256  != tc.cl_sha256);
`,
  },
  {
    id: '006-library-import-names',
    sql: `
-- --------------------------------- import names from the libraries' own tables
--
-- 105 of the subject's 255 import slots have no name, because the loader
-- overwrote the only copy of them in place and the slots hold SafeDisc stubs.
-- The project's rule has been never to guess an API name from a call's shape,
-- and that rule stands: arity and argument kinds only constrain.
--
-- There is a route that does not guess. The image contains prebuilt CRT code
-- from the install's own LIBC.LIB -- \`crt_identifications\` names 297 of those
-- addresses by byte-matching library objects against the image -- and a
-- library object carries a RELOCATION TABLE naming the external symbol each of
-- its \`call dword ptr [...]\` sites targets. Place the object's bytes in the
-- image, and the relocation says which slot that call site uses and what the
-- library calls it. The name comes from the library's own symbol table.
--
-- WHAT EACH ROW BELOW ASSERTS, AND WHAT IT DOES NOT
-- ------------------------------------------------
-- A row asserts that the four bytes at \`site + 2\` in the image are the slot,
-- that the instruction at \`site\` is one that reads through it, and that the
-- object whose relocation named it is placed over those very bytes. It asserts
-- nothing about the slot as a whole: an API is keyed by (slot, call site), and
-- the derivation itself demonstrates why. 11 slots the dump named from its
-- SafeDisc cache are referenced by CRT call sites that link against a
-- DIFFERENT API, so the slot-level name is incomplete rather than wrong -- one
-- stub serves several APIs and the dispatcher picks on the caller's return
-- address.
CREATE TABLE library_import_references (
    subject_sha       TEXT NOT NULL REFERENCES subjects(sha256),
    -- Address of the referencing instruction in the image, so the claim can be
    -- checked against the bytes rather than taken on trust.
    site              INTEGER NOT NULL,
    slot              INTEGER NOT NULL,
    -- Undecorated, as the loader resolves it. Stored without the DLL because
    -- which DLL the slot belongs to is import_slots' answer, not this one's.
    api               TEXT NOT NULL,
    -- The symbol exactly as the object names it: \`__imp__HeapAlloc@12\`. The
    -- undecorated name above is derived from this, so the derivation is
    -- re-checkable from the stored evidence.
    decorated         TEXT NOT NULL,
    library           TEXT NOT NULL,
    member            TEXT NOT NULL,
    section_index     INTEGER NOT NULL,
    -- Where that section sits in the image, from the identification's address
    -- less the symbol's offset in the section. The whole section's
    -- non-relocated bytes are confirmed against the image at this address
    -- before any relocation of it is read.
    section_base      INTEGER NOT NULL,
    relocation_offset INTEGER NOT NULL,
    -- call-indirect | jmp-indirect | load-pointer | push-pointer. Only the
    -- first two are call sites; the others read the slot into a register or
    -- onto the stack and the call happens elsewhere, so they name the slot
    -- without naming a call site.
    form              TEXT NOT NULL,
    PRIMARY KEY (subject_sha, site)
);
CREATE INDEX library_import_references_slot ON library_import_references(subject_sha, slot);

-- Every relocation this derivation did NOT turn into a name, and why.
--
-- A count of what was dropped answers "how many"; only the rows answer "which
-- ones and why", which is what is actually needed when a slot has no name and
-- somebody wants to know whether that is an absence or a refusal.
CREATE TABLE library_import_refusals (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_sha       TEXT NOT NULL REFERENCES subjects(sha256),
    library           TEXT NOT NULL,
    member            TEXT NOT NULL,
    section_index     INTEGER NOT NULL,
    relocation_offset INTEGER,          -- null: the refusal is of the whole section
    decorated         TEXT,             -- null: no relocation is in question
    reason            TEXT NOT NULL
);
CREATE INDEX library_import_refusals_member
    ON library_import_refusals(subject_sha, library, member);

-- import_bindings is rebuilt so a library-derived binding can be recorded at
-- all. \`target\` is the address SafeDisc's dispatcher cached and \`bucket\` is
-- which of its cache slots held it: both belong to the dump, and a binding
-- read out of a library's relocation table has neither. They were NOT NULL, so
-- the only way to store such a row was to write 0 into both -- a number a
-- reader cannot distinguish from a real cached address of zero, and the exact
-- shape of "a writer that skips a field is a second format".
ALTER TABLE import_bindings RENAME TO import_bindings_002;
CREATE TABLE import_bindings (
    subject_sha   TEXT NOT NULL REFERENCES subjects(sha256),
    slot          INTEGER NOT NULL,
    call_site     INTEGER NOT NULL,
    api           TEXT,                -- null: the target is not an export
    evidence      TEXT NOT NULL,
    target        INTEGER,             -- null: not derived from the dump's cache
    bucket        INTEGER,             -- null: likewise
    call_operand  INTEGER,             -- set only when it names another slot
    blocked_by    TEXT,
    PRIMARY KEY (subject_sha, slot, call_site)
);
INSERT INTO import_bindings(subject_sha, slot, call_site, api, evidence, target,
                            bucket, call_operand, blocked_by)
SELECT subject_sha, slot, call_site, api, evidence, target, bucket, call_operand, blocked_by
FROM import_bindings_002;
DROP TABLE import_bindings_002;

-- ONE NAME PER EXPORT ADDRESS, BECAUSE WINE PUBLISHES SEVERAL
--
-- The guest's kernel32 exports ordinal 600 \`LockResource\` and ordinal 787
-- \`SetHandleCount\` at the SAME entry point, 0x7C80CD37. The dump can only say
-- which address a call reached, so it names such a call by whichever export
-- sits there; a library relocation names the other. Counting those as two APIs
-- would turn one slot with one API into a contradiction.
--
-- So the canonical name is chosen WITHIN ONE MODULE and looked up BY NAME, not
-- by the address a call resolved to. Resolving by address instead loses every
-- forwarded export: \`kernel32!GetLastError\` forwards to ntdll and has no
-- address of its own, so the address a call reached is
-- \`RtlGetLastWin32Error\` -- which the import map has already un-forwarded
-- back to the name kernel32 publishes. Re-deriving it from the address undoes
-- that, and 6 slots whose two sources agree were reported as contradictions.
CREATE VIEW guest_export_canonical AS
SELECT subject_sha, module_base, va, MIN(name) AS canonical
  FROM guest_exports
 WHERE va IS NOT NULL AND name IS NOT NULL
 GROUP BY subject_sha, module_base, va;

CREATE VIEW guest_export_alias AS
SELECT e.subject_sha, e.module_base, LOWER(e.name) AS name, c.canonical
  FROM guest_exports e
  JOIN guest_export_canonical c
    ON c.subject_sha = e.subject_sha AND c.module_base = e.module_base AND c.va = e.va
 WHERE e.name IS NOT NULL AND e.va IS NOT NULL;

-- Every API an import slot is known to serve, from which evidence, and from
-- how many sites.
--
-- The one place that question is answered, so "does this slot have a single
-- name" is a query and not a second derivation. More than one API for a slot
-- means it has no single name -- which is an answer, not a gap: SafeDisc's
-- dispatcher resolves on the caller's return address, so one stub serves
-- several APIs.
CREATE VIEW import_slot_apis AS
WITH slot_module AS (
  SELECT s.subject_sha, s.slot, s.dll, m.base AS module_base
    FROM import_slots s
    LEFT JOIN guest_modules m
      ON m.subject_sha = s.subject_sha AND LOWER(m.name) = LOWER(s.dll)
),
cached AS (
  SELECT b.subject_sha, b.slot,
         substr(b.api, 1, instr(b.api, '!')) ||
           COALESCE(a.canonical, substr(b.api, instr(b.api, '!') + 1)) AS api,
         'safedisc-cache' AS source
    FROM import_bindings b
    JOIN slot_module k ON k.subject_sha = b.subject_sha AND k.slot = b.slot
    LEFT JOIN guest_export_alias a
      ON a.subject_sha = b.subject_sha AND a.module_base = k.module_base
     AND a.name = LOWER(substr(b.api, instr(b.api, '!') + 1))
   WHERE b.api IS NOT NULL AND b.evidence <> 'library-relocation'
),
library AS (
  SELECT r.subject_sha, r.slot,
         k.dll || '!' || COALESCE(a.canonical, r.api) AS api,
         'library-relocation' AS source
    FROM library_import_references r
    JOIN slot_module k ON k.subject_sha = r.subject_sha AND k.slot = r.slot
    LEFT JOIN guest_export_alias a
      ON a.subject_sha = r.subject_sha AND a.module_base = k.module_base
     AND a.name = LOWER(r.api)
)
SELECT subject_sha, slot, api, source, COUNT(*) AS sites
  FROM (SELECT * FROM cached UNION ALL SELECT * FROM library)
 GROUP BY subject_sha, slot, api, source;

-- Every (slot, call site) BOTH sources name, and whether they agree.
--
-- This is the only independent check the library derivation has: the dump
-- named 150 slots by a completely unrelated route -- SafeDisc's own cache of
-- (call site -> resolved address) pairs -- so a call site both sources reach
-- is one the two can be held against each other at.
--
--   agrees                   the cached export and the library's symbol are
--                            the same name.
--   same-address-other-name  the library's symbol is published AT the address
--                            the call resolved to, under another name. Wine
--                            puts \`LockResource\` and \`SetHandleCount\` on one
--                            entry point, so the dump cannot tell which name
--                            the site was linked against and the library can.
--                            Agreement, with the ambiguity resolved.
--   disagrees                the library's symbol is not at that address at
--                            all, so the two are about different code. One of
--                            the derivations is wrong about this call site.
--                            A finding, never merged.
CREATE VIEW import_binding_agreement AS
SELECT r.subject_sha, r.slot, r.site AS call_site,
       b.api     AS cached_api,
       b.target  AS cached_target,
       r.api     AS library_api,
       CASE
         WHEN LOWER(substr(b.api, instr(b.api, '!') + 1)) = LOWER(r.api) THEN 'agrees'
         WHEN EXISTS (SELECT 1 FROM guest_exports e
                       WHERE e.subject_sha = r.subject_sha
                         AND e.va = b.target
                         AND LOWER(e.name) = LOWER(r.api)) THEN 'same-address-other-name'
         ELSE 'disagrees'
       END AS verdict
  FROM library_import_references r
  JOIN import_bindings b
    ON b.subject_sha = r.subject_sha AND b.slot = r.slot AND b.call_site = r.site
   AND b.evidence <> 'library-relocation'
 WHERE b.api IS NOT NULL;
`,
  },
  {
    id: '007-rejected-entries',
    sql: `
-- An address that is NOT a function entry, recorded as a fact.
--
-- Three rows in \`functions\` came from \`discover.py\`, which no longer
-- exists, labelled \`discovered_by='inventory'\`. One of them, 0x5a4c34,
-- decodes to \`inc ebp; hlt\` -- a privileged halt instruction, so those
-- bytes are data. It sits INSIDE the real function at 0x5a4afa, whose
-- prologue is \`push ebp; mov ebp,esp; sub esp,0x28; mov [ebp-0x20],ecx\`,
-- a textbook __thiscall member.
--
-- A spurious entry is not merely noise. It does three things:
--   1. it bounds its PREDECESSOR's extent measurement, so the real function
--      measures as 'no-terminator' and cannot be sized at all
--   2. the predecessor's wrong recorded size then cuts mid-instruction, and
--      \`decodeFunctionBody\` demands an exact cover, so the function is
--      handed to agents with an EMPTY disassembly -- unworkable, with no
--      error anywhere
--   3. it inflates the denominator, so coverage reads lower than it is
--
-- DELETING the row does not fix it. The evidence that produced the address
-- is still in the bytes, so the next producer re-adds it; that is exactly
-- what happened to these three. A rejection has to be a stored fact the
-- producers consult, carrying the reason and the bytes that justify it, so
-- it survives re-discovery and can be audited or reversed.
CREATE TABLE rejected_entries (
  subject_sha  TEXT    NOT NULL,
  va           INTEGER NOT NULL,
  reason       TEXT    NOT NULL,   -- why it is not an entry
  evidence     TEXT    NOT NULL,   -- the decode, verbatim, so it is checkable
  rejected_at  REAL    NOT NULL,
  PRIMARY KEY (subject_sha, va)
);

-- The trigger that enforces this lives in migration 009, NOT here. It was
-- written into this migration after this migration had already been recorded
-- as applied, so the runner skipped it and the trigger silently never
-- existed -- which is why five rejected addresses were back in the inventory
-- within the hour. Editing an applied migration does nothing; 009 also adds
-- the checksum that makes that mistake report itself.
`,
  },
  {
    id: '008-globals',
    sql: `
-- ---------------------------------------------------------- the globals half
--
-- 6,986 functions were catalogued and no global variable was. The browser
-- build cannot be finished without them, and the reason is specific.
--
-- The reconstructions reach global state by raw address -- a line reads
-- #define g_flag (*(Flag **)0x684480), meaning "the pointer stored at
-- 0x684480". Natively that is correct and it is part of what makes the
-- compiled bytes match the shipped game, so those lines stay in the proven
-- sources. For WebAssembly there is no address 0x684480. Mapping the whole
-- data region onto one extracted block works for plain data and FAILS for
-- any dword in that data which is itself an address, because moving the
-- block changes what the address means.
--
-- The subject carries NO relocation table: IMAGE_DIRECTORY_ENTRY_BASERELOC
-- is rva 0, size 0. So nothing in the binary says which dwords are
-- addresses, and enumerating them is reconstructing the table the linker
-- threw away. 13,259 aligned dwords in the data region hold an address
-- inside the executable span, and 1,875 hold one inside the data region.
--
-- WHY THIS IS SHAPED LIKE 004-recovered-names
-- -------------------------------------------
-- globals holds the ANSWER for each address; the three tables around it
-- hold the EVIDENCE the answer was read out of, and global_deferrals holds
-- every question the evidence did not settle, with its reason. That split is
-- the one functions.name and string_references already use, for the same
-- reason: a withheld answer is evidence, not an absence, and a reader with no
-- reason beside it has every incentive to "fix" it by choosing one.
--
-- NOTHING HERE STORES WHETHER A FUNCTION IS PROVEN. The strength of a
-- literal depends on whether its containing function is byte-exact UNDER THE
-- CONFIGURATION IN FORCE, which is what the proven view computes. A stored
-- flag would be a second answer that nothing retires when the compiler
-- changes -- the exact failure that shipped 6,953 blocks of which 1,450 were
-- still proved. So global_references stores the containing function and
-- global_evidence joins.

-- One confirmed reference from an instruction to a data address.
--
-- A row asserts that the instruction at site names address in its
-- operands AND that the value is a 32-bit field of the instruction's own
-- bytes. The second half is not decoration: a direct branch is printed as its
-- computed absolute target, which appears nowhere in the encoding, so without
-- it a branch target would be filed as a global.
CREATE TABLE global_references (
    subject_sha TEXT NOT NULL REFERENCES subjects(sha256),
    site        INTEGER NOT NULL,
    address     INTEGER NOT NULL,
    -- absolute  | [0x684480] alone: a scalar access of width bytes.
    -- indexed   | [eax + 0x684480]: the address is an ARRAY BASE and the
    --           | extent is not stated.
    -- immediate | push 0x684480: the address is taken and nothing is read.
    form        TEXT NOT NULL,
    -- Bytes the instruction accesses, from its own operand size prefix. Null
    -- for an immediate, which reads nothing.
    width       INTEGER,
    mnemonic    TEXT NOT NULL,
    -- The operand text, so the claim is checkable against the disassembly
    -- rather than taken on trust.
    op_str      TEXT NOT NULL,
    -- Null: the site is in a stretch of the executable span the inventory
    -- attributes to no function. Still a fact about bytes, but nothing ties
    -- it to a function that could be proven.
    containing_function INTEGER,
    PRIMARY KEY (subject_sha, site, address, form)
);
CREATE INDEX global_references_address ON global_references(subject_sha, address);
CREATE INDEX global_references_fn ON global_references(subject_sha, containing_function);

-- Operand literals the decoder printed that the instruction does not encode.
-- None becomes evidence. Kept because "the derivation saw this and refused
-- it" and "the derivation never saw this" are different answers.
CREATE TABLE global_reference_refusals (
    subject_sha TEXT NOT NULL REFERENCES subjects(sha256),
    site        INTEGER NOT NULL,
    address     INTEGER NOT NULL,
    mnemonic    TEXT NOT NULL,
    op_str      TEXT NOT NULL,
    reason      TEXT NOT NULL,
    PRIMARY KEY (subject_sha, site, address)
);

-- A data symbol a CRT library's own relocation table names in the image.
--
-- address is field_value - addend, and both are stored so the
-- subtraction is re-checkable. It is not optional: a Dir32 field holds
-- symbol + addend, so _iob + 64 and _iob + 32 are two references to ONE
-- global, and read without subtracting they become two globals at addresses
-- _iob does not occupy. The same correction puts _XcptActTab at 0x682670
-- rather than 0x682678.
CREATE TABLE global_library_symbols (
    subject_sha       TEXT NOT NULL REFERENCES subjects(sha256),
    address           INTEGER NOT NULL,
    -- As the library's symbol table spells it. A CRT global is __pctype in
    -- the object and _pctype in C; the stored form is the one the evidence
    -- carries, so no name here is a transformation of another.
    name              TEXT NOT NULL,
    library           TEXT NOT NULL,
    member            TEXT NOT NULL,
    -- external-relocation | the object referred to a symbol it does not
    --                     | define, so the patched field gives the address.
    -- placed-data-section | the object's own data section was located in the
    --                     | image, so every symbol in it has an address AND
    --                     | a size.
    route             TEXT NOT NULL,
    section_index     INTEGER NOT NULL,
    relocation_offset INTEGER,
    field_value       INTEGER,
    addend            INTEGER,
    -- The byte of the symbol this reference reaches. Non-zero is a lower
    -- bound on the symbol's size independent of the library's own table.
    offset_reached    INTEGER NOT NULL,
    size              INTEGER,
    -- library-section     | alone in its section, so the section's size IS
    --                     | its size.
    -- library-next-symbol | bounded by the next symbol. An UPPER BOUND: the
    --                     | gap may include alignment padding.
    size_basis        TEXT,
    PRIMARY KEY (subject_sha, address, name, member, route)
);
CREATE INDEX global_library_symbols_name ON global_library_symbols(subject_sha, name);

-- Every library relocation or section placement that produced no name, and
-- why. A count answers "how many"; only the rows answer "which, and why",
-- which is what is needed when a global has no name and somebody wants to
-- know whether that is an absence or a refusal.
CREATE TABLE global_library_refusals (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_sha       TEXT NOT NULL REFERENCES subjects(sha256),
    library           TEXT NOT NULL,
    member            TEXT NOT NULL,
    section_index     INTEGER NOT NULL,
    relocation_offset INTEGER,          -- null: the refusal is of a section
    symbol            TEXT,
    reason            TEXT NOT NULL
);
CREATE INDEX global_library_refusals_member
    ON global_library_refusals(subject_sha, library, member);

-- An aligned dword in the data region holding a valid address: the weakest
-- evidence this inventory admits, and the one the browser build cannot do
-- without, because this IS the missing relocation table.
--
-- The weakness is stored rather than hidden. section and target_section
-- are both kept, so a reader can see that 166 candidates sit in .rsrc,
-- where a dword that looks like an address is almost certainly a resource
-- offset -- and 0x6ACFC0 is both a plausible byte count and an address
-- inside .data.
--
-- run_start and run_length are what make this useful. A vtable is a run
-- of consecutive aligned dwords all pointing into code; a run whose first
-- address the code NAMES is a table the program declares, and 214 such runs
-- account for 11,354 of the 13,259 code-valued dwords.
CREATE TABLE global_pointer_candidates (
    subject_sha    TEXT NOT NULL REFERENCES subjects(sha256),
    address        INTEGER NOT NULL,
    value          INTEGER NOT NULL,
    section        TEXT NOT NULL,
    target_section TEXT NOT NULL,
    run_start      INTEGER NOT NULL,
    run_length     INTEGER NOT NULL,
    PRIMARY KEY (subject_sha, address)
);
CREATE INDEX global_pointer_candidates_run
    ON global_pointer_candidates(subject_sha, run_start);

-- One row per global: the answer, from all four kinds of evidence.
CREATE TABLE globals (
    subject_sha TEXT NOT NULL REFERENCES subjects(sha256),
    address     INTEGER NOT NULL,
    -- From the subject's own section table, so a SafeDisc data section is
    -- named rather than lumped in with .data.
    section     TEXT NOT NULL,
    -- proven-literal   | a literal in a function whose bytes we reproduce
    --                  | exactly. A fact about verified bytes.
    -- library-symbol   | a Dir32 relocation in a confirmed library object.
    -- decoded-literal  | the same literal, in a function not yet proven.
    -- pointer-dword    | only the value scan. The weakest.
    evidence    TEXT NOT NULL,
    size        INTEGER,
    -- library-section | library-next-symbol | pointer-run | access-width
    size_basis  TEXT,
    name        TEXT,
    -- The library member whose relocation named it.
    name_from   TEXT,
    -- code-pointer | data-pointer | float. Null means nothing says -- which
    -- is NOT the same as "an integer", and the reason is in
    -- global_deferrals.
    holds       TEXT,
    -- indirect-call | indirect-jump | x87-access | stored-address. The
    -- instruction outranks the bytes: call dword ptr [X] says X holds a
    -- code pointer whatever X contained at the moment the dump was taken.
    holds_basis TEXT,
    points_to   INTEGER,
    PRIMARY KEY (subject_sha, address)
);
CREATE INDEX globals_section ON globals(subject_sha, section);
CREATE INDEX globals_name ON globals(subject_sha, name);

-- Everything the evidence does not settle, with the reason.
--
-- identity is an address that gets no globals row at all -- a declared
-- import slot, or an address in no section. The other three are questions
-- about a global that does exist.
CREATE TABLE global_deferrals (
    subject_sha TEXT NOT NULL REFERENCES subjects(sha256),
    address     INTEGER NOT NULL,
    what        TEXT NOT NULL,   -- identity | size | name | holds
    reason      TEXT NOT NULL,
    PRIMARY KEY (subject_sha, address, what)
);

-- The strength of each reference, computed and never stored.
--
-- A literal inside a byte-exact function is a fact about bytes this project
-- has reproduced; the same literal inside an unproven reconstruction depends
-- on that decode being right. Which one a row is depends on the
-- configuration in force, so it is a join against proven -- changing the
-- compiler re-ranks every reference at once, with no flag to set.
CREATE VIEW global_evidence AS
SELECT r.subject_sha, r.address, r.site, r.form, r.width, r.mnemonic, r.op_str,
       r.containing_function,
       CASE
         WHEN r.containing_function IS NULL THEN 'unattributed-literal'
         WHEN EXISTS (SELECT 1 FROM proven p
                       WHERE p.subject_sha = r.subject_sha
                         AND p.va = r.containing_function) THEN 'proven-literal'
         ELSE 'decoded-literal'
       END AS strength
  FROM global_references r;

-- Which functions touch each global, and how hard the evidence is.
CREATE VIEW global_touched_by AS
SELECT e.subject_sha, e.address, e.containing_function AS va,
       COUNT(*) AS sites,
       MAX(e.strength = 'proven-literal') AS proven
  FROM global_evidence e
 WHERE e.containing_function IS NOT NULL
 GROUP BY e.subject_sha, e.address, e.containing_function;

-- Addresses BOTH this inventory and the import map answer.
--
-- There must be none: an import slot gets no globals row, because
-- import_slots already answers it and 51 slots serve several APIs, which no
-- single global can express. A non-empty result means the two have started
-- double-counting.
CREATE VIEW global_import_slot_overlap AS
SELECT g.subject_sha, g.address
  FROM globals g
  JOIN import_slots s ON s.subject_sha = g.subject_sha AND s.slot = g.address;
`,
  },
  {
    id: '008-inventory-audits',
    sql: `
-- Each run of the workability audit, stored as a fact.
--
-- The audit decodes every inventory entry, which takes about two seconds --
-- far too slow for a dashboard polling every five. The alternative of
-- recomputing it per request was what produced pre-aggregated scalars
-- nobody could re-derive. So the audit WRITES its result and every reader
-- queries it, which also gives the figure a history: whether the number of
-- unworkable entries is falling is a question no single reading answers.
CREATE TABLE inventory_audits (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  subject_sha        TEXT    NOT NULL,
  at                 REAL    NOT NULL,
  entries            INTEGER NOT NULL,
  workable           INTEGER NOT NULL,
  undecodable        INTEGER NOT NULL,
  undecodable_proven INTEGER NOT NULL,
  repaired           INTEGER NOT NULL
);
CREATE INDEX inventory_audits_at ON inventory_audits(subject_sha, at DESC);
`,
  },
  {
    id: '009-honour-rejections',
    sql: `
-- Rejections, enforced by the TABLE rather than by each producer.
--
-- There are two writers of \`functions\` today -- discovery, and the legacy
-- import that reads decomp/functions.json -- and the JSON still lists every
-- address rejected so far, so it re-seeds them on each import. Asking each
-- writer to remember a NOT EXISTS clause is how a rule survives in two
-- places and then in one. As a trigger it is a property of the table, so a
-- writer cannot fail to honour it, including the legacy import and whatever
-- is added next.
--
-- RAISE(IGNORE) skips the row and lets the statement proceed, the same
-- semantics as ON CONFLICT DO NOTHING. The skip is not hidden:
-- \`rejected_entries\` records what is skipped and why, and the discovery
-- report counts its own refusals.
CREATE TRIGGER functions_honour_rejections
BEFORE INSERT ON functions
WHEN EXISTS (
  SELECT 1 FROM rejected_entries r
   WHERE r.subject_sha = NEW.subject_sha AND r.va = NEW.va
)
BEGIN
  SELECT RAISE(IGNORE);
END;

-- The text each migration was applied FROM.
--
-- A migration already recorded in \`migrations\` is skipped, so editing one
-- does nothing at all -- and says nothing. That is how the trigger above was
-- written, believed applied, and absent: the table from the same migration
-- existed, so everything looked right. Storing the hash lets the runner
-- compare what it would run against what it did run and say so.
--
-- Rows applied before this migration have no hash. They are backfilled from
-- the current text on this upgrade -- presumed correct as of now -- so that
-- any edit AFTER this point is caught rather than assumed.
ALTER TABLE migrations ADD COLUMN sql_sha256 TEXT;
`,
  },
  {
    id: '010-globals-pointer-coverage',
    sql: `
-- Pointer coverage as the rebuild measured it.
--
-- "How many of the pointers in the data region fall inside a global whose
-- extent we have settled" is an interval-containment test over every
-- candidate and every sized global, and it is implemented once, in
-- globals/inventory.ts, with a deliberate exclusion: a global sized ONLY
-- from the pointer values is left out, because its extent was inferred from
-- the very dwords being counted and including it would report 100% while
-- measuring nothing.
--
-- Re-expressing that in SQL so a dashboard could ask cheaply would be a
-- second implementation of the same rule, and two implementations of one
-- algorithm drift silently -- the exclusion is exactly the clause someone
-- would omit. So the rebuild stores what it measured and every reader
-- queries this.
CREATE TABLE globals_pointer_coverage (
  subject_sha  TEXT    NOT NULL REFERENCES subjects(sha256),
  at           REAL    NOT NULL,
  target       TEXT    NOT NULL,   -- 'code' | 'data'
  enumerated   INTEGER NOT NULL,
  attributed   INTEGER NOT NULL,
  PRIMARY KEY (subject_sha, target)
);
`,
  },
  {
    id: '011-import-dumps',
    sql: `
-- Which memory dumps the import surface has been read from.
--
-- SafeDisc writes a slot's API into its cache only when the game actually
-- calls through that slot, so one capture answers for the slots that session
-- exercised and is silent about the rest: the first dump leaves 54 of 255
-- unanswered. More captures is the only remedy, which makes a new dump NEW
-- EVIDENCE -- and the derivation was a one-time job, gated on
-- \`guest_modules\` being empty, so a second dump sitting on disk changed
-- nothing. It had been there for hours.
--
-- These rows are the re-derivation trigger AND the report. If the set of
-- dumps on disk differs from the set recorded here, the surface is re-read;
-- and \`bindings_added\` is the only figure that says whether taking a
-- capture was worth it, because a dump whose session exercised nothing new
-- contributes nothing however large it is.
CREATE TABLE import_dumps (
  subject_sha      TEXT    NOT NULL REFERENCES subjects(sha256),
  dump             TEXT    NOT NULL,   -- basename, not a full path
  bytes            INTEGER NOT NULL,
  -- Derived from the dump, never recorded alongside it: a hand-written CR3
  -- made every new capture a code change.
  cr3              INTEGER NOT NULL,
  -- SafeDisc's loader DLL is mapped at a different base on every boot.
  loader_base      INTEGER NOT NULL,
  bindings_offered INTEGER NOT NULL,
  bindings_added   INTEGER NOT NULL,
  contradictions   INTEGER NOT NULL,
  read_at          REAL    NOT NULL,
  PRIMARY KEY (subject_sha, dump)
);
`,
  },
  {
    id: '012-slot-resolution-over-all-dumps',
    sql: `
-- How a slot resolves, decided over ALL the evidence rather than one dump's.
--
-- \`buildImportMap\` classifies a slot from the cache state of the capture it
-- is reading, which was the only scope there was while one dump was read.
-- With several dumps unioned, reporting the LAST dump's classification beside
-- the UNION of the bindings put two scopes in one answer: a slot came back
-- 'multiple-apis' while the bindings recorded for it named exactly one API,
-- because the second dump saw two cache records and the pair for the one it
-- shared with the first dump was already recorded.
--
-- So the classification is a query over what is recorded, in one place:
--
--   no-cached-call-site  no dump ever caught a call through this slot, so
--                        nothing names what it serves
--   multiple-apis        the bindings name more than one API. This is the
--                        case an API-per-slot model gets wrong, and more
--                        captures keep finding more of them.
--   not-an-export        exactly one API, but the address it resolved to is
--                        not an export of any mapped module -- a finding,
--                        never merged
--   export-exact         exactly one API at an address that is an export
--
-- A library-relocation binding counts as evidence here: it names a call site
-- from the libraries' own symbol tables, which is independent of any dump.
CREATE VIEW import_slot_resolution AS
SELECT s.subject_sha,
       s.slot,
       COUNT(b.call_site)                AS bindings,
       COUNT(DISTINCT LOWER(b.api))      AS apis,
       CASE
         WHEN COUNT(b.call_site) = 0 THEN 'no-cached-call-site'
         WHEN COUNT(DISTINCT LOWER(b.api)) > 1 THEN 'multiple-apis'
         WHEN MAX(b.target) IS NOT NULL
          AND NOT EXISTS (
                SELECT 1 FROM guest_exports e
                 WHERE e.subject_sha = s.subject_sha AND e.va = MAX(b.target))
           THEN 'not-an-export'
         ELSE 'export-exact'
       END                               AS resolution
  FROM import_slots s
  LEFT JOIN import_bindings b
    ON b.subject_sha = s.subject_sha AND b.slot = s.slot
 GROUP BY s.subject_sha, s.slot;
`,
  },
  {
    id: '013-slot-resolution-aggregate-fix',
    sql: `
-- Migration 012's view used MAX(b.target) inside a correlated NOT EXISTS in
-- the same CASE, which SQLite rejects at query time with "misuse of aggregate
-- function MAX()" -- CREATE VIEW accepted it, so the fault appeared only when
-- something read it.
--
-- Recreated here rather than by editing 012, because an applied migration is
-- skipped and the edit would never run. That is not hypothetical: a trigger
-- written into 007 after 007 had been applied silently never existed, which
-- is why migrations now carry the hash of the text they ran from.
--
-- The aggregate is computed in an inner query and the CASE reads its result.
DROP VIEW IF EXISTS import_slot_resolution;
CREATE VIEW import_slot_resolution AS
SELECT agg.subject_sha,
       agg.slot,
       agg.bindings,
       agg.apis,
       CASE
         WHEN agg.bindings = 0 THEN 'no-cached-call-site'
         WHEN agg.apis > 1 THEN 'multiple-apis'
         WHEN agg.target IS NOT NULL
          AND NOT EXISTS (
                SELECT 1 FROM guest_exports e
                 WHERE e.subject_sha = agg.subject_sha AND e.va = agg.target)
           THEN 'not-an-export'
         ELSE 'export-exact'
       END AS resolution
  FROM (
    SELECT s.subject_sha                   AS subject_sha,
           s.slot                          AS slot,
           COUNT(b.call_site)              AS bindings,
           COUNT(DISTINCT LOWER(b.api))    AS apis,
           MAX(b.target)                   AS target
      FROM import_slots s
      LEFT JOIN import_bindings b
        ON b.subject_sha = s.subject_sha AND b.slot = s.slot
     GROUP BY s.subject_sha, s.slot
  ) AS agg;
`,
  },
  {
    id: '014-working-on',
    sql: `
-- What is being worked on right now, in prose, for a person reading the
-- dashboard.
--
-- Every other figure on that page is derived from evidence, which is what
-- makes them trustworthy and also what makes them silent about intent: the
-- proven count cannot say why the queue was reordered this morning, or what
-- the next blocker is. This holds the sentence a person would say.
--
-- One row, replaced in place, with the time it was written. The timestamp is
-- the point: a note with no age is indistinguishable from a note nobody has
-- revisited, and a stale note is worse than none because it reads as current.
CREATE TABLE working_on (
  only_row   INTEGER PRIMARY KEY CHECK (only_row = 1),
  note       TEXT    NOT NULL,
  updated_at REAL    NOT NULL
);
`,
  },
  {
    id: '015-executable-gaps',
    sql: `
-- Executable bytes that no inventory extent claims.
--
-- Every discovery rule follows a REFERENCE -- a call inside a proven
-- function, a pointer in a table -- so none of them can find a function that
-- nothing references. Measured: the inventory covers 85.81% of the
-- executable span. Of the 291,413 bytes it does not claim, 5,771 gaps
-- totalling 44,529 bytes are nothing but padding, and 527 gaps totalling
-- 246,884 bytes -- 10.93% of all executable bytes -- hold real content whose
-- first bytes are unmistakable function prologues: \`56 8b f1 57\` is
-- push esi; mov esi,ecx; push edi, a __thiscall member, and
-- \`64 a1 00 00 00 00 6a ff\` is MSVC's structured-exception frame setup.
--
-- They are RECORDED rather than entered into the inventory, because their
-- extents cannot yet be measured honestly. The extent rule closes a function
-- at a ret or jmp followed by padding, and inside a dense gap one function's
-- ret is followed immediately by the next function's first byte, so none of
-- the 408 regions measured. A wrong size is worse than no entry: it reaches
-- an agent as a function with no readable body, which is a failure this
-- service has already paid for.
--
-- So this table is the frontier, visible and countable, instead of 10.93% of
-- the executable being invisible because no rule happened to cover it.
CREATE TABLE executable_gaps (
  subject_sha TEXT    NOT NULL REFERENCES subjects(sha256),
  va          INTEGER NOT NULL,
  bytes       INTEGER NOT NULL,
  -- First bytes as hex, so a reader can see what is there without the image.
  head        TEXT    NOT NULL,
  reason      TEXT    NOT NULL,
  found_at    REAL    NOT NULL,
  PRIMARY KEY (subject_sha, va)
);

-- Each run of the gap scan, so the frontier's SIZE has a history: whether
-- unfound executable bytes are falling is a question no single reading
-- answers.
CREATE TABLE gap_scans (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  subject_sha    TEXT    NOT NULL,
  at             REAL    NOT NULL,
  text_bytes     INTEGER NOT NULL,
  covered_bytes  INTEGER NOT NULL,
  padding_gaps   INTEGER NOT NULL,
  padding_bytes  INTEGER NOT NULL,
  residue_gaps   INTEGER NOT NULL,
  residue_bytes  INTEGER NOT NULL,
  added          INTEGER NOT NULL
);
CREATE INDEX gap_scans_at ON gap_scans(subject_sha, at DESC);
`,
  },
  {
    id: '016-dump-identity-includes-mtime',
    sql: `
-- A capture is identified by name, size AND modification time.
--
-- Name and size alone cannot tell two captures apart, because every capture
-- of the same region is the same size: \`pmemsave 0 0x20000000\` always
-- writes 512MB. So when a weaker first capture of guest-ram-2.bin was
-- REPLACED with a stronger one -- 344 cache entries becoming 362 -- the
-- re-read trigger saw an identical name and an identical size and did
-- nothing. The service went on reporting the weaker dump's numbers while the
-- better file sat on disk.
--
-- mtime is what distinguishes them, and it costs a stat rather than hashing
-- half a gigabyte.
ALTER TABLE import_dumps ADD COLUMN mtime REAL NOT NULL DEFAULT 0;
`,
  },
  {
    id: '017-agent-doing',
    sql: `
-- What an agent is doing RIGHT NOW, in its own words.
--
-- The dashboard had a "doing" column and it showed \`role\`, which is set once
-- at registration and never changes -- "round 38 batch A" for an agent that
-- has since claimed two functions, read 8,000 lines of notes, and spent an
-- hour on a branch displacement. For agents registered without a role it was
-- simply blank. Neither told a reader what was happening.
--
-- An agent beats on every submit and on a timer anyway, so the beat is where
-- this belongs: it costs the agent one extra field on a call it already
-- makes, and it cannot go stale without the beat also going stale.
--
-- \`doing_at\` is kept separately from \`last_beat\` because they answer
-- different questions. A beat says the agent is alive; this says when it last
-- described itself. An agent that beats every minute while repeating a
-- summary from forty minutes ago is exactly the case a reader must be able
-- to see.
ALTER TABLE agents ADD COLUMN doing TEXT;
ALTER TABLE agents ADD COLUMN doing_at REAL;
`,
  },
  {
    id: '018-toolchain-identity-over-all-binaries',
    sql: `
-- Carry the existing toolchain rows onto the new identity.
--
-- A toolchain was identified by the sha256 of CL.EXE alone. CL.EXE is a 64KB
-- DRIVER that Service Pack 3 never touched: it still reports version
-- 12.00.8168 on this install, whose code generator C2.DLL is 12.00.8447 and
-- whose front ends C1.DLL/C1XX.DLL are 12.00.8472. None of the files that
-- decide what gets emitted was in the hash.
--
-- This stops being academic now. The subject's own Rich header says 169 of
-- its objects were produced by build 8168 and 306 by 8447, so a second
-- compiler has to stand beside this one. Swapping C2.DLL would have left
-- cl_sha256 byte-for-byte identical, the toolchain row would have been reused
-- by its primary key, and proofs taken under one code generator would have
-- been silently attributed to the other.
--
-- The identity now covers CL.EXE, C1.DLL, C1XX.DLL, C2.DLL and LINK.EXE.
-- THE BINARIES HAVE NOT CHANGED, only how they are named, so the 3,356
-- existing proofs are still proofs and must not be retired: \`proven\` joins
-- on cl_sha256, and leaving the old value would have retracted every one of
-- them for a reason that has nothing to do with the evidence.
UPDATE toolchains
   SET id = '91ea199691b0f7d91a228e88c42e54d96132af25d29da22912b40c574f49f01c:' || flags,
       cl_sha256 = '91ea199691b0f7d91a228e88c42e54d96132af25d29da22912b40c574f49f01c'
 WHERE cl_sha256 = '5e712379f6f2dc979bdc09573a9609a72225288ec6da232b83e5962800cb5ff4';

UPDATE current_config
   SET toolchain_id =
       '91ea199691b0f7d91a228e88c42e54d96132af25d29da22912b40c574f49f01c:'
       || substr(toolchain_id, instr(toolchain_id, ':') + 1)
 WHERE toolchain_id LIKE
       '5e712379f6f2dc979bdc09573a9609a72225288ec6da232b83e5962800cb5ff4:%';

UPDATE gate_runs
   SET toolchain_id =
       '91ea199691b0f7d91a228e88c42e54d96132af25d29da22912b40c574f49f01c:'
       || substr(toolchain_id, instr(toolchain_id, ':') + 1)
 WHERE toolchain_id LIKE
       '5e712379f6f2dc979bdc09573a9609a72225288ec6da232b83e5962800cb5ff4:%';
`,
  },
  {
    id: '019-toolchain-identity-fk-safe',
    sql: `
-- Migration 018 was recorded as applied and did nothing. This does the same
-- work in an order foreign keys permit.
--
-- 018 updated \`toolchains.id\` in place. Three tables reference it --
-- current_config, gate_runs, composition_runs -- and the connection runs with
-- PRAGMA foreign_keys = ON. Under that, the UPDATE to the referenced parent
-- key silently changed NOTHING and raised nothing, so the migration committed
-- and was recorded while its effect was entirely absent. Reproduced in
-- isolation before writing this.
--
-- The FK-safe order is: create the new parent rows, repoint every child at
-- them, then remove the old parents. At no point does a child reference a row
-- that does not exist.
INSERT OR IGNORE INTO toolchains(id, cl_sha256, flags, comp_id, added_at)
SELECT '91ea199691b0f7d91a228e88c42e54d96132af25d29da22912b40c574f49f01c:' || flags,
       '91ea199691b0f7d91a228e88c42e54d96132af25d29da22912b40c574f49f01c',
       flags, comp_id, added_at
  FROM toolchains
 WHERE cl_sha256 = '5e712379f6f2dc979bdc09573a9609a72225288ec6da232b83e5962800cb5ff4';

UPDATE current_config
   SET toolchain_id = '91ea199691b0f7d91a228e88c42e54d96132af25d29da22912b40c574f49f01c:'
       || substr(toolchain_id, instr(toolchain_id, ':') + 1)
 WHERE toolchain_id LIKE '5e712379f6f2dc979bdc09573a9609a72225288ec6da232b83e5962800cb5ff4:%';

UPDATE gate_runs
   SET toolchain_id = '91ea199691b0f7d91a228e88c42e54d96132af25d29da22912b40c574f49f01c:'
       || substr(toolchain_id, instr(toolchain_id, ':') + 1)
 WHERE toolchain_id LIKE '5e712379f6f2dc979bdc09573a9609a72225288ec6da232b83e5962800cb5ff4:%';

UPDATE composition_runs
   SET toolchain_id = '91ea199691b0f7d91a228e88c42e54d96132af25d29da22912b40c574f49f01c:'
       || substr(toolchain_id, instr(toolchain_id, ':') + 1)
 WHERE toolchain_id LIKE '5e712379f6f2dc979bdc09573a9609a72225288ec6da232b83e5962800cb5ff4:%';

DELETE FROM toolchains
 WHERE cl_sha256 = '5e712379f6f2dc979bdc09573a9609a72225288ec6da232b83e5962800cb5ff4';
`,
    // Checked INSIDE the migration's own transaction. 018 proved that
    // "recorded as applied" and "actually did something" are different
    // claims, and only this one is worth anything.
    // The invariant is that NO row carries the old identity any more, which is
    // true both after a successful migration and on a fresh database that
    // never had one. Asserting instead that the new rows exist was wrong: it
    // failed every fresh database, where inserting nothing is the correct
    // outcome. `verify` is deliberately not part of the migration's stored
    // hash, so fixing it here does not read as an edited migration.
    verify: `SELECT COUNT(*) AS stragglers FROM toolchains
              WHERE cl_sha256 = '5e712379f6f2dc979bdc09573a9609a72225288ec6da232b83e5962800cb5ff4'`,
    verifyExpects: 'zero',
  },
  {
    id: '020-port-stranded-literals',
    sql: `
-- Literal addresses the browser build cannot resolve.
--
-- A reconstruction refers to the game's variables by bare address, because
-- that is what the original compiler emitted. The portable rendering rewrites
-- each one into an offset inside the loaded data image; a literal the rewrite
-- pattern does not match stays a bare number, and in WebAssembly that is a
-- dereference of an address which does not exist there.
--
-- The conversion already computed these and then THREW THEM AWAY -- they were
-- returned in a report and never stored, so the one correctness hole standing
-- between the proven set and a browser build could not be counted, tracked,
-- or shown. Stored per (function, literal), so the same address stranded in
-- four functions is four facts and the worst offenders are a query.
CREATE TABLE port_stranded_literals (
  subject_sha TEXT    NOT NULL REFERENCES subjects(sha256),
  va          INTEGER NOT NULL,   -- the function whose source holds it
  literal     INTEGER NOT NULL,   -- the address the rewrite did not match
  found_at    REAL    NOT NULL,
  PRIMARY KEY (subject_sha, va, literal)
);
CREATE INDEX port_stranded_by_literal
    ON port_stranded_literals(subject_sha, literal);
`,
  },
  {
    id: '021-unreferenced-import-slots',
    sql: `
-- Import slots that NO instruction anywhere in the image refers to.
--
-- 241 of 255 slots are referenced. These 14 are not: a scan of every
-- executable section for FF 15 / FF 25, and of the whole file for any dword
-- equal to a slot address -- so vtables and .rdata are covered -- finds no
-- reference to any of them.
--
-- That settles them. SafeDisc's dispatcher matches the calling instruction's
-- disp32 against the record's slot, so a slot nothing calls can never be
-- dispatched and its cache can never fill. No further memory capture will
-- ever name one, and two captures were already spent partly on the hope that
-- one would. They are dead entries left behind by the protection's remap:
-- their original names were 13 KERNEL32 and 1 USER32 name from the residual
-- set, but the slot-to-name correspondence died with the overwritten name
-- table.
--
-- For the browser build this is not a loss. A slot nothing calls needs no
-- implementation.
CREATE TABLE unreferenced_import_slots (
  subject_sha TEXT    NOT NULL REFERENCES subjects(sha256),
  slot        INTEGER NOT NULL,
  reason      TEXT    NOT NULL,
  found_at    REAL    NOT NULL,
  PRIMARY KEY (subject_sha, slot)
);

INSERT INTO unreferenced_import_slots(subject_sha, slot, reason, found_at)
SELECT c.subject_sha, s.slot,
       'no instruction and no data dword in the image refers to this slot, so '
       || 'the dispatcher can never match it and its cache can never fill',
       strftime('%s','now')
  FROM current_config c
  JOIN import_slots s ON s.subject_sha = c.subject_sha
 WHERE c.only_row = 1
   AND s.slot IN (
     6509788, 6509796, 6509800, 6509836, 6509932, 6509940, 6510008,
     6510020, 6510052, 6510068, 6510088, 6510184, 6510200, 6510236
   );
`,
    // A verify has to hold on a FRESH database too, where there are no import
    // slots and inserting nothing is the correct outcome. Asserting that rows
    // exist fails there -- which is the second time I have written that, so it
    // is stated here: assert an INVARIANT, not a population. The invariant is
    // that nothing recorded as an unreferenced slot is absent from the slot
    // table, which is true of 14 rows and of none.
    verify: `SELECT COUNT(*) AS violations
               FROM unreferenced_import_slots u
              WHERE NOT EXISTS (SELECT 1 FROM import_slots s
                                 WHERE s.subject_sha = u.subject_sha
                                   AND s.slot = u.slot)`,
    verifyExpects: 'zero',
  },
  {
    id: '022-unreferenced-import-slots-correct-addresses',
    sql: `
-- Migration 021 inserted NOTHING. Its slot list was fourteen decimals I typed
-- by hand instead of converting, and not one of them was an address in the
-- table. It passed because its verify asserted an invariant -- that no
-- recorded slot is absent from import_slots -- which zero rows satisfy
-- perfectly.
--
-- Two lessons, both already paid for elsewhere today. A decimal address must
-- be COMPUTED, never typed: this is the fifth hand conversion to be wrong in
-- one session and every one produced a plausible result rather than an error.
-- And a verify has to be able to fail: "no violations" over an empty table is
-- not evidence of anything, so this one compares the count recorded against
-- the count of those slots that actually exist, which is 14 here and 0 on a
-- fresh database and wrong in neither.
--
-- The finding itself: 241 of 255 import slots are referenced by some
-- instruction or data dword. These 14 are referenced by nothing -- a scan of
-- every executable section for FF 15 / FF 25, and of the whole file for any
-- dword equal to a slot address, finds no reference. SafeDisc's dispatcher
-- matches the calling instruction's disp32 against the record's slot, so a
-- slot nothing calls can never be dispatched and its cache can never fill.
-- No future memory capture will name one. They are dead entries left by the
-- protection's remap, and for the browser build that is fine: a slot nothing
-- calls needs no implementation.
INSERT INTO unreferenced_import_slots(subject_sha, slot, reason, found_at)
SELECT c.subject_sha, s.slot,
       'no instruction and no data dword in the image refers to this slot, so '
       || 'the dispatcher can never match it and its cache can never fill',
       strftime('%s','now')
  FROM current_config c
  JOIN import_slots s ON s.subject_sha = c.subject_sha
 WHERE c.only_row = 1
   AND s.slot IN (
     6508764, 6508772, 6508776, 6508812,
     6508908, 6508916, 6508968, 6508996,
     6509028, 6509044, 6509064, 6509160,
     6509176, 6509212
   )
   AND NOT EXISTS (SELECT 1 FROM unreferenced_import_slots u
                    WHERE u.subject_sha = c.subject_sha AND u.slot = s.slot);
`,
    verify: `SELECT
      (SELECT COUNT(*) FROM unreferenced_import_slots)
      -
      (SELECT COUNT(*) FROM import_slots WHERE slot IN (
         6508764, 6508772, 6508776, 6508812,
     6508908, 6508916, 6508968, 6508996,
     6509028, 6509044, 6509064, 6509160,
     6509176, 6509212
       )) AS shortfall`,
    verifyExpects: 'zero',
  },
  {
    id: '023-composition-run-says-what-it-recompiled',
    sql: `
-- A composition run recompiles every reconstruction in force and takes about
-- seven minutes alone; sharing the one container with five agents it took
-- nearly thirty. On a thirty-minute interval over a proven set that changes
-- constantly, it would hold the compiler permanently and halve every agent's
-- throughput. So a run may now CARRY FORWARD a contribution instead of
-- recompiling it.
--
-- The carry-forward is exact, not an approximation, and it is sound for
-- exactly one case: a contribution recorded as placed with diff_bytes = 0,
-- for the same attempt_id, under a run with the same toolchain_id. Such a
-- contribution wrote bytes equal to the subject's, and the canvas is
-- initialised from the subject, so re-emitting it provably changes nothing.
-- Anything else -- a different source, a different compiler, or any
-- disagreement at all -- is recompiled.
--
-- These two columns exist so the run cannot claim work it did not do. A run
-- that recompiled twelve functions and carried 3,350 must not read as having
-- verified 3,362: that is how a cache keyed on a timestamp came to report
-- "already proved" about a harness no proof had ever seen. considered stays
-- the total; these say how it was reached.
ALTER TABLE composition_runs ADD COLUMN recompiled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE composition_runs ADD COLUMN carried    INTEGER NOT NULL DEFAULT 0;
`,
    verify: `SELECT COUNT(*) AS missing FROM pragma_table_info('composition_runs')
              WHERE name IN ('recompiled','carried')`,
    verifyExpects: 'nonzero',
  },
  {
    id: '024-function-closability',
    sql: `
-- WHICH UNSOLVED FUNCTION TO HAND OUT, measured instead of guessed.
--
-- The queue ordered by size under a ratcheting ceiling, then by size band.
-- Both are about WHERE THE BYTES ARE and neither is about whether a function
-- can be finished. A worker measured the second question across every
-- unsolved function: x87 instructions appear in 1,054 of them holding 38.6%
-- of the remaining bytes, jump tables in 376 holding 18.9%, and vetoing both
-- and taking branch density under 5% leaves 684 functions and 202,378 bytes
-- -- 11.3% of what is left, and the set every recent close came from.
--
-- The evidence for branch density is five closes in a week at 0.6% to 2.3%,
-- against 6-16% for every candidate a worker read and declined. It stands in
-- for how much of a function is a straight list of source statements, and a
-- list can be machine-extracted from the disassembly.
--
-- x87 and jump tables are VETOES rather than weights. Floating point brings
-- the whole x87 register-stack scheduling problem; a jump table brings a
-- switch whose arms the compiler lays out past the code, which is its own
-- open class.
--
-- Stored rather than computed per claim because decoding thousands of
-- functions is the expensive part, and a claim already came close to tripping
-- the supervisor's watchdog once.
CREATE TABLE IF NOT EXISTS function_closability (
  subject_sha  TEXT    NOT NULL,
  va           INTEGER NOT NULL,
  instructions INTEGER NOT NULL,
  branches     INTEGER NOT NULL,
  x87          INTEGER NOT NULL,   -- 0 | 1
  jump_table   INTEGER NOT NULL,   -- 0 | 1
  -- The size it was measured against. A corrected extent invalidates the
  -- measurement, and an entry was corrected on four functions this week.
  size         INTEGER NOT NULL,
  measured_at  REAL    NOT NULL,
  PRIMARY KEY (subject_sha, va)
);
CREATE INDEX IF NOT EXISTS function_closability_rank
  ON function_closability(subject_sha, x87, jump_table, branches);
`,
    verify: `SELECT COUNT(*) AS missing FROM pragma_table_info('function_closability')
              WHERE name IN ('branches','x87','jump_table','size')`,
    verifyExpects: 'nonzero',
  },
  {
    id: '025-near-miss-carries-its-source',
    sql: `
-- A NEAR-MISS RECORD WITH NO SOURCE.
--
-- The service owns the proof record -- an exact source lives in attempts
-- and nothing can lose it. It did not own the near-miss record: a park stored
-- the blocked class and the eliminations and NOT the candidate those were
-- measured against, so the candidate lived in a file under decomp/src/wip/.
--
-- Two workers reported the same consequence in one day. Records of 2,000
-- characters quoted their best source inline in prose while the wip file did
-- not exist, and one of them retyped a candidate out of the prose to continue.
-- That matters more here than almost anywhere else, because every function
-- above 1,024 bytes that has been proved closed on a SECOND PASS over an
-- earlier worker's written reading -- the candidate IS the deliverable of a
-- first pass.
--
-- Nullable: every existing row predates this and has no source to put in it,
-- and a column that forced one would have to invent it.
ALTER TABLE near_misses ADD COLUMN source TEXT;
`,
    verify: `SELECT COUNT(*) AS present FROM pragma_table_info('near_misses')
              WHERE name = 'source'`,
    verifyExpects: 'nonzero',
  },
];
