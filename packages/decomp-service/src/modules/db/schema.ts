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

export const MIGRATIONS: ReadonlyArray<{ id: string; sql: string }> = [
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
  },
];
