# Project Context

## Agent Operating Contract
- `CONTEXT.md` is the active memory and operating contract for the `open-empires` meta repository.
- `AGENTS.md` and `CONTEXT.md` are maintained at the meta repo root and govern agent behavior across workspace packages unless a deeper repo overrides them.
- Start every run by reading this file.
- Keep execution autonomous and momentum-oriented.
- Ask clarifying questions only when a decision is high-risk, irreversible, or product-direction changing.
- Update this file when project decisions materially change.

## Hard Rules
- Maintain `CONTEXT.md` autonomously; do not ask the user what to store here.
- Keep entries durable and reusable; avoid one-off incident logs.
- Prefer concise, decision-oriented wording over process-heavy prose.
- If repository facts contradict this file, update this file in the same run.

## Per-Run Output Contract
- Every final response includes: `Context Sync: read=<yes/no>, sweep=<yes/no>, updated=<yes/no>`.
- If `updated=yes`, include `Context Deltas:` with concise bullets.

## Engineering Standards
- Default to small, verifiable changes over speculative rewrites.
- Keep docs and implementation aligned in the same run when practical.
- Follow clean code, DRY, and SOLID principles.
- In TypeScript source, prefer static ES imports over CommonJS `require(...)`.

## Canonical Docs
- `packages/open-empires-web/docs/prd.md`

## Product Scope (Current)
- Build a browser-native, multiplayer RTS inspired by AoE2 using TypeScript.
- Primary game loop: gather resources, build, train units, fight, and resolve win/loss.
- Movement model: grid-based global pathfinding plus continuous local collision/avoidance.
- Multiplayer model: authoritative server simulation with client interpolation.
- The BoxedWine/WebAssembly AoE2 runtime experiment is a separate, tangential research track contained to `packages/aoe2-in-browser/`; it is not a product architecture pivot.

## Technical Decisions (Current)
- Backend authority model: SpacetimeDB reducers as simulation authority.
- Backend data model now uses normalized SpacetimeDB tables with `u64` auto-increment primary keys for players, datasets, maps, units, unit metadata, and unit action sprite mappings.
- Backend action architecture is data-driven: action definitions live in metadata tables and are executed by generic simulation reducers instead of one reducer per action type.
- Core action effects are property-based deltas (`add`/`sub`/`set`) applied to source/target unit properties (for example, chopping lowers a tree death property; gathering lowers resource stock and raises carrier stock).
- Entity lifecycle is property-threshold driven: unit/resource nodes can "die" when a configured property reaches `0`, then despawn or transform into a configured replacement unit metadata row.
- Some effects remain explicit interpreter primitives rather than pure property deltas: conversion uses a channeled probabilistic `transfer_owner` effect, and monk relic carrying is modeled as `garrison`/`ungarrison` (relic entity stored in monk capacity) instead of replacement.
- Backend reducer baseline now includes deterministic `create_empire`, `enqueue_action`, and `tick` flows with normalized action-queue links (`action_sequence_nodes`) and explicit garrison relationships (`unit_garrisons`) to support generic effect execution.
- Tick execution now enforces action min/max range constraints by superseding out-of-range actions with deterministic one-tile movement (toward targets when too far, away when too close) until in-range execution is possible.
- Backend map flow now includes deterministic `create_map` terrain/resource generation with dataset-tied terrain weights, terrain dominance ordering, transition variant rules, and map-linked spawn definitions (`map_spawn_units`) for both neutral/nature and player-start units.
- Backend dataset ingestion now treats `dataset.json` as the source of truth for all `datasetId`-backed metadata tables, with Effect Schema-based type-safe parsing/validation and a generated JSON Schema contract (`dataset.schema.json`) for editor/tooling `$schema` usage.
- Immediate implementation phase: local browser prototype with no backend dependency.
- Current prototype view/model: isometric tile terrain with grid outlines and non-walkable water tiles.
- Current input model: click/drag multi-unit selection with shared right-click move commands.
- Drag-selection behavior: selection start is anchored to a world/map position while dragging; visible drag end is clamped to game-canvas bounds.
- Camera control model: arrow keys + window-edge mouse scrolling; reserve WASD for future hotkeys.
- Camera edge-scroll tuning uses `CAMERA_EDGE_SCROLL_BORDER_PX` in `packages/open-empires-web/src/index.ts`.
- UI terminology: `game canvas` refers to the non-HUD gameplay render region.
- Minimap input model: left click/drag on minimap pans camera focus.
- Current HUD model: AoE-style bottom HUD with integrated bottom-right minimap frame, flat shared background, and vertical section separators (no inset panel rectangles); top/bottom HUD bars share the same per-theme base/background palette.
- Top HUD model: thin AoE-style header with resource/pop counters, centered sign-in button, and top-right controls including day/night toggle, tech tree, diplomacy, chat, and settings (settings furthest right).
- HUD modal model: top HUD buttons open centered canvas popups titled by scenario (Settings, Tech Tree, Diplomacy, Sign In).
- HUD modal sizing model: modals target wider layouts (up to 1000px width) while preserving minimum visible game-canvas margins on all sides.
- HUD modal positioning model: center in game canvas by default, but switch to screen-centered/clamped positioning when vertical game-canvas padding is exhausted.
- HUD modal layering model: modal overlay renders in final frame pass above all world/HUD text/minimap content.
- Game canvas model: world rendering/camera viewport is clipped to the area above the HUD (no world rendering under HUD).
- Current render model: terrain/grid pre-rendered to a cached layer and composited each frame for smoother camera movement.
- Current camera model: tile-centered focus camera (screen center maps to a map tile position), clamped directly to valid tile coordinates.
- Camera debug behavior: center pixel is rendered black and the tile containing that center focus is highlighted white.
- Minimap viewport overlay is clipped to minimap diamond bounds.
- Minimap render model: draw/map interaction is diamond-only (no rectangular black map box), and viewport overlay is clipped to that diamond.
- Minimap background model: minimap frame does not force a dark fill; panel background shows through around the diamond map.
- Camera/minimap organization: camera math/debug lives in `src/game/camera.ts`; minimap projection/render/input mapping lives in `src/game/minimap.ts`.
- Debug toggle: `DEBUG_CAMERA_FOCUS` in `src/index.ts` controls white focus-tile outline + black center pixel visibility.
- CI/CD model: GitHub Actions builds Bun static export (`dist/`) and publishes it to `gh-pages`.
- Tick model target: fixed server tick in the 10-20 Hz range for MVP.
- Client stack: TypeScript with Canvas-first rendering, preserving a migration path to WebGL batching.
- Pathfinding architecture: replaceable module boundary with deterministic tie-breaking and budgeted/incremental execution.
- Asset strategy: progressive loading and modern compression; keep initial playable load small.
- Sprite asset pipeline direction: parse AoE SLP in TypeScript and pre-convert to web-friendly outputs (lossless WebP/PNG + sidecar frame metadata), while preserving player-color pixels as runtime-remappable mask/index data; keep parser modules reusable for future browser-side mod/import tooling.
- `packages/open-empires-datasets` now includes a TypeScript SLP conversion CLI that outputs per-frame base PNGs, player-mask PNGs (red channel stores SLP player shade index), outline-mask PNGs (red channel stores outline type), and `metadata.json` sidecars for runtime sprite assembly; current decoder scope is AoC-style SLP `2.0N`, with optional Sharp-based rendering of player-color-composited animated WebP exports.
- `packages/open-empires-datasets` also includes a separate TypeScript DRS extraction CLI (`extract:drs`) that unpacks Genie `.drs` archives into prefixed file outputs (for example, `graphics.drs -> graNNNNN.slp`) matching the existing extraction folder naming convention.
- AoE2/BoxedWine browser experiment: its bootstrap scripts and `aoe2.zip` archive are no longer in the package tree (checked 2026-11-01).
- `packages/aoe2-in-browser/work/` (round briefs and write-ups, GUIDE.md, TELLS.md, the risk register, tools, memory mirror) was retired on 2026-11-01. Findings about unproven functions were merged into their parks; disassembly tells are in `decomp-service/src/workflows/decompile/README.md`; open risks are in the README of the module they concern (`modules/wasm`, `modules/import-names`, `modules/globals`). Round ids below (r98-x, r111-c, …) name write-ups that no longer exist.
- The AoE2 browser package is a Git submodule. Reproducibility from the parent
  requires a package-repository commit containing `aoe2.zip` and the scripts,
  followed by a parent-repository commit recording the updated submodule
  pointer; the current local package repository has no commit yet.
- The AoE2 decompilation service and dashboard live INSIDE the submodule, at
  `packages/aoe2-in-browser/decomp-service` and
  `packages/aoe2-in-browser/decomp-dashboard`. Sibling top-level packages must not be
  created for this track: the research track is contained to `packages/aoe2-in-browser/`,
  and a sibling package would sit in a different repository from the work tree it serves
  (subject binary, toolchain, proof records). The service resolves the work root as
  `import.meta.dir` + `'../../../..'`.
- OUTSTANDING DEFECT (decomp-service), RE-MEASURED 2026-10-21 by r128-k and the field name
  corrected: `POST /api/work/park` refuses an append that carries no **`blockedClass`** even when
  only the `note` is being extended, so a note-only correction is impossible — a worker wanting to
  correct prose must restate a class or leave the error standing. The guard is right in intent (a
  park must say why it gave up) and wrong in scope (it should require a reason only when the park is
  NEW or its class changes). **Measured live: `{"agent","va","note"}` to the raw route returns
  `400 ParkWithoutReason` with `detail.missing == "blockedClass"`, not `eliminated`.** This entry is
  now the accurate one: **`oe_lib.py`'s own comment (~line 1702) and the agents' common brief's newest park
  section (both retired) both claimed a note-only append is accepted** ("re-verified live against migration 44 by
  r102-e: HTTP 200, `appended: true`") **and both are stale.** Two further facts from the same run:
  an append that **OMITS the `source` key preserves the banked source** (`wipCharsBefore 2911 /
  sourceChars 2911` across two appends sending none), which resolves the ambiguity in `park`'s
  docstring — it banks nothing new and destroys nothing; and **`oe_lib.park` cannot append to any
  park below `/api/work/parked`'s 500-row cap at all**, because it calls `parked_record(va)` at
  `oe_lib.py:1722` *before* its POST at 1736 and that raises, so the write never happens (no
  double-write risk) and the raw route is the only way in for five to seven parks per band.
- DATA DEFECT (proof corpus), found 2026-10-15: **a proof produced by `substitute.py` carries
  its ANCESTOR's prose.** The proven 0x598EA0's header states `ret 0x14` and five dwords; its
  own bytes are `ret 4` and one dword. The code is right and the header describes the proof it
  was derived from. **Read a substituted proof's code, not its prose** — and when a proof is
  used as a template, verify its arity and member layout against its own listing. A sweep for
  substituted proofs whose header arity disagrees with their `ret N` would quantify this.
- DECISION (inventory), 2026-11-11: **a function's length has one rule, Discovery's `Measure lengths` step**
  (`decomp-service/src/modules/discovery/function-length.ts`). Each record is measured from its entry by the closing
  rule, bounded by the next record and by its library object's end (`crt_identifications.object_length`), and
  corrected only where the bytes contradict it; a function found in the bytes it gives up is recorded first, and a
  refused recording refuses the cut. A library object is longer than its function's record by design: its section also
  holds the function's own switch tables and its `__except` filter and handler, which the inventory records apart
  (0x6180CB: 440 + 4 + 8 = 452; 0x61F6EC: 1,185 + a 48-byte table = 1,233). Own trailing switch tables sit outside the
  record, as every proven one has them; trailing padding may stay inside. Each turn stores the proven records the rule
  measures otherwise and what it would do were they unproven: that must never be a correction. It replaced 'Fix sizes',
  'Correct extents' and 'Split at exact prefixes'. The 0x587FD0 / 0x588180 overlap of 2026-10-14 was corrected to 389
  and proved with no agent on 2026-11-08.
- DECISION (inventory), 2026-11-11: **Scan gaps records the functions in code no record holds, only while its rule
  is wrong on no proven function.** Each scan first puts the rule to every proven function's own bytes as if no record
  held them (`gap-calibration.ts`); one wrong record holds all recording. Gap entries keep the length rule's guards (no
  switch-table arm, no code the code before runs or branches into, no branch past the measured end, no early
  terminator nothing reaches past). A rejection the rule reads as a function is withdrawn and the function recorded.
  `/GX` exception code is not recorded by this rule.
- DECISION (inventory), 2026-11-12: **Exception code is recorded as functions, each under its parent**
  (`exception-code.ts`, Discovery's 'Record exception code'). Each unwind funclet and `__ehhandler` stub a
  `_s_FuncInfo` names becomes a function; its parent is the function whose prologue pushes the stub and stores `esp` in
  `fs:[0]`. Found: 708 blocks, 2,121 entries, each block with exactly one parent; 1,644 entries are of proven parents.
  Their bytes compile from the parent's source: 0x401000's proof emits its `.text$x` section as the 18 bytes at
  0x620D30, relocations aside. Decompile lists them as waiting on their parent's proof and gives them to no agent,
  because an agent can only transcribe them as `__asm`, and 96 such transcriptions were deleted. Proof through the
  parent, comparing the parent's compiled `.text$x` with each entry, is not built yet.
- DESIGN DEFECT (decomp-service), evidenced 2026-10-14 and worth 82,590 unparked bytes:
  `claim` builds its sibling-template pool with `ORDER BY ABS(p.va - ?) LIMIT 400`
  (`SIBLING_POOL`, `decomp-service/src/modules/work/impl.ts`), so `rankSiblings` only ever sees the 400 proven
  functions nearest BY ADDRESS, and `matchRatio` compares them character-by-character over the
  space-joined mnemonic string. An image-wide instruction-sequence screen found that **54% of
  341 high-similarity pairs (46,982 bytes) have their best template outside that window**; one
  close used a template at address-rank 502 and another at 4,083, and on 0x489300 the claim
  route's best offer scored 0.338 against the real template's 0.962. `GET /api/work/shapes`
  refuses a whole-image call and does not contain the calibration pair even within its window.
  **The fix is an instruction-sequence index maintained by a producer job (like `portable` and
  `discovery`), read by `claim`** — not a larger `LIMIT`, because rankSiblings decodes each
  candidate and an unwindowed route has starved every worker here before. Normalise to
  mnemonics plus operand KINDS: finer (register width, esp/ebp identity, memory base class)
  measurably ranks worse, and the normaliser must RAISE on an unclassified operand — doing so
  caught 1,365 of 7,442 extents in four families a silent fallback would have mis-tokenised.
  Interim data: `r98-x-matches-g1.json.gz` in the session scratchpad holds 341 rows with five
  candidates each.
- PHASE 4 CORRECTED 2026-10-15, superseding the entry below: **the `__asm` debt is 26 proofs /
  5,345 bytes, not 63 / 7,231** (and the share is 0.98%, not 1.04%). Of the 63 `__asm` proofs,
  **27 are already filed CRT-supplied**; of the 36 the service files as work owed, **10 are CRT
  routines `decomp/crt_identified.json` MISSES** (594 B — one proof says in its own text that
  its 15 bytes are a COFF symbol `__clrfp` the JSON lacks), **10 are complete recovered C++
  whose only `__asm` is a `nop` or `int 3`** (2,329 B — `nop` is the only MSVC 6 spelling for an
  empty `if` body, so 0x530CF0 is 634 bytes blocked by seventeen of them; 9 of the 10 convert by
  deleting a no-op statement), and **16 are genuine hand-written assembly** (3,016 B) — of which
  **14 are two prebuilt library modules** (the 0x607xxx decompressor, 1,832 B, and 0x60EB80's
  MPEG filterbank, 1,041 B) whose entire external surface is **two `__cdecl` entries with all
  three call sites inside one proven function**, so a library substitution is viable.
  **The dominant phase-4 gap is not `__asm`: it is the 2,084 never-proven functions, absent from
  the tree entirely.** 5,214 units written (3,861 converted + 1,353 needsGlobals), 144 refused
  (105 CRT + 36 `__asm` + 3 SEH, and all 3 SEH are CRT too); `blocksTheBuild` reads 39 of which
  **13 are misfiled CRT**.
- PHASE 4 DEBT INSIDE GREEN PROOFS, found 2026-10-15: **a wrong declared callee arity is
  invisible to the byte gate and visible to the portable link.** Both readings of a call pop the
  same total, so the push run is byte-identical; what the arity changes is the argument-list
  NESTING, hence evaluation order, schedule and register assignment. A park with 14 refuted
  spellings whose class said the residue was "not reachable from the source" closed on a FIRST
  PROBE with no statement changed — only two callees' declared arity (0x425610 pops 20, not 2;
  a virtual slot pops 12, not 6). **Two already-proven functions carry three wrong callee
  arities between them** and will stay proven. This
  belongs in the same bucket as the 2,084 never-proven functions as a reason the portable tree
  does not link.
- DEFECT (portable tree), found 2026-10-15: **356 of the tree's 705 "which the tree names
  sub_00XXXXXX -- this member is not wired to it" messages name a unit the tree does not
  contain** (250 distinct addresses, each `NoProofInForce`). `convert.ts:1312` builds that
  sentence from an in-range address alone, while the `standInsOverProvenCode` FIGURE
  (`impl.ts:666`) correctly filters on the proven set — so the number is right and **the
  artifact over-claims the wiring job by 2x**. (Its census tool is retired.)
- CORRECTED 2026-10-21 by r128-q2, and the correction unblocks every `/O1` band:
  **`POST /api/work/amend` DOES honour `flags`. It has an ALLOW-LIST of exactly the two proof
  buckets — `"/O1 /GX /GR-"` and `"/O2 /GX /GR-"` — and any other string falls back SILENTLY to the
  `/O2` default.** Measured two-sided on one source by the echoed `comparison.flags` and by two
  distinct self-digests: omitted / `/O2 /GX /GR-` / `/NONSENSE-NOT-A-FLAG` / `/O1` / `/O1 /GX` and
  seven `/O1 /<letter> /GX /GR-` spellings all echo `/O2 /GX /GR-` (ecs 508, digest `4f21adf70f53`),
  while `"/O1 /GX /GR-"` echoes itself (ecs 452, digest `79b024256c47`). The 2026-10-15 reading was
  right about every string it tested and wrong about the parameter: `/O1 /GX /GR-` had never been
  tried, because every band that wanted it is an `/O1` band and every `/O1` band had been told the
  parameter does not work. **Consequences: a dry-run `amend` on a CLAIMED, UNPROVEN `/O1` row now
  gives a correct verdict (it defaults to `/O2`, which on that band reads a byte-exact source as
  `diff 310`); a flag sweep BETWEEN the two proof buckets is free and needs no probe; and the
  `/O1`-carrier workaround plus `lab_vs_subject.py`'s missing `carrier=` CLI argument stop
  mattering.** Only non-bucket letters still need `probe`'s `flagSets`, and for those
  `#pragma optimize` is honoured inside a bucket. A dry-run `amend` still returns `emittedSha: null`,
  so group its results by a self-digest.
- GAP (decomp-service), found 2026-10-15: **`/api/discovery/entries` does not expose `heldBy`**
  while `/api/discovery/callers` does, so a range-based round cannot see a parallel round's
  claims. `GET /api/work/band` does carry `parked` and `claimed` and is the route to prefer.
- REPO EXPOSURE, re-measured 2026-10-20 — **IT HAS NOW COST A FILE, so this is no longer a
  hypothetical.** **17 of 362 tools and 20 of 220 round files are tracked in git; 1,078 paths
  under `work/` (retired 2026-11-01) were untracked (12.3 MB), none of them ignored.** Since 2026-10-15 the tool count
  grew 235 → 362 and the tracked count did not move.
  **The first loss, and its cause is now KNOWN — it was a collision between two live rounds, not
  an unexplained deletion.** `band_callee_rank.py` ran for r107-a and 40 minutes later
  did not exist. **r107-d wrote that file**, then found `r100-a-callees.py` already did the job,
  and **removed its own duplicate by inverse edit** (`os.unlink`, correctly never `rm`) — while
  r107-a was using it. I first recorded the cause as unidentified; that was wrong and this
  corrects it. Nothing in `decomp-service/src` or `scripts/` deletes under the tools folder (checked),
  which is still true and is why the shell was never the suspect.
  **The exposure is what made a tidy-up indistinguishable from data loss**: untracked, the removal
  left no diff, no reflog and no notification, so r107-a could only observe that a file it had
  just run was gone. Both rounds behaved defensibly in isolation — one declining to add a
  duplicate screen, the other using the best screen available — and the shared, unversioned
  tools folder is what turned two correct local decisions into a loss. r107-a committed
  `band_proven_callee_rank.py`; at the moment of deletion the removed file *was* the
  better of the two, because `r100-a-callees.py` then counted an intra-function `jmp` as a callee
  (since fixed), so its `callees` column was an upper bound. Every round file from r97 onward — the method record the
  GUIDE cites — still exists only in the working tree. Also **`commit.gpgsign` is true and
  `ssh-keygen -Y sign` hangs** with no agent identity, so an automated commit stalls until a key
  is loaded. **The commit decision is the user's and is open; it is now actively costing work.**
- PHASE 4 DEPENDENCY, measured 2026-10-14: **63 proofs / 7,231 bytes (1.04% of proven bytes)
  contain `__asm` after comment stripping** — 42 of them `__declspec(naked)`, 3,302 bytes.
  `portable/convert.ts` refuses them (`hand-written __asm`) and the service correctly files
  that as work owed rather than as a benign refusal, unlike `_sprintf`/`_fopen` which the wasm
  toolchain supplies. **A byte-exact `__asm` proof closes a park and does not advance phase 4:**
  each of the 63 still owes a real C++ reconstruction or a hand-written portable equivalent.
  Largest: 0x60EB80 (1,041 B), 0x607D7D (851), 0x530CF0 (634), 0x4C5C00 (529), 0x5305A0 (401),
  0x41FD10 (387). The route is legitimate for a WHOLE routine (`decomp-service/src/workflows/decompile/README.md`) and forbidden for
  a mid-routine slice or compiler-generated code; 0x616D9A was correctly refused on that basis.
  Re-measure with a comment-stripped `__asm` grep over the proofs.
- OUTSTANDING DEFECT (decomp-service, DATA LOSS): a `park` append that omits `source` makes
  the service adopt the `wip/` file, and the shrink guard then compares the result against
  THAT SAME FILE, so it cannot see the loss. One round destroyed 3,418 characters of its own
  reconstruction at HTTP 200 and restored it by hand. The guard must compare against the
  BANKED source as well as the file. Until fixed, every worker must send `source` explicitly.
- OUTSTANDING DEFECT (decomp-service): `park` resolves `wip/sub_<EIGHT upper-hex>.cpp`, but 38
  candidates totalling 265,274 characters were written with SIX hex digits and are therefore
  invisible to it. Six are at parked addresses whose banked source is shorter by 35,305
  characters; 28 are at addresses with no park record at all. All 38 are tracked in git.
  **Do not bulk-rename:** `sub_5500a0.cpp` (1,201 B, 51 lines) and `sub_005500A0.cpp` (1,401 B,
  43 lines) are DIFFERENT content for the same address and must be read and merged by hand.
  The fix belongs in the service (normalise the address to one canonical filename, and migrate
  the six-digit files once), not in a rename script.
- Not a defect, confirmed: the 26 `wip/` files that `git status` reports deleted correspond to
  functions that have since been PROVEN. The service retires a draft when its function closes;
  checked 0x402E90, 0x41B4E0, 0x426280 and 0x42A520, all proven.
- OUTSTANDING DEFECT CLASS (decomp-service), third instance 2026-10-15: **unknown query keys
  are silently dropped on at least three routes**, and each instance has invalidated a published
  figure. `/api/work/parked` ignores an unknown filter; `POST /api/work/amend` SILENTLY FALLS BACK
  TO `/O2` for any `flags` string that is not exactly one of the two proof buckets (so a "14-bucket
  flag sweep" was one bucket compiled fourteen times — but the two buckets themselves ARE
  selectable, corrected above); and **`/api/work/band` ignores `provenNeighbours`** — a parameter that was written into the agents' common brief, their guide
  and a coordinator brief (all retired) and **has never filtered anything**. The real parameter is
  `neighbours` (a minimum) and the real default `maxBranches=2` hides 84% of the band: the
  `neighbours=2` surface is **419 rows / 248 free / 175,636 bytes, not the 84 everyone quoted**.
  The routes DO echo an applied-`filter` block, which is how this was caught — **the fix is to
  refuse an unknown key, and the interim discipline is to assert the echoed filter.**
- OUTSTANDING DEFECT (decomp-service): `GET /api/work/parked` silently IGNORES an unknown
  query parameter instead of refusing it, and its default page is 25 records size-descending.
  A mistyped filter therefore returns the biggest 25 parks and looks like an answer. The same
  class of defect was fixed on another route after `max=120` was dropped; this route was
  missed. Fix when no rounds are running, since deploying needs a service restart.
- The dashboard's recovery log (`/api/milestones?step=N`, rendered as the "Recovery log"
  section) answers "is it moving", which neither the chart nor the written note can: one row
  per N functions first proved byte-exact, newest first, with the gap since the previous
  milestone and the rows that ran at least 3x the usual gap marked. `medianGapHours` is taken
  over NON-ZERO gaps only and the response carries `undatedRows`: `solved_at` was backfilled,
  so the earliest 2,350 functions share one timestamp and those milestones have no interval.
  Counting them halved the median (0.17h against the real 1.16h) and made every ordinary
  4-hour stretch read as a stall. The newest row is the LIVE count, not a finished batch --
  the service appends it so an ongoing hold shows before the next batch lands -- and it is
  labelled as such in the row ("now, 30 of 50 toward the next"), identified by
  `reached % step !== 0` rather than by position.
- Agent operating docs for the decompilation track live in the service: each workflow's prompt sits beside its definition under `packages/aoe2-in-browser/decomp-service/src/workflows/` (the proving round's is `proving-round-brief.md`). The old `work/batches/` docs were retired 2026-11-01. A shared file that several agents append to races: one such guide silently lost half of a batch's write-ups.
- AoE2/BoxedWine browser resolution model: resolution is pass-through, not viewport-fit. The selected guest resolution is passed to BoxedWine/AoE2 at boot and the canvas is displayed 1:1; if it exceeds the viewport, the page scrolls. Changing resolution restarts Wine/AoE2.
- AoE2/BoxedWine browser resolution persistence uses origin storage only: localStorage when available, otherwise a first-party cookie. Resolution query parameters are prohibited; changing the selector reloads the same clean URL.
- AoE2/BoxedWine browser persistence uses one stable `/root` IDBFS mount plus boot-time pruning: SaveGame, Scenario, and recording folders are preserved, while Wine runtime, registry, and lock state are recreated from `wine3.zip` on reload/resolution change. Versioned runtime roots are not part of normal app behavior.
- AoE2/BoxedWine browser launch uses `age2_x1/age2_x1.exe` without the desktop-only `game=aoc`/`nostartup` arguments; the browser executable's own patch selector/startup flow is the compatible web path.
- AoE2/BoxedWine final translation target is a profile-guided hybrid with no shipped interpreter fallback: ship a canonical offline-AOT WASM baseline plus an x86-to-WASM completion tier that pauses on an unknown block, translates it before first execution, runs only the translated WASM, and persistently caches the emitted module keyed by build/module/address/code fingerprint/translator ABI so the same byte-form is compiled only once across runs. Unsupported blocks halt with an exportable diagnostic for maintainer work. Runtime-discovered blocks must be foldable into the next offline baseline. Keep the verified unoptimized baseline separate from optional optimized/native-API-substituted artifacts so optimization remains reversible and parity-testable.

## Risk Policy (standing, set by the user 2026-10-16)

**Each open risk is recorded in the README of the module it concerns** (`decomp-service/src/modules/<module>/README.md`; the single `work/RISKS.md` register was retired 2026-11-01), **and it is maintained, not
written once.** Every risk is tracked and worked; none is left as a note in a park or a clause on
a dashboard card.

**The question that orders the register is not "how big is it" but "can the evidence we already
have settle it".** A risk that cannot may force a restart from a new evidence point — a longer
memory dump, a different capture, a second toolchain — and **everything built after the point we
would restart from is work lost.** The cost of an unassessed risk therefore grows every day the
project builds on top of it.

**Priority order: UNKNOWN first, then NEEDS-NEW-EVIDENCE, then the rest.** An UNKNOWN outranks a
known NO, because a known NO can be planned around today. "Unknown" must never be reported as
"fine".

Three rules that follow, each written because it was broken:

- **A definitional correction is not progress and never shares a column with work.** Reporting
  "14 → 0" in a before/after table beside "82,317 → 1,091 bytes" made a redefinition read as a
  risk solved. State what the old figure counted, what the new one counts, and that the work is
  unchanged.
- **A risk gets a figure and a route, or it is not tracked.** The real import risk — 456 of 736
  call sites resolved by inference rather than checked against the call instruction — existed only
  as a sub-clause on a card counting successes, so a reader looking for risk found reassurance.
- **Every check needs a negative control proving it can go red.** Several figures that could not
  fall have shipped.

## Where the Remaining AoE2 Decompilation Work Actually Is (measured 2026-10-16)

Every figure below is live from `GET http://127.0.0.1:8787/api/status` at 5,608 proven functions,
after the 708-record exception-table derivation was deployed and the globals inventory rebuilt:

| blocker | figure | state |
|---|---|---|
| code we cannot attribute to a function | 80,819 B in 501 stretches, of which **1,091 B in 14 stretches are UNEXPLAINED** | the rest is classified: 44,540 B of jump tables (511 of 512 dispatch-confirmed), 30,605 B compiler-generated, 3,287 B shared tails, 1,296 B static data |
| data pointers with no owning object | **674 of 1,726** (was 1,382) | halved by naming the 708 `_s_FuncInfo` records; the honest residue is ~126 after classes D and E are read one at a time |
| code pointers with no owning object | **277 of 13,093** (was 1,690) | same derivation, non-transitively |
| pointers that resolve nowhere | **1 of 14,819** | not a blocker; it has been misreported as one |
| Windows import slots unanswered | **0 of 255** (14 unreferenced) | closed |
| signature conflicts filed | **0** (was 19) | closed; the callee-derived figure reads **7**, a different set |
| functions that will not decode | 1 | a decoder artefact on a proven function |
| parked functions | 430 functions, 313,903 B in 401 distinct causes | the largest family, 29 survey parks / ~72,000 B, is **untried work, not a wall** — see below |

Two measurements reclassify a large share of the remaining work:

- **A banked survey transcribes.** 37 parks carried the class `NO CANDIDATE HAS EVER BEEN COMPILED
  AGAINST THIS ADDRESS`, their `source` a written structural reading rather than a reconstruction.
  Six have now been transcribed: first-compile length errors of **+2, +5, 0, 0, +8 and +44**, with
  five closing byte-exact. **And survey DENSITY — characters of reading per byte of code —
  predicted the first-compile verdict in order: 12.3 ch/B closed byte-exact on one compile, 6.0
  took 13, 3.3 took 20.** Order the remainder by that figure, computable from one
  `/api/work/parked` call. It is distorted only where one survey file covers several addresses
  (the 0x618000–0x61A000 CRT window).
  A survey park's dry-run verdict looks catastrophic and is not: `compiled: true`,
  `emittedCodeSize: 0`, `differingBytes` = the whole extent, `masked: 0`, `compared: 0`,
  `firstDiff: null`, no `comparison` object — a translation unit defining no function.
- **142 unproven functions have a real symbol name**, from `decomp/crt_identified.json` matching
  297 addresses against the install's own `LIBC.LIB`; 7 of the 9 whose Microsoft source is on disk
  are now proven (3,327 B). **`VC98/CRT/SRC` is one revision AHEAD of `VC98/Lib/LIBC.LIB`**, so
  the newer source always has code the library **lacks** — the edit is a guard to **delete**,
  never code to add. Where the revisions agree, transcription is free. The bucket above 0x606000
  is `/O1 /GX /GR-` for every C-library object; the EH and intrinsic objects (`trnsctrl`,
  `exsup`, `ftol`, `llmul`) are `/O2`, interleaved at 50-byte granularity. 39 of the remaining
  133 are hand-written x87 assembly needing an `__asm` route that does not exist yet.

**A wasm signature mismatch is a hard `wasm-ld` error ONLY where the symbol is UNDEFINED.** Where
an object defines it, the call binds with a warning at exit 0, and variadic-against-fixed at equal
arity is not even a warning. **So the link gets quieter as more functions are proven, and a
miswiring arrives silently** — phase 4 ships one module, so that is a wrong game rather than a
failed build. The conflict table is a correctness instrument, not a list of link-stoppers.

Operational notes: the service listens on **port 8787** (a probe of 3001 returns `http 000`,
indistinguishable from an outage); the compiler image is **`oe-cc`** and holds no toolchain —
`cl.exe` is mounted from `local/inputs/toolchain/` (see `decomp-service/src/modules/repo-paths.ts`); and **the supervisor deliberately
does NOT reload on edit**, restarting only on child exit or a failing health probe, so a service
change needs a deliberate restart at a moment when `health.compiler.active` is 0.

## Repository Snapshot
- Repository role: `open-empires` is the meta monorepo; product code currently lives under `packages/`.
- `CONTEXT.md` and `AGENTS.md` live at the repo root as the agent policy/memory entrypoint.
- `packages/open-empires-web/docs/prd.md` is the product source-of-truth.
- AoE2 decompilation state (phase 2, byte-exact recompilation under MSVC 6.0 SP3): the
  proven count is a ROLLING figure and `GET http://127.0.0.1:8787/api/health` is the live
  one (**5,236** at r98-s; do not quote a stale literal from here). The byte and percentage
  figures below are the last full measurement, taken at **5,225** functions:
  **689,662 bytes = 30.54% of `.text`** — but
  the honestly VERIFIED figure is **608,858 bytes = 26.96%**. The gate excuses relocation
  fields it cannot check, and 80,804 such bytes (20,201 fields) sit inside proven functions
  and were never compared. Quote both figures; the gap is not an error, it is the limit of
  what a byte comparison can establish.
- The gate's `compared` field is NOT the count of compared bytes: `masked` counts a
  relocated byte only when the two streams DISAGREE, so a relocation whose unapplied value
  coincides with the subject is counted as compared. **Note the emitted stream is not always
  zero there: a relocation with a negative addend (`SYM-4`) emits `fc ff ff ff`, so its top
  byte is masked despite the subject's byte being zero.** The project-wide shorthand
  "relocated bytes whose subject value is nonzero" was wrong and was corrected in
  the agents' common brief (since retired); the GATE's own figures were always right, only our
  prediction of them was off. The honest figure is
  `size − |relocatedOffsets ∩ extent|`; 2,749 of 5,225 proofs (52.6%) overstate by 20,624
  bytes in total.
- **PHASE 4 CORRECTED 2026-10-16 by r103-ai, superseding the entry below: THE TREE DOES NOT
  LINK.** Re-measured from the repo (with a shell build script, since replaced by the service's `wasm build` job; the harness
  risk D1 was about — `verify.ts portable-compiles` writes its module to `/tmp` *inside* the
  container, so the module it proves exists is destroyed on exit): at 5,647 proofs,
  **`linkedAsIs 0`**. `0x4792F0`'s proof (r102-p, 02:03 today) declares `extern int g_cnt_x;`
  and `extern int g_tab_x[];` with no address, and an undefined **data** symbol is fatal even at
  `-sERROR_ON_UNDEFINED_SYMBOLS=0`, so one proof refuses the whole module. The project's own
  `bun src/verify.ts externs` says exactly this and had not been run; the addresses are
  **0x68cc98** and **0x68d8bc** and the amend is byte-neutral. Also **16 units do not compile**
  (14 hand-declare a `size_t` CRT function as `unsigned int`; 2 use `NULL` undeclared), so
  `did not generate IS 0` is refuted. Excluding the one refusing object, the module is
  **9,811,412 bytes / 5,443 address-named exports / 369 imports** — not 7.63 MB / 4,143 / 3,915.
  **There is no live figure anywhere for "does the tree link"**, which is why this stood for
  eight hours and three briefs.
- Phase 4 (WebAssembly), superseded figures: all 5,070 rendered units compile and the tree links
  as ONE wasm module, strict link ~7.63 MB, 0 signature mismatches; 342 undefined symbols over
  3,556 references remain.
- **Phase-4 link signatures: RESOLVED 2026-10-15, and the first diagnosis was wrong.**
  The claim that *"14 addresses declared `void(void)` against `void(void*)` will stop a
  `wasm-ld` link"* was **false**. Those rows are a CONVENTION artefact: the `void(void)` side is
  always the address's own **member** definition with an implicit receiver, and `convert.ts`
  gives that member's rendered thunk `void *self` first (`EntryPoint.takesSelf`). Every such row
  carries exactly **one** wasm signature in `decomp/port`, `void(i32)`. The figure 14 does not
  reproduce under any reading (9 / 10 / 11). Proof it is an artefact: **fixing a real blocker
  CREATES one of these rows.**
  The real population was **six**, found only by asking the question of the tree the linker is
  handed — keyed on the ADDRESS (so `oe_4c8940` and `sub_004C8940` are one symbol) and **lowered
  to wasm types**. **Five of the six were invisible to both existing audits.** All six are fixed
  byte-neutrally, and the (since retired) `port_link_sigs.py` read **`symbols with TWO
  WASM SIGNATURES 0`** over 5,406 files / 5,483 address-named symbols, with
  `GET /api/work/shared-names` reading `stopsTheLink: 0` (was 1). Verified independently by the
  coordinator.
  **The conflict split nobody had computed:** of 463 conflicts, **293 are one wasm signature, 12
  are the receiver artefact, and 158 genuinely differ in wasm — 147 of those RETVOID.** PTRINT
  (131), PTRNAME (170), WIDTH (58), RETWIDTH (28) and RETPTR (5) are all `i32` against `i32`:
  real defects with **zero link risk**. **RETVOID is the next round's target**, being the largest
  wasm-visible class by 20x. Undefined symbols measured at **110 address-named spellings defined
  nowhere over 456 references** — 89 coverage, 21 non-canonical, 1 renameable. The audit also shows the
  conflict corpus was missing half its evidence: counting each record's OWN entry definition,
  which `verify.ts declarations` cannot see, takes signature-carrying addresses from 1,739 to
  **4,154** and disagreements from 219 to **466** (335 real, 271 own-proof-against-caller).
  Classes: PTRINT 173, RETVOID 148, WIDTH 86, ARITY 17, FLOAT 8, VARIADIC 4. 17 conflicts filed
  (ids 28-44), 3 resolved. **A byte-exact proof outranks a caller's declaration**, and a float
  reconciliation must reach the value's own declaration — forwarded slot, record member, or the
  caller's parameter — because half of it costs +6 to +14 bytes (4 for 4).
- Web client code is organized under `packages/open-empires-web/src/game/` modules (`iso`, `terrain`, `units`, `camera`, `minimap`, `hud`) with `packages/open-empires-web/src/index.ts` as orchestrator.

- **Where the project's learning lives.** Proofs, parks (with every finding about an unproven function), trials and agent transcripts are rows in `decomp.db`; disassembly tells are in `decomp-service/src/workflows/decompile/README.md`; facts and open risks about a module are in its README. The `work/` folder that held GUIDE.md, round write-ups, tools and a memory mirror was retired on 2026-11-01.
- **Before any blanket `git add`, exclude the database backups.** `decomp-service/data/decomp.db`
  (251 MB) is tracked and holds the proofs. `decomp-service/data/backups/` holds hourly snapshots
  of it — **1.245 GB of the 1.26 GB of untracked bytes**, and redundant with the tracked file.
  `decomp-dashboard/.next/` is build output. The genuine untracked work is about 12 MB.

- **"Code we cannot find" is 90.6% accounted for, measured 2026-10-15 (r101-x).** Of the
  82,317 residue bytes in 502 gaps: **41,097 are switch tables** in 442 gaps / 486 regions, and
  **486 of 486 are confirmed twice** — each arm lands inside one entry AND that entry's own
  `jmp [reg*4+BASE]` names the table base. Plus 3,196 bytes of tails and 38,024 in 60 untabled
  gaps, of which **33,617 is four CRT / `/GX`-funclet spans (0x620D2B alone is 30,546)**.
  **74,602 of 82,317 bytes are not missing code.** The dashboard card's premise is wrong for this
  population and the card has not yet been corrected.
  **Why the existing route never offered them:** `confirmed-extents` begins `FROM proven p`, and
  **249 of 442 owners are unproven** — no predicate change reaches those. Worse,
  **`emitted_past_extent` misses the table in 83% of the cases where the dispatch names it**
  (0x4DB870 reads `epe=0` over a table plainly at 0x4DB954; the same shape gives 0, 1, 37, 173
  and 781). **The route needs a different oracle, not a looser clause.** Writing extents was
  deliberately NOT done: the agent-writable set is 18 of 442 owners, selected by an
  implementation accident, and writing it would contradict the tables-out convention that
  `jumpTableAt` derives from a proof while buying no provability. **Whether tables belong inside
  or outside an extent is one coordinator/owner decision; the classification itself needs no
  write.**
- **Service defect, diagnosed and not fixed:** `paddingRun` treats `0x90` as filler **wherever it
  sits**, so at 0x50EE61 it consumes the low byte of the arm `0x0050EB90`. A table is
  dword-aligned, so alignment is where filler stops. Worth 3 regions / 112 bytes.

- **The unresolved-imports blocker is ZERO real work, measured 2026-10-15 (r102-a).** Scanning
  every 4-byte occurrence of each slot address across all 7 sections (3,821,568 bytes), the image
  holds **1,374 slot references and every one carries an API name** — 653 bound per call site, 83
  at record entries, 721 on the 69 slots SafeDisc does not mediate, and **0 unbound sites whose
  slot is unnamed**. KERNEL32 285 sites / 0 unbound; USER32 368 / 0 unbound. The card's 14 are
  slots with **zero occurrences of their address anywhere in the image**: no call site, and
  `ImportDispatch.resolve` needs a call site's region-relative offset as input, so there is no
  name to compute and writing one would be fabrication. **The fix is one
  `NOT EXISTS (... unreferenced_import_slots ...)` clause in `metrics/impl.ts:540`, taking the
  card to 0/255** — the route 40 lines away already states the rule. Swapping
  `export-exact`/`not-an-export` in the rank table at `subject/impl.ts:613` takes `blocked`
  48 → 46. **No HTTP route writes `import_slots.name` or `import_bindings`, and
  `ingestStaticBindings` has zero callers**, so no agent can move this from outside the service.
  Follow-up recorded: 32 rows carry a stale label because `mapImports`' promotion is gated on the
  dump set changing (`main.ts:5868`) and has not run since the static-route bindings landed.

- **`unattributedDataPointers: 1763` overstates its own population 5.2x, measured 2026-10-15
  (r102-b).** Both coverage columns are keyed on **the dword's own location**, not its
  destination; the destination column, `resolvable`, reads **1,874 of 1,875**. Composition of the
  1,763: **708 are a `/GX` `_s_FuncInfo` pointer field** (compiler-generated), 529 have nothing at
  the destination, 286 are members of a real pointer table, 184 are text read as a dword, 55
  undecided, 1 isolated. Rolled up over all 1,875: **1,135 are pointers at all, 708 of those
  compiler-generated, leaving 342 real source-level unattributed pointers in 85 groups.**
  **176 of the 342 are mechanical** — 27 globals sized by access width rather than by their
  pointer run (`0x681dd4` has `size=4` over a 248-byte run) and 149 named only at an interior
  offset; **sizing a code-named global from its pointer run moves 176 in one rebuild**
  (`globals/inventory.ts`). The other 166 have zero `global_references` — nothing decoded touches
  those bytes. **No agent route writes a global**, so this moves only from inside the service.
  Two defects: **`GlobalsReportWire.pointers` (`api/wire.ts:842`) strips `resolvable`**, serving
  the exact figure commits `890d229`/`193a25a` corrected; and the route and the status tally
  partition differently (executable flag against `target_section != '.text'`), so SafeDisc's
  executable-but-not-`.text` `THIS_COD` puts **8 slots on both sides**.

- **VERIFIED LIVE 2026-10-15 after the migration-44 restart and rescan — every risk figure
  measured against the running service, not reported from a round:**

  | figure | was | now |
  |---|---:|---:|
  | residue `unexplained` | 7,659 B / 79 spans | **2,542 B / 26 spans (3.1%)** |
  | residue total | 82,317 B / 502 gaps | **80,883 B / 501** |
  | table regions | 464 / 40,493 B | **512 / 44,540 B** (511 dispatch-confirmed) |
  | `unansweredImportSlots` | 14 / 255 | **0 / 255** |
  | `/api/imports` `blocked` | 48 | **16** (multiple-apis 77 -> 120, no-cached 46 -> 29) |
  | `unattributedDataPointers` | 1,763 / 1,875 | **1,640 / 1,875** |

  The residue total fell because **0x6071E8 was admitted as a function at 1,341 bytes** (its base
  is named by zero absolute disp32s in `.text` — the one genuine "nothing refers to it" case) and
  two extents were corrected (0x4731E0 772->1,085, 0x5171D0 469->1,315). Tiling is exact.
  **The residue blocker was ONE ordering defect:** every rule in `scanGaps` for saying what a
  span is ran only after `measureExtent` succeeded, and a switch table is data, so the rule
  written to recognise a table could never run on one. `verdicts` had read `jump-table: 0`
  forever. Recognition is now `classifyPiece`, pure and exported, reached through
  `IDisasm.classifyPieces`.
  **The pointer lever was the SIB SCALE, not the pointer run** — an `indexed` reference states
  the element stride and `resolveSize` read widths off `absolute` references only.
  **The import block was stale, not wrong:** `mapImports` last ran 2026-10-05 while bindings
  moved twice; the binding-only conclusions are now `Subject.promoteSlotsFromBindings()`, called
  from the `import-names` job. `blocked = 46` was already wired.
  Tests after all of it: `decomp-service` **697 pass / 0 fail**, `decomp-dashboard` **16 / 0**,
  `tsc` exit 0 in both.
- **Still open, with line numbers rather than mysteries:** 2,542 unexplained residue bytes in 26
  spans; **219 real unattributed pointers, 216 of them one kind — a table no instruction names
  any byte of**; the last 2 AppCompat import rows, which need one full `mapImports` run (decided:
  **add an explicit route, do not widen the gate** — it re-reads both 512 MB captures in 5 s);
  **`ingestStaticBindings()` has zero callers, a producer with no owner**; 0x597BA0's 8-byte
  extent, which **no route can correct** (`remeasure` refuses because the address has a
  byte-exact proof, and `confirmed-extents` does not list it); and
  **`/api/discovery/callers` reports call sites that are not instruction boundaries** — a
  coincidental `e8` inside another instruction's displacement, and one phantom reference is one
  wrong "this is an entry".
- BoxedWine AoE2 desktop bring-up is complete in `packages/aoe2-in-browser/`: BoxedWine `26R1.0` interpreter + Wine `3.1` reaches controllable gameplay and verified Save/Load locally. Browser/WASM bring-up is re-verified on `http://localhost:8791/` with `1.4 RC` selected, reaching controllable gameplay after slow startup. Browser native Save/Load survives a full refresh under the data-preserving clean-restart model. Bundled scenario discovery, recording classification, boot status messaging, file-panel tabs, and pass-through resolution sizing are verified in source/build plus current browser screenshot; remaining experiment risks are Firefox/Safari verification, performance measurement, and longer-term GPU/precompile research.
- Movement quality and collision deadlock handling at scale are not yet validated in implementation.
- Replication bandwidth strategy (full-match vs AOI scoped) is still an open architectural tradeoff.
- Final rendering backend commitment (Canvas-only vs early WebGL adoption) remains open.

## Open Questions
- Public alpha target scale: start with 1v1 only or include team modes immediately?
- Default simulation tick for first playtests: 10 Hz or 20 Hz?
- Sequence for AOI/fog-scoped subscription investment: MVP or post-vertical-slice hardening?

## User Collaboration Preferences
- Autonomy-first: implement directly when decisions are bounded by repo context.
- Ask questions only when blocked by missing permissions/credentials or materially risky choices.
- Keep communication concise and explicit about tradeoffs.
- Proactively refactor incrementally toward SOLID/module boundaries as features evolve.
- Keep `CONTEXT.md` clean and project-relevant as decisions evolve.
