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
- `docs/prd.md`

## Product Scope (Current)
- Build a browser-native, multiplayer RTS inspired by AoE2 using TypeScript.
- Primary game loop: gather resources, build, train units, fight, and resolve win/loss.
- Movement model: grid-based global pathfinding plus continuous local collision/avoidance.
- Multiplayer model: authoritative server simulation with client interpolation.

## Technical Decisions (Current)
- Backend authority model: SpacetimeDB reducers as simulation authority.
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

## Repository Snapshot
- Repository role: `open-empires` is the meta monorepo; product code currently lives under `packages/`.
- `CONTEXT.md` and `AGENTS.md` live at the repo root as the agent policy/memory entrypoint.
- `docs/prd.md` is the product source-of-truth.
- Web client code is organized under `packages/open-empires-web/src/game/` modules (`iso`, `terrain`, `units`, `camera`, `minimap`, `hud`) with `packages/open-empires-web/src/index.ts` as orchestrator.

## Known Issues / Active Risks
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
- Keep `CONTEXT.md` clean and project-relevant as decisions evolve.
