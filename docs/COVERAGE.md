# Full-game scope and measurement

The end goal includes the original PC engine, integration and all playable
content, not a visual remake or a single playable yard. The owned data remains
an external input. Middleware integration must be original or lawfully reusable;
its exact version, APIs and licensing cannot be assumed.

| Workstream | Full-game acceptance scope | Current original-target evidence |
|---|---|---|
| Startup/runtime | Boot, shutdown, memory, threading, exceptions, platform services | Header/import audit; entry graph and five static call paths |
| Resource system | Archives, paths, streaming, formats, ownership and error behavior | None |
| World/rendering | Scene graph, interiors/exteriors, cameras, animation, materials, visibility | None |
| Simulation | Collision, physics, entities, pools, movement, AI, combat, vehicles | None; invented handle fixture only |
| Scripting/game flow | Lua ABI, mission state, all chapters, activities/classes, cutscenes, checkpoints | None |
| Presentation/input | UI, menus, controls, audio, music, localization, settings | None |
| Persistence | Saves/loads, restart, progression, compatibility, failure handling | None; original saves untouched |
| Integration | Entire game from new game to ending, side content, regression/performance matrix | None |

Each function gets an exact-target RVA, independently justified boundary/size,
subsystem, evidence references, uncertainty and separate stage fields:

1. **Inventoried:** boundary hypothesis recorded; confidence explicit.
2. **Analyzed:** contract and side effects supported by reviewed evidence.
3. **Candidate implemented:** original or licensed source exists.
4. **Compiled:** pinned toolchain accepts that candidate.
5. **Original-oracle tested:** aligned inputs/state compared against owned original;
   list cases, environment, tolerances and failures.
6. **Binary matched:** exact compiler/build inputs and comparison procedure pinned;
   define reference extraction and relocation treatment without masking operands.

These are independent facts, not automatic promotions. Synthetic tests are a
separate infrastructure counter. A named call or address reference counts in
none of the implementation stages. Generated stubs do not count.

At this checkpoint: all six game-function counts are **0**; total game function
count is **unknown**. There is one binary header/import audit and one bounded
entry window, neither a recovered function. No whole-game percentage is reported.
`evidence/coverage.json` is the machine-readable ledger.

Later bounded discovery found three `.bind` leaf hypotheses with independent
decoder agreement. They are recorded as **artifact function candidates**, outside
the game-function counts: five static caller paths are checked, while gameplay role, semantic contracts
and runtime execution remain unverified. See [STATIC_CALL_PATHS.md](STATIC_CALL_PATHS.md).

Follow-up infrastructure evidence: 38 Python tests, including negative analyzer,
architecture, sanitizer
and symbol/output-preservation regressions; 200 import slots mapped locally;
zero direct-IAT-call patterns for one clock anchor in initialized `.text`.
Import slots and byte patterns never enter the game-function denominator.

Matching is the strongest code-recovery criterion but currently blocked by exact
compiler/linker/runtime/SDK/options and suitable reference mapping. Behavioral
agreement may be recorded separately while these are researched. It never gets
renamed a binary match or proof of original source recovery. Full-game behavior
requires scenario coverage across every workstream above, not a function ratio.

Upstream bully-re reports 345/20,819 address-referenced functions and 2.5% code-byte
coverage at the cited revision. Its counter includes addresses mentioned by
calls; those are not independently verified implementations and are not this
project's denominator or progress. Xbox 360 BullyRecomp is a different target.
