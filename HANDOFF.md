# Bully PC recovery handoff — 2026-10-18

Owner: the sole authorized Bully decompilation task. No secondary driver, model
server or background loop was started. Branch: `research/pc-baseline`.
Remote: https://github.com/oh-ashen-one/bully-decompilation

## Verified work

Exact owned target located and fingerprinted; headers cross-checked with LLVM.
See docs/TARGET. Original files and saves remain untouched. Private installation
path and metadata are in the local ignored provenance record.

Runnable original PE reader, synthetic malformed-PE tests, scalar handle/ABI
fixture and deterministic qualification receipt are complete. Native sanitizer
execution and x86 COFF compile/inspection pass; x86 execution is not claimed.
One 256-byte entry window was decoded locally; raw data stays ignored. `-d`
skipping `.bind` is retained as a failed attempt, with `-D` as the bounded correction.
Default COFF timestamps also broke spaced reproducibility; the fixture compiler
flags now disable incremental-linker compatibility and assert timestamp zero.

Follow-up review fixes are in the current checkpoint: distinct `code-only` and
`all-sections` output names (verified as distinct files), corrected UTC timestamp,
nonrecovering sanitizers with stderr retention/rejection, and exact defined ABI
symbol checks. The initial receipts and collided legacy local directory remain
preserved; `entry-audit-v2.json` and the current qualification receipt supersede
their affected claims. 22 Python infrastructure tests and 14 C cases pass.

Original bounded import mapping found 200 slots across 13 DLLs (195 named, 5
ordinal). One GetTickCount IAT slot exists; the narrow FF15 scan in initialized
`.text` found zero patterns. Raw mapping stays local; no no-use/function inference.

Game functions recovered/matched/original-oracle-tested: **0**. Denominator
unknown. No runtime/gameplay/rendered validation or full-game completion claim.

## Blockers and next milestone

- Retail patch, region and modification status not authenticated. Hash is exact.
- Linker 8.0 is evidence, not exact compiler/SDK/CRT/ABI/options recovery.
- Ghidra not located after catalog, package, Spotlight and bounded filesystem
  discovery. Temurin JDK 21.0.11/25.0.3 and Gradle 9.5.0 are installed. The
  exact Ghidra 12.1.4 download/native-build proposal is now concrete.
- No qualified local weights in documented locations. Modelfiles point to a
  former nonexistent home; Ollama launcher dangles; LM Studio home missing.
  llama.cpp 0.4.0 build10809 is usable as a runtime prerequisite, not qualified
  inference. No repair, model load or download occurred.
- No real handle function address/layout or original execution oracle yet.

Next: resolve an existing approved local tool/model path, qualify it with the
invented fixture within the bounded budget in docs/TOOLS_MODELS, then establish
one real handle-validation contract locally. Review instrumentation separately
before controlled original-oracle tests. Expand only after evidence supports it.

Specific pending decisions are in docs/SETUP_PROPOSAL: A, the 569,649,598-byte
official Ghidra ZIP, task-local native build with existing tools and bounded
synthetic analysis; B, optionally the 4,683,073,536-byte official Qwen 7B GGUF and
one CPU-only synthetic qualification. Do not infer download/start permission
from this proposal. Exact URLs/hashes are in evidence/setup-options.json; actual
local executable paths are in ignored local-private/setup-paths.json.

## Verification commands

`python3 tools/qualify.py` runs all current public tests without the game.
`python3 tools/fingerprint.py "$BULLY_EXE" --output local-private/new-audit.json`
does a read-only metadata pass. `tools/audit_entry.py` is exact-hash gated and
refuses to overwrite an existing private audit directory.

Before further publication, inspect every staged file and history; retain the
target and coverage distinctions. No changes to bully-remake or unrelated work.
