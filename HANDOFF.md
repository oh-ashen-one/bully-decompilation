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

Game functions recovered/matched/original-oracle-tested: **0**. Denominator
unknown. No runtime/gameplay/rendered validation or full-game completion claim.

## Blockers and next milestone

- Retail patch, region and modification status not authenticated. Hash is exact.
- Linker 8.0 is evidence, not exact compiler/SDK/CRT/ABI/options recovery.
- No qualified local model/weights or semantic analyzer in inspected locations.
  LM Studio discovery failed; do not repair or start it without a setup decision.
- No real handle function address/layout or original execution oracle yet.

Next: resolve an existing approved local tool/model path, qualify it with the
invented fixture within the bounded budget in docs/TOOLS_MODELS, then establish
one real handle-validation contract locally. Review instrumentation separately
before controlled original-oracle tests. Expand only after evidence supports it.

## Verification commands

`python3 tools/qualify.py` runs all current public tests without the game.
`python3 tools/fingerprint.py "$BULLY_EXE" --output local-private/new-audit.json`
does a read-only metadata pass. `tools/audit_entry.py` is exact-hash gated and
refuses to overwrite an existing private audit directory.

Before further publication, inspect every staged file and history; retain the
target and coverage distinctions. No changes to bully-remake or unrelated work.
