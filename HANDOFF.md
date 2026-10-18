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

## Approved Ghidra / REA checkpoint

The user explicitly approved Ghidra and REA. Official Ghidra 12.1.4 archive
verified/extracted; ARM64 native decompiler built with existing Clang and make
in 51.82 seconds using two jobs. Existing ARM64 JDK 21.0.11+10 used. No Gradle
download, quarantine removal or shared configuration changes.

REA 6.7.0 installed task-locally with lifecycle scripts and optional dependencies
disabled. npm archive integrity verified; release source pinned to
27dc42d10249f0410904a75c0997842eb03b931c (different from reviewed main). All 26
packaged bridge files match that source. Published attestation payload was
decoded, not independently signature-chain verified. No persistent MCP profile
registration; local CLI uses an ephemeral Unix-domain Ghidra bridge.

REA/Ghidra decompiled the original synthetic x86 fixture. Reproducible runner
took 12.17 seconds, produced identical pseudocode to the initial success, and
the reviewed expression passed 2,880 native ARM64 sanitizer comparisons.
Raw-loader compiler spec was GCC: no Windows ABI or x86 execution claim.
Direct headless synthetic audit separately used Windows spec and observed a
2 GiB maximum heap / two processors. REA heap was configured 512 MiB but not
measured; REA exposes no general CPU limit and was not used for the retail pass.

Hash-locked retail audit with auto-analysis disabled completed in 5.44 seconds:
50 reachable instructions, 229 decoded bytes, one outgoing flow, no terminal
instruction or complete function boundary. Window 256 bytes; final 14 bytes
reserved from instruction starts. Original input hash unchanged. No game run.
Raw listing private; public minimized receipt evidence/ghidra-entry.json.

Failed npm config, Swift cache and sandbox Java spawn attempts retained. First
retail pass caught an instruction crossing the window despite Ghidra exit zero;
the corrected script was requalified before retry. Runner requires summary
creation and unchanged input as well as exit success. All-local-private storage
was 1,927,303,168 bytes, below the approved 5 GiB. Process-family RSS unmeasured.
See docs/ANALYZER_QUALIFICATION.md and evidence/analyzer-*.json.

## Blockers and next milestone

- Retail patch, region and modification status not authenticated. Hash is exact.
- Linker 8.0 is evidence, not exact compiler/SDK/CRT/ABI/options recovery.
- Ghidra/REA now installed and synthetically qualified as recorded above.
  Complete real function boundary and local semantic contract are still absent.
- No qualified local weights in documented locations. Modelfiles point to a
  former nonexistent home; Ollama launcher dangles; LM Studio home missing.
  llama.cpp 0.4.0 build10809 is usable as a runtime prerequisite, not qualified
  inference. No repair, model load or download occurred.
- No real handle function address/layout or original execution oracle yet.

Next: use a qualified local analyst/model to inspect one real handle-validation
candidate and its callers, with a measured window and independently written
contract. Do not expand an incomplete entry trace into a recovery claim. Review
instrumentation separately before controlled original-oracle tests. The current
cloud workflow may continue public compiler/reference research and original tests.

Option A in docs/SETUP_PROPOSAL was approved/completed. Option B, the optional
4,683,073,536-byte official Qwen 7B GGUF and bounded CPU-only qualification,
remains unapproved/unexecuted. No new model decision is inferred from REA/Ghidra
approval. Exact model URLs/hashes remain in evidence/setup-options.json.
Task-local runtime paths are listed in local-private/analyzer-paths.json.

## Verification commands

`python3 tools/qualify.py` runs all current public tests without the game.
`python3 tools/fingerprint.py "$BULLY_EXE" --output local-private/new-audit.json`
does a read-only metadata pass. `tools/audit_entry.py` is exact-hash gated and
refuses to overwrite an existing private audit directory.

Before further publication, inspect every staged file and history; retain the
target and coverage distinctions. No changes to bully-remake or unrelated work.
