# Bully PC recovery handoff — 2026-10-18

Owner: the sole authorized Bully decompilation task. No secondary driver, model
server or background loop was started. Branch: `research/pc-baseline`.
Remote: https://github.com/oh-ashen-one/bully-decompilation

## Edge-verifier review correction

The reviewer reproduced false RET fallthrough/JMP-as-CALL acceptance in 6962b77.
The original false-positive receipt is retained; eight new regressions exercise
the corrected typed-edge checker and main entrypoint. Revalidation confirms all
five real paths / 1,933 entry edges and 186 callee edges. See
evidence/edge-verifier-v2.json; historical static-call-paths.json is superseded
for edge-validation confidence. No game execution or coverage promotion.

## Latest saved milestone: static call paths and value boundary

All current artifacts are saved. Entry graph: 1,782 instruction starts / 7,921
bytes, independently checked with LLVM plus 1,933 edges. Five static call paths
reach three `.bind` candidates. Candidate 2 adds a closed 167-instruction /
503-byte boundary across two ranges; its 186 edges are independently checked.
The original hash is unchanged. No game launch or runtime instrumentation occurred.

The computed transfer was followed beyond the first unknown call to candidate 2.
Its return depends on six dynamic memory reads and an incoming stack value;
both callers' inferred arguments also retain unknown input/memory/call-return
boundaries. The bounded structural/value model now needs a reviewed private
semantic/state contract or an explicitly approved isolated runtime observation.
This is a precise method limit, not a claim that all static research is exhausted.
Missing local model weights alone did not stop the structural work.

See docs/STATIC_CALL_PATHS.md and evidence/static-call-paths.json for the method,
limits, retained failures and deterministic edge checks. Current tests: 46 Python,
14 native sanitizer C cases, deterministic i386 COFF; prior synthetic expression
comparison remains 2,880. Game functions recovered/oracle-tested/matched: **0**.

Private continuation points (all ignored):
- local-private/reference-value-index-retail: complete entry graph and cached SSA.
- local-private/reference-five-paths-llvm: independently checked five paths.
- local-private/callee-two-graph-v2: isolated callee graph and cached SSA.
- local-private/callee-two-return-query and callee-two-caller-query: bounded slices.
- local-private/callee-two-graph: retained rejected empty graph / loader conflict.

The cache queries avoid repeated PE imports. Final synthetic callee qualification
passed in 4.18 seconds. Latest all-private file bytes: 1,896,618,043, below 5 GiB.
No weights, paid API, persistent bridge or unattended loop was started. Original
files/saves and every unrelated workload remain untouched.

Next decision: obtain a reviewed local semantic contract/state model, or approve
and define the isolated runtime/observation environment in ORIGINAL_ORACLE_PLAN.
The exact optional model proposal remains unapproved in NEXT_LOCAL_MODEL. No
runtime approval is inferred from installing Ghidra/REA. Compiler/patch/ABI
uncertainties still prevent matching claims. Continue public/reference or bounded
static research when it supplies new evidence; do not repeat the same query as
if it could manufacture unknown process state.

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

Latest independent preparation: tools/select_candidate_seeds.py identifies six
bounded `.bind` prologue-pattern leads. BoundedCandidateScan.java accepted two
closed leaf hypotheses and rejected four, retaining all detailed output under
local-private/ghidra-candidates-retail-v1. Candidate IDs 3/4 are 101/117 bytes,
37/42 instructions, one return each with 8/12-byte cleanup. LLVM independently
agreed with every instruction start and raw file byte. No semantic contract,
caller proof, gameplay role or original execution follows. Pseudocode stays local.
Runtime: 5.53 seconds, 2 GiB heap, two JVM processors, unchanged original hash.
These hypotheses are outside the game-function counts, which remain zero.

Review fixes now require Darwin ARM64 for the synthetic comparison and validate
summary target/scope/completion/counts instead of mere existence. Five new
negative regressions pass; total Python tests 27, C cases 14, architecture-gated
synthetic expression comparison 2,880. Prior receipts retained, including
qualification-before-analyzer-gates.json and rea-synthetic-comparison.json.

docs/ORIGINAL_ORACLE_PLAN.md gives a proposed isolated baseline/function-oracle
sequence, without executing it. Actual current CrossOver runtime/version remains
unverified. docs/NEXT_LOCAL_MODEL.md refreshes the exact 7B Q4_K_M proposal:
4,683,073,536 bytes, Apache-2.0, installed llama.cpp runtime, additional 6 GiB disk
approval, 8 GiB process-family RSS stop, four threads and 120-second synthetic run.
No weights downloaded or inference started. At 23:11 UTC free pages were
121.05 GiB, inactive pages 56.27 GiB, disk available 349.6 GiB, zero swap/compression.

- Retail patch, region and modification status not authenticated. Hash is exact.
- Linker 8.0 is evidence, not exact compiler/SDK/CRT/ABI/options recovery.
- Ghidra/REA now installed and synthetically qualified as recorded above.
  Gameplay-function boundaries and local semantic contracts are still absent.
- No qualified local weights in documented locations. Modelfiles point to a
  former nonexistent home; Ollama launcher dangles; LM Studio home missing.
  llama.cpp 0.4.0 build10809 is usable as a runtime prerequisite, not qualified
  inference. No repair, model load or download occurred.
- No real handle function address/layout or original execution oracle yet.

That earlier caller-path milestone is now complete as recorded above. Next,
resolve the documented input/state boundary and continue locating a gameplay target.
Qualified local semantic analysis is needed for a private contract, but is not
a blanket blocker for analyzer-only structural work or public compiler/reference
research. Review the concrete isolated environment and instrumentation before
controlled original-oracle tests. Never widen an incomplete trace silently.

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
