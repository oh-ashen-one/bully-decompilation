# Bounded analyzer/model setup proposal — not yet executed

Checked 2026-10-18. The full original PC game remains the recovery goal. This
proposal only enables the next verifiable analysis step. No installation, model
download, local inference, paid API, security change or shared-server mutation
was performed while preparing it.

## Verified host and existing tools

M3 Ultra, 256 GiB unified memory, 32 physical/logical CPUs. At 21:17 UTC the
snapshot showed 123.0 GiB free pages, zero compressed pages, no swap, and 91.42%
CPU idle. Available storage was 377.3 GiB on the system volume and 461.7 GiB on
the external volume. The separate macOS memory-pressure query reported 96%
free; this includes reclaimable memory and is not the same measure as free pages.
These are snapshots, not reserved capacity or permission to consume it.

- Temurin **21.0.11+10** and **25.0.3+9**, arm64 JDKs: verified using the macOS
  Java registry, actual bundle paths and `java -version`. JDK 21 is usable;
  no JDK installation is needed. Homebrew also records OpenJDK 25.0.2 and 17.0.19.
- Gradle **9.5.0**, CMake **4.3.1**, Xcode Clang/LLVM **21.0.0** installed.
- llama.cpp **0.4.0**, build **10809**, commit **5266f24da**, Darwin arm64:
  executable version/help verified without loading weights.
- LM Studio **0.4.21+2** application exists, but its configured home is missing.
  Ollama's launcher is a dangling link to a missing application.
- MLX **0.32.0** is in the inspected Python environment; `mlx-lm` is absent.
  Presence of the array library does not provide a language-model runner.
- No relevant Ghidra/Java/llama/Ollama/LM Studio/MLX process names were observed
  in the filtered process snapshot. No unrelated arguments or processes were controlled.

## Scope and limits of discovery

The shared catalog search found the pinned decompilation workflow, but no Ghidra
installation entry. The current systems index and the wiki's model inventories
were consulted as historical leads, not treated as live machine proof.

Ghidra was not found through PATH, Homebrew receipts, Spotlight filename results,
or a depth-three name-only scan of standard application/tool/home roots (4,382
directories). Hidden configuration, Trash, archives, credentials, unrelated
project contents and application internals were excluded from that scan. Thus
**no accessible installation was located**, not proof that none exists anywhere.

The documented model locations were checked directly: default LM Studio/Ollama
homes, current Hugging Face cache, external model folder, and exact `FROM` paths
in existing Modelfiles. The latter point to a former home that does not exist.
The external model folder is empty; the named download backup holds metadata,
not weights. No Trash was inspected. No usable LLM weights were located in these
documented places. Audio model cache entries are not substitutes for a code model.

## Smallest analyzer installation proposal

Use the official [Ghidra 12.1.4 release](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build),
tag commit `8b6bbb857accdfa20dc5b2f5dea471178c2e9fbc`:

- File: `ghidra_12.1.4_PUBLIC_20260921.zip`
- Exact archive download: **569,649,598 bytes** (543.26 MiB).
- SHA-256: `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`.
- Official installed-binary minimum: 1 GB. Reserve a **4 GiB installation/build
  budget**, including archive/native build/cache, plus **1 GiB** for the initial
  analysis project. These are proposed ceilings, not measured extraction sizes.

The pinned [official guide](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/GhidraDocs/GettingStarted.md)
requires 64-bit JDK 21 and supports macOS ARM64 through user-built native
components. Its native build path uses `support/gradle` and `buildNatives` with
Gradle 8.5+ and C/C++ build tools. Existing tools satisfy those documented minimums;
the exact combination remains unqualified until a build succeeds.

Proposed actions, after approval:

1. Download only the pinned official ZIP into a task-owned ignored tools folder;
   verify SHA-256, inspect its file inventory, then extract to a new directory.
2. Use the installed JDK 21 in the child process only. Put Gradle/cache/config/tmp
   outputs under this task; leave shell profiles and shared Java defaults alone.
3. First try installed Gradle 9.5.0 with `--offline --no-daemon --max-workers=2`
   for `buildNatives`. Allow at most 10 minutes, 4 GiB build storage and a 2 GiB
   Gradle JVM heap. Stop on missing dependencies or incompatibility. Do not
   automatically use the supplied wrapper: it names Gradle 9.7.1 and could download
   more files. Any extra dependency download needs a separately sized proposal.
4. Qualify headless analysis/decompilation on the original synthetic i386 COFF
   fixture first: at most 2 CPUs, 2 GiB heap, 180 seconds. Verify native component
   architecture, calling conventions and known contract. Only after this passes,
   propose a bounded hash-gated retail import/analysis pass with local outputs.

Use locally built native components; do not remove quarantine attributes or
change Gatekeeper/firewall settings. Stop if an OS approval prompt appears. No
GUI, debugger, bridge, network listener, Ghidra server or PyGhidra dependency is
needed for the first batch qualification. No original game execution is proposed.

## Local-model shortlist, separate optional approval

Choose an official GGUF that the existing llama.cpp can attempt to load, avoiding
LM Studio repair and new Python stacks. These are conservative qualification
candidates, not claims of state-of-the-art decompilation performance. Both cards
describe code-oriented instruction models and Apache-2.0 licensing; neither
establishes binary-analysis reliability on this project.

| Candidate | Exact single-file Q4_K_M download | Proposed disk / runtime envelope | Role |
|---|---:|---|---|
| [Qwen2.5-Coder-7B-Instruct-GGUF](https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct-GGUF) | 4,683,073,536 bytes (4.36 GiB) | 6 GiB disk / 8 GiB RSS target | Recommended first low-cost qualification candidate |
| [Qwen2.5-Coder-14B-Instruct-GGUF](https://huggingface.co/Qwen/Qwen2.5-Coder-14B-Instruct-GGUF) | 8,988,110,272 bytes (8.37 GiB) | 10 GiB disk / 14 GiB RSS target | Optional second candidate only if 7B fails semantic checks |

Immutable revisions, exact filenames and SHA-256s are in
`evidence/setup-options.json`. Download only the single file, not both the
single-file and split-file variants or an entire model repository. Capacity
allows either proposed envelope in the measured snapshot; actual load/latency
and RSS have not been measured. Disk envelopes assume streaming into one partial
file followed by rename, without a duplicate cache copy.

Proposed first inference: existing `llama-cli`, local file only, `--offline`,
`--device none`, `--n-gpu-layers 0`, 4 CPU threads, 4,096-token context,
2,048-token maximum output, seed 1, temperature 0, one turn and a 120-second
supervised timeout. Monitor task-owned RSS and stop at the selected budget.
Recheck pressure first. No server, auto-download flag or GPU use. Allow one
synthetic fixture response with no tool execution, then score widths, unsigned
comparisons, stack convention, invalid cases and explicit uncertainty. A timeout
is failure evidence; do not silently increase resources or switch models.

## Decisions needed

**A:** approve the pinned 569,649,598-byte Ghidra archive, task-local native build
and bounded synthetic headless qualification using existing tools, with the
ceilings above. This is sufficient to move beyond metadata without a local LLM.

**B (optional, separately):** approve exactly one model file (recommended 7B,
4,683,073,536 bytes) and the bounded CPU-only synthetic qualification. No payment
or subscription is involved. Downloads and starts were explicitly held pending
the user's setup decision; the skill itself does not impose this extra approval.

If an existing approved installation/weights path is supplied instead, inspect
that path first and revise the proposal. No actions A/B have occurred.
