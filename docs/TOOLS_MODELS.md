# Tool and model checkpoint — 2026-10-18

This records the initial limited inventory. The deeper follow-up in
[SETUP_PROPOSAL.md](SETUP_PROPOSAL.md) confirms installed JDKs/Gradle, runtime
versions, broken historical model paths, resource pressure, and exact proposals.
Ghidra and REA were subsequently approved, installed and qualified; see
[ANALYZER_QUALIFICATION.md](ANALYZER_QUALIFICATION.md) for the current results.
The local-model discovery limitations below remain unresolved.

Read-only inventory was scoped to conventional installation locations, the
configured LM Studio home pointer, the external model directory and the named
LM Studio download backup. This was not a whole-disk search.

| Capability | Verified state | Next decision |
|---|---|---|
| Host | Apple M3 Ultra, 256 GiB, macOS 27.0.1 | CPU-only qualification used |
| Python | Python 3 available; standard library audit runs | No package installation needed |
| Compiler/disassembler | Apple Clang/LLVM 21.0.0 | Qualified native fixture and i386 COFF inspection |
| Historical compiler | Exact original compiler/SDK/CRT not identified or qualified | Research evidence first; do not download proprietary toolchains indiscriminately |
| Ghidra / REA | Task-local Ghidra 12.1.4 with built ARM64 decompiler; REA 6.7.0 pinned release CLI | Synthetic decompilation qualified; bounded retail entry audited; no persistent MCP registration |
| Python PE/emulation packages | pefile, capstone, unicorn absent from inspected Python | Standard-library audit and LLVM used instead |
| llama.cpp | Homebrew installation 0.4.0 and CLI present | No weights loaded, inference or server started |
| LM Studio | Application and CLI present; configured home missing | `lms ls --json` failed; `lms ps` did not run after that failure |
| Model weights | Default LM Studio/Ollama locations absent; inspected external `models` directory empty; named backup contains download metadata only | No verified usable model found in these locations |
| Cloud model | Current Codex session authored original code, tests and reviewed metadata | No separate paid API or subscription started |

The LM Studio listing command itself reported an attempt to connect/start its
daemon and then failed with no valid installation. Treat it as a failed discovery
probe, not evidence of a running server. No model load/unload, configuration edit,
repair or further daemon command followed. Future discovery should inspect files
or use a documented no-start status API first.

Historical shared wiki notes described Qwen 122B and MiMo on an earlier setup.
Those notes do not establish today's installed weights or ownership. No unrelated
process, listener, terminal, engine or workload was managed by this task.

## Bounded choices before local-model work

1. **Reuse already approved weights:** identify their current local path and owner,
   verify model/revision and runnable format read-only, then propose a task-owned
   CLI qualification run. Budget: one synthetic function, at most 2,048 output
   tokens and 120 seconds, no listener, no retail context, no shared-server
   changes. Resource mode and concurrency must be checked before starting.
2. **Continue without model setup:** use LLVM and original synthetic fixtures on
   CPU; keep private semantic reconstruction pending a qualified local analyst.
   This is the route used for this checkpoint and incurs no new API spend.

If the only option is new weights, a model installation, or paid inference,
present the exact model, download size, runtime/resource budget and cost using
current provider evidence before seeking that decision. None is authorized or
scheduled here. Do not delete another model to make room.

## Information boundary

Retail executable/assets, raw disassembly/pseudocode, databases, private model
prompts and responses stay local. A cloud-controlled tool's returned output is
also an upload boundary. Public references, independently authored contracts,
synthetic fixtures, original source and reviewed minimized metadata may enter
the cloud workflow. Never forward the whole analysis directory.

Local inference quality gates: correct widths/signedness, calling convention,
side-effect description, boundary cases, uncertainty, and a discriminating test.
Record actual model/weights, settings, time, prompt hash, tool version, failures
and qualified context classes. Model confidence is not evidence. Do not claim a
clean-room process merely because two models are involved.
