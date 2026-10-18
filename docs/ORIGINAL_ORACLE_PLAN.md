# Original-execution oracle plan — proposed, not run

Current evidence is static. None of the three candidates has an independently written
semantic contract or observed original execution. The three `.bind` leaf hypotheses
are entry-section leads, with their gameplay relevance unknown. They must not be
called handle validators or used as justification for injecting an engine hook.

## First resolve the static uncertainty

Keep the exact on-disk hash as the baseline. Establish whether each candidate is
actually called, which registers/stack locations supply its inputs, what memory
it reads/writes and whether any system state or CPU flags matter. The observed
return cleanup of 8/12 bytes alone does not prove stdcall, parameter counts or
types; thiscall/fastcall or custom conventions remain possibilities.
For example, Microsoft's documented [stdcall](https://learn.microsoft.com/en-us/cpp/cpp/stdcall)
and [thiscall](https://learn.microsoft.com/en-us/cpp/cpp/thiscall) conventions both
assign stack cleanup to the callee on x86; thiscall also supplies `this` in ECX.

The `.text` byte distribution is almost uniform. This suggests an encoding or
transformation may need to be understood before treating it as ordinary code,
but entropy alone proves neither encryption nor a specific protection scheme.
Do not invent a gameplay address, apply external-build offsets or patch the file.
Public references and further bounded local caller/metadata analysis can proceed
without a local model. Semantic review of private pseudocode needs a qualified
local analyst/model or explicit permission for a particular different destination.

## Establish an isolated reference environment before any launch

Read-only inspection now locates CrossOver 26.3 (build 26.3.0.39832) in the
user Applications folder and the matching win10_64 Steam bottle. Unrestricted
code-signature verification passed. This is runtime metadata, not a successful
game launch. [ISOLATED_RUNTIME_PROPOSAL.md](ISOLATED_RUNTIME_PROPOSAL.md) supplies
the concrete owner prerequisites, fresh-bottle/save isolation, measured storage,
bounded observation and cleanup choice. That proposal remains unapproved.

Use a separate, user-approved test environment with the owned game, fresh test
saves/configuration and a known writable directory. Do not reuse production
saves or blindly clone a Steam bottle containing credentials and unrelated
applications. The user should establish required account authorization through
the normal UI. Do not copy authentication stores, change account settings or
disable cloud synchronization globally as an incidental preparation step.

Record exact executable/dependency hashes, runtime/OS, graphics mode, resolution,
input mapping and process ownership. Size the isolated game data separately:
copying a full installation is not covered by the existing 5 GiB analyzer budget.
If CrossOver cannot provide an isolated, reproducible reference, propose a
separate owned Windows test environment; do not switch the game edition/platform.

## Two distinct oracle levels

1. **Unmodified baseline observation:** after explicit execution approval, run
   only the owned game in the isolated environment. First limit one startup/menu
   scenario to 120 seconds, at most two attempts, with a normal exit. Record
   whether it launches, input sequence, state, timestamps and environment. This
   is an integration observation, not a function differential test. Do not touch
   other engines; renderer slot and OS-dialog rules still apply.
2. **Function differential oracle:** only after a supported ABI/state contract
   exists, propose a small original harness and an exact-build address check.
   Qualify its capture/replay and cleanup on our synthetic cdecl/stdcall wrappers
   first. Define valid argument ranges, accessible memory, initialization order,
   outputs, allowed side effects and log cap before executing it against retail.
   No random pointers, arbitrary calls into an uninitialized image or downloaded
   hook/mod binaries. Instrumentation requires a separate concrete review.

For deterministic integer routines, compare every output bit and explicitly
specified memory change. For floating point, choose tolerances before viewing
results and record exceptional values. Align initial state and random seeds
where controllable. A lifted/emulated function can help test a hypothesis, but
does not establish that the original process invokes it with those inputs.

Use hash-gated, task-owned logs with a 10 MiB initial cap, no public raw dumps,
and no persistent listener. Compare an uninstrumented baseline with an
instrumented run to detect perturbation. Any wrong hash, unexpected save write,
unowned process, unresolved ABI, crash or unverifiable cleanup stops that run.
Terminate only the task-owned process when normal exit fails; never use a global
Wine/Steam kill command.

## Required next decisions

No execution or instrumentation is authorized by this document. Before launch,
resolve the actual runtime and approve a concrete isolated environment, storage
budget and scenario. Before a function oracle, review the original harness and
candidate ABI/state contract. Static discovery and original synthetic work remain
available independently of those decisions.
