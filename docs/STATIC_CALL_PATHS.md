# Entry graph, direct callees and the unresolved transfer

This checkpoint is static evidence for the exact owned PC executable in
[TARGET.md](TARGET.md). It does not execute the game, establish gameplay semantics
or advance recovered/matched/original-oracle game-function counts above zero.

## Independent-review correction

Commit 6962b77's edge checker was too permissive: adjacency admitted a fallthrough
from RET, and destination-only checking admitted JMP as CALL. Its untyped edge
relation could also admit a call as an intra-function path step. The reviewer's
invented PE reproducer was reproduced and its false-positive receipt retained.
Those earlier receipts alone do not justify opcode-level path confidence.

The corrected checker validates each edge kind against its control-transfer
opcode, forbids fallthrough after unconditional transfers/returns, rejects
malformed edges and its explicitly enumerated disallowed transfer encodings,
retains edge kinds, and requires a real direct CALL
at each endpoint. Eight new regressions include the actual main-entry reproducer.
The saved real entry graph revalidates all 1,933 edges and five paths; candidate 2
revalidates 186 edges. Current receipt:
[edge-verifier-v2.json](../evidence/edge-verifier-v2.json). That checkpoint had 46
Python tests; runtime/semantic coverage remains unchanged.

## Follow-up: UD0, UD1 and RSM

A narrower review found UD0, UD1 and RSM were falling through the classifier's
ordinary default. Synthetic false acceptances are retained. The three encodings
are now explicitly rejected, with three new test methods covering nine base and
prefixed cases. They do not occur in the inspected saved entry/callee graphs or
the two earlier leaf linear decodes. All five paths / 1,933 entry edges and 186
callee edges revalidate; the full native-host suite passes 49 Python tests.
See [edge-verifier-v3.json](../evidence/edge-verifier-v3.json).

The classifier is an enumerated control-transfer check, not a complete supported
instruction allowlist. Other LLVM-decoded instructions fall back to ordinary.
Accordingly, the earlier universal unsupported-transfer fail-closed wording is
withdrawn; only the documented/tested rejection cases are claimed. Old receipts
are preserved, with this qualification superseding their broader wording.

## Independently checked structure

The entry-rooted traversal decoded 1,782 instructions / 7,921 bytes in `.bind`.
It found 91 calls (86 computed), one computed jump and one return. No queued,
undecoded or out-of-section destinations remained. This means the bounded
structural traversal completed; conditional feasibility was not evaluated and
calls were assumed to return. Callees were not silently traversed.

LLVM agreed with all 1,782 instruction starts and original bytes. Separate
encoding checks validated all 1,933 recorded edges. Five entry-to-call-site paths
were checked: two to candidate 4, one to candidate 3, and two to candidate 2.
The paths contain 49, 54, 281, 80 and 419 instructions respectively. None proves
that the path executes in an actual process. All addresses and listings stay local.

Candidate 2 was then analyzed separately from a validated direct call. The first
attempt decoded nothing and failed function creation; the runner rejected its
missing summary even though Ghidra exited zero. Imported analysis had a data unit
covering the requested entry. Clearing analysis units in the disposable `.bind`
database fixed that conflict without changing any executable bytes. This is not
evidence that a previous overlapping instruction hypothesis was correct.

The corrected candidate has 167 instructions / 503 decoded bytes across two body
ranges, zero calls, zero computed jumps and one return. LLVM independently agrees
with every start and 186 edges. The return boundary is closed under this static
model. Its purpose and calling contract remain unreviewed. This raises the
separate artifact-candidate count to three; it does not identify a gameplay function.

## What blocks the next transfer

The entry's computed transfer target is not a constant in the cached high-level
dataflow. Following value and callee-identity dependencies reaches a computed-call
return and a known direct callee: candidate 2. That discovery justified the
additional callee analysis rather than stopping at the first indirect branch.

Candidate 2's returned value depends on six dynamic-address memory reads and one
incoming stack value. Its backward slice contains 61 values, no call-return
boundary, and does not hit its traversal budget. Both callers were then inspected:
their four decompiler-inferred argument values remain nonconstant, involving
indirect-call results, dynamic memory and input leaves. Argument counts/types and
SSA values remain analyzer hypotheses, not a recovered Windows ABI specification.

The next missing evidence is the contract and concrete state behind those input,
memory and indirect-call boundaries. This bounded structural/value-slice method
cannot produce the next executable target from the evidence currently modeled.
The slice follows data dependencies, not control predicates or a reconstructed
memory/alias model. This does not prove that every static-analysis method is exhausted.

Two concrete ways forward require different additional inputs:

- Private semantic review can supply a reviewed contract/state model. No qualified
  local model weights are installed. [NEXT_LOCAL_MODEL.md](NEXT_LOCAL_MODEL.md)
  gives the exact optional 4,683,073,536-byte download and resource proposal; it
  remains unapproved. A model's output would still need independent validation.
- A controlled original-process observation could provide concrete runtime state.
  It requires explicit runtime/instrumentation authorization, a verified compatible
  runtime, and the isolation/resource decisions in
  [ORIGINAL_ORACLE_PLAN.md](ORIGINAL_ORACLE_PLAN.md). The existing bottle alone does
  not establish the current runtime/version. No launch or instrumentation occurred.

## Bounds, checks and retained failures

Each headless invocation has a 180-second deadline, a 2 GiB Java heap and two
processors. Each decompilation is limited to 10 seconds. Traversal stops at 65,536
decoded bytes or 16,384 instruction addresses; cached dependency queries stop at
4,096 values. The entry value-index export took 6.44 seconds; the corrected callee
pass took 5.65 seconds. Heap settings are verified; process-family RSS is not.

Original synthetic graphs qualify reachable versus unreachable call patterns,
indirect memory/call-return dependencies and callee roots. Six new value-query
regressions and five graph regressions bring the infrastructure suite to 38
Python tests; all pass alongside 14 native sanitizer C cases and deterministic
i386 COFF checks. The earlier 2,880 synthetic expression comparisons remain a
separate prior result, not a new game oracle.

Retained failures include one automatic-approval timeout before launch (the
permitted identical retry succeeded), the rejected empty callee graph, an initial
byte-equality comparison of JSON objects whose key ordering differed, and the
initial query's mistaken treatment of a direct-callee address as an unbound value.
Structural JSON equality and byte-identical instruction listings confirmed the
repeated entry graph; no byte-identical JSON claim is made. A one-off local
metadata script also mistook a list for an object; its corrected query succeeded.

The minimized receipt is [static-call-paths.json](../evidence/static-call-paths.json).
Raw graphs, SSA indexes, pseudocode, diagnostics and failed runs stay ignored.
No model, game process, paid API or persistent bridge was started.

## Local reproduction

Use the public `scan_candidate_references.py` to produce a private request from
the existing candidate record, then `run_ghidra_entry.py --reference-graph` to
produce the bounded graph. `verify_reference_graph.py` checks original bytes and
edges independently with LLVM. A callee request must include its private parent
graph and direct-call site; the runner checks the parent edge and original E8
relative-call bytes before accepting it. Private requests are deliberately absent
from this repository.

`inspect_transfer_dependencies.py --graph ... --output ...` queries a saved index
without reimporting the executable. Its `--mode returns` and `--mode call-arguments
--callee-graph ...` modes expose unresolved value boundaries. These queries do not
emulate code, infer memory values or turn analyzer observations into contracts.
