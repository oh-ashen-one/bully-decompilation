# Bounded entry-section candidate discovery

Target remains the exact owned PC SHA-256 in [TARGET.md](TARGET.md). No game
launch, patch, memory dump, unwrapping or other platform was involved.

The original section-statistics tool measured `.text` at 7.99997 bits/byte
entropy, with zero standard frame-prologue pattern hits. `.bind` had six hits.
This is a lead-selection observation, not proof of encryption, compression or a
particular protection scheme. Pattern hits are not automatically functions.

Each of the six `.bind` seeds received a 256-byte window, with the final 14
bytes excluded from instruction starts, a 128-instruction traversal cap and a
10-second per-candidate decompilation limit. Whole-program auto-analysis stayed
disabled. The headless run used a 2 GiB heap and two reported processors and
completed in **5.53 seconds**. The executable hash remained unchanged.

The filter required resolved, in-window control flow, at least one return and
no calls. Four seeds failed (undecoded destinations or no bounded return); their
private diagnostics were retained. Two passed:

| Private candidate ID | Contiguous body | Instructions | Returns | Return stack cleanup |
|---|---:|---:|---:|---:|
| 3 | 101 bytes | 37 | 1 | 8 bytes |
| 4 | 117 bytes | 42 | 1 | 12 bytes |

Both have a standard frame prologue. An independent LLVM pass agreed with every
Ghidra instruction start and reproduced the exact original-file bytes across
each body. The return encodings independently agreed. Detailed addresses, raw
bytes, listings and Ghidra pseudocode remain local; public receipts contain
aggregate metadata and hashes only.

These are **static leaf-function hypotheses in the entry section**, likely
wrapper-related but of unverified purpose. No observed caller or runtime path
establishes their actual use. Callee cleanup alone cannot distinguish a complete
calling convention or parameter types/counts. A decompiler-created function
record and pseudocode do not establish an independently reviewed contract.

Game-function recovery, implementation, original-oracle and match counts remain
zero. The coverage ledger tracks these two hypotheses separately, outside the
game-function denominator. The first gameplay handle-validation target remains
unlocated; do not rename these candidates to make them fit that goal.

## Qualification and review repairs

The same filter first accepted our two original synthetic wrappers, correctly
observing return cleanup of 0 and 16 bytes. Neither synthetic execution nor
static decoding is counted as a retail oracle.

Five new regression tests reject a wrong host architecture, absent/malformed
summaries, failed disassembly and inconsistent counts. The synthetic comparison
now requires native ARM64 macOS and records its observed platform. The Ghidra
runner validates target/scope/completion and bounded count relationships before
success. Existing valid receipts were preserved; the revised native comparison
again passed 2,880 combinations. The complete infrastructure suite now has
**27 passing tests**, plus 14 explicit C fixture cases.

## Reproduce locally

```sh
python3 tools/select_candidate_seeds.py "$BULLY_EXE" --output local-private/new-seeds
python3 tools/run_ghidra_entry.py "$BULLY_EXE" --ghidra "$GHIDRA_DIR" \
  --java-home "$JDK_HOME" --candidate-seeds local-private/new-seeds/seeds.txt \
  --output local-private/new-candidates
python3 tools/verify_candidates.py "$BULLY_EXE" --scan local-private/new-candidates \
  --output local-private/new-crosscheck
```

Next static question: establish a caller/reference path to a candidate and review
its side effects locally. Separately, [the oracle plan](ORIGINAL_ORACLE_PLAN.md)
defines the conditions before any original execution, and
[the model proposal](NEXT_LOCAL_MODEL.md) identifies the exact optional decision.
No model approval is needed to continue public-reference research or bounded
analyzer-only structural checks.
