# First bounded slice: qualify handle-validation analysis

Goal: recover one deterministic PC object/handle validation operation, with its
actual target function boundary, contract and test oracle. No candidate address
or Bully handle layout has yet been established for the fingerprinted build.
Public bully-re pool notes are research leads only; offsets are not portable.

Preparation completed: exact target/ABI baseline, local entry inspection,
original PE audit with malformed fixtures, and an invented scalar handle fixture
that checks toolchain handling of widths, unsigned comparisons and stack cleanup.

## Invented qualification contract (not a Bully hypothesis)

`synthetic_handle_matches(handle:u32, capacity:u32, generation:u16, live:u8)`
returns integer 0 or 1 with no side effects. For this fixture only, the low 16 bits
are an index and the high 16 bits a generation. Reject sentinel 0xffffffff,
capacity 0 or >65535, index >= capacity, unequal generation, or live == 0.
No pointers, allocation, object mutation, concurrency or lifetime are modeled.
Fourteen explicit cases cover high bits, wrap boundaries, sentinel, dead entries,
non-boolean live values and invalid capacities.

Native arm64 execution with ASan/UBSan passes. A freestanding Windows i386 COFF
object compiles at -O2; cdecl/stdcall decorations and 16-byte callee stack cleanup
are observed. The i386 object has **not** executed. Clang 21 is a development
tool, not the original compiler, and the fixture cannot establish Bully parity.

Reproducibility failure retained: default COFF compilation embedded wall-clock
timestamps, so an immediate same-second repeat was insufficient. The qualified
flags now include `-mno-incremental-linker-compatible`; the harness asserts a
zero COFF timestamp and repeated complete objects are compared byte-for-byte.
No post-build instruction or header normalization is used. This fixture-specific
build option is not a hypothesis about the retail compiler flags.

## Next target milestone

1. Qualify an existing approved local model/analyzer using the synthetic fixture.
   Keep its task to one function, two hypotheses, edge-case checklist and no tools
   that mutate files or start listeners. No private game context until qualified.
2. Locally locate one real handle-validation routine and relevant callers/types;
   establish call convention, arguments, object layout, sentinel and side effects.
   Disprove the invented fixture's assumptions rather than transplanting them.
3. Publish only a reviewed independently written contract and uncertainty summary.
4. Implement an original candidate and align bounded original-oracle cases using
   a separately reviewed, reversible exact-build harness. Do not patch or launch
   the installed game as an incidental tool-qualification step.
5. Record every mismatch. Only then expand to pool allocation/free and generations.

Stop conditions: target hash changes; ambiguous boundary; unavailable local-only
evidence processing; unavailable original oracle; two failed attempts at the
same uncertainty; need for downloads, paid APIs, shared model changes, or runtime
instrumentation outside current preparation scope. These stop the dependent
step, not unrelated safe documentation or synthetic verification.
