# Bully decompilation

This project aims to recover the **entire original engine and game behavior of
Bully: Scholarship Edition for PC**, incrementally from an authorized owned copy.
It is early research, not a playable reconstruction or a completed decompilation.
The separate [bully-remake](https://github.com/oh-ashen-one/bully-remake) project is
outside this repository's scope.

## Verified checkpoint — 2026-10-18

- Located the owned Steam PC installation under CrossOver; inspected read-only.
- Fingerprinted `Bully.exe`: SHA-256
  `36ff31682081a61ba564cb5e09cd6240f79791879cf1fbfb8e6252f75faddc6c`.
- Confirmed i386 PE32, 32-bit little-endian pointers, image base `0x400000`.
  Steam app 12200, installed manifest build 16483958. Exact retail patch remains
  unverified; Steam build IDs do not prove a patch number or unmodified files.
- Built an original read-only PE audit; cross-checked headers using LLVM.
- Inspected a bounded entry-point window locally. Entry is in `.bind`, not
  `.text`; no gameplay function or compiler identity inferred from that alone.
- Passed 22 infrastructure tests (9 PE, 5 import-map, 2 output-preservation,
  6 qualification regressions) and 14 invented handle-contract cases with native
  AddressSanitizer/UndefinedBehaviorSanitizer. Compiled a freestanding i386 COFF
  ABI fixture and checked cdecl/stdcall symbol/stack conventions.
- Mapped 200 import slots locally. A bounded direct-call encoding scan for one
  clock API found no candidates; this negative result is not a no-use proof.
- Checked actual analyzer/model paths and resources; existing JDK 21, Gradle and
  llama.cpp are usable prerequisites. Exact installation/download options are
  proposed in [setup decisions](docs/SETUP_PROPOSAL.md), not executed.

**Recovered game functions: 0. Original-game differential tests: 0. Binary
matches: 0.** The function denominator is not established for this executable.
The fixture is original test infrastructure, not a recovered Bully implementation.

See [target evidence](docs/TARGET.md), [full-game scope and coverage](docs/COVERAGE.md),
[first slice](docs/FIRST_SLICE.md), [tool/model status](docs/TOOLS_MODELS.md),
[receipts](evidence/qualification.json), and [handoff](HANDOFF.md).

Independent review corrections: fixed case-insensitive audit filename collisions,
UTC timestamp rendering, sanitizer failure handling and exact symbol checks.
Earlier receipts remain available; current evidence supersedes the affected claims.

## Reproduce safe qualification

On the verified development host with Python 3, Xcode command-line tools and Clang:

```sh
python3 tools/qualify.py
```

This runs only original synthetic code. It does not load a model, use the network,
read a game installation, or execute the game. Build products are ignored.

For authorized local analysis of the exact owned executable:

```sh
python3 tools/fingerprint.py "$BULLY_EXE" --output local-private/fingerprint.json
python3 tools/audit_entry.py "$BULLY_EXE"
python3 tools/map_imports.py "$BULLY_EXE"
```

The fingerprint tool refuses overwrite; the entry audit refuses a different hash
or existing output directory. Both only read the input. Keep all generated
analysis local. Review a separate minimized summary before publication.

## Contribution boundary

Public files contain original implementation, synthetic fixtures, reviewed
metadata and attributed references. No game binaries/assets, extracted scripts,
raw decompilation, analysis databases, memory dumps or proprietary SDKs belong in
this repository or its history. `.gitignore` is only a first line of defense.
Review every staged file. See [provenance](docs/PROVENANCE.md) and
[third-party notices](THIRD_PARTY_NOTICES.md).

No deadline or guarantee of complete recovery is implied. Full-game recovery
remains the goal; narrow validated slices are milestones toward it.
