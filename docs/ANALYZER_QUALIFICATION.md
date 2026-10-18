# Ghidra and REA qualification — 2026-10-18

Follow-up: [STATIC_CANDIDATES.md](STATIC_CANDIDATES.md) records two bounded
entry-section hypotheses and independent decoder checks. Later review added
explicit ARM64 and structural-summary gates with five regressions. Original
successful receipts remain preserved; v2 synthetic comparison passed and the
current infrastructure count is 27.

The user approved Ghidra and REA installation. Both are now task-local under
ignored `local-private/tools`. No model weights, paid inference, agent-profile
registration, system service, quarantine removal or security-setting change was
part of this work. No retail executable was run or modified.

## Installed identity

- Official Ghidra **12.1.4**, release commit
  `8b6bbb857accdfa20dc5b2f5dea471178c2e9fbc`. The 569,649,598-byte archive matched
  the release SHA-256. ZIP member paths were checked before extraction.
- The distribution's C++ decompiler was built using existing Apple Clang,
  `make -j2 ghidra_opt ARCH_TYPE="-arch arm64" OSDIR=mac_arm_64 ADDITIONAL_FLAGS=-w`.
  Build time: 51.82 seconds, within a 600-second limit. The installed executable
  is Mach-O ARM64, 3,262,120 bytes. No Gradle wrapper or new JDK was needed.
- REA **6.7.0**, official npm tarball, SHA-512 matched registry integrity.
  Its published provenance payload names release commit
  `27dc42d10249f0410904a75c0997842eb03b931c`; that commit was fetched and reviewed.
  All 26 packaged bridge files and the dispatcher matched the release source.
  Today's main commit differed, so main was not used as proof of release contents.
  The attestation payload was decoded and compared; its signature chain was not
  independently verified. The compiled package was not reproducibly rebuilt here.
- Task-local npm install: 147 installed packages including REA, lifecycle scripts
  disabled, optional dependencies omitted. Frida and browser binaries were not
  installed. Existing Node 26.8.2, npm 11.19.1 and ARM64 Temurin 21.0.11+10 were used.

Complete hashes and provenance are in [analyzer-setup.json](../evidence/analyzer-setup.json).
Ghidra/REA and their dependency notices remain local; none is vendored publicly.
The combined installation, source review copies, archives, caches and initial
analysis remained below the approved 5 GiB ceiling; measured totals are in the
resource receipt. Java heap settings are not total process-family RSS limits.

## What passed

REA's local CLI successfully decompiled the 122-byte `.text` section of our
original, relocation-free synthetic i386 fixture through Ghidra. Its raw loader
selected `x86:LE:32:default:gcc`. This verifies a useful pipeline but does not
qualify retail Windows ABI recovery. The output inferred a boolean result where
the source declares integer 0/1; no original type-recovery claim is made.

The reviewed synthetic expression was recompiled for native ARM64 with ASan and
UBSan, recovery disabled, and compared against the original synthetic source on
**2,880 boundary combinations**. All passed with empty stderr. This is neither
x86 execution nor a Bully oracle. The prior 22 infrastructure tests and 14
original fixture cases also passed.

An independent original Ghidra script was then qualified on a padded synthetic
window using the Windows compiler specification: 21 reachable instructions,
56 decoded bytes, one terminal instruction, no flow leaving the window. It
observed a 2 GiB maximum heap and two JVM processors. REA's small synthetic run
used a configured 512 MiB heap; effective REA heap/RSS were not measured. REA
does not expose a general analysis CPU limit; it is not used for the retail pass.

## Bounded retail result

Exact target SHA-256 remained
`36ff31682081a61ba564cb5e09cd6240f79791879cf1fbfb8e6252f75faddc6c`.
The qualified script imported that PE read-only, disabled auto-analysis and
followed reachable decoding from entry VA `0x020f32ed` inside a 256-byte window.
The final 14 bytes were reserved from instruction starts to accommodate x86's
maximum 15-byte instruction. This deliberately leaves tail coverage incomplete.

Result: **50 instructions / 229 decoded bytes**, **one flow edge outside the
window**, zero terminal instructions and zero analysis function records. The
window does **not** establish a complete function boundary. No retail pseudocode
was exported to the cloud. The raw local listing is separate from the public
[minimized receipt](../evidence/ghidra-entry.json).

The first attempt caught a crossing instruction and correctly withheld its
summary, although Ghidra exited zero. The runner therefore requires an emitted
summary, unchanged source hash and successful exit. The corrected script was
requalified before the second retail attempt. Failed logs remain local and
[failure history](../evidence/failures.json) records the problem.

**Recovered/matched/original-oracle-tested game functions remain 0.** An
instruction count, imported function record or synthetic comparison is not a
completed decompilation. Exact retail patch, compiler/SDK/CRT/options and handle
layout remain unknown. Further semantic reconstruction needs qualified local
analysis of a real candidate and a separately reviewed original oracle.

## Reproduction

Use fresh private output directories; tools refuse overwrite. Provide actual
task-local installation paths through these variables; the commands do not
install tools, download packages or register an MCP server.

```sh
python3 tools/qualify.py
python3 tools/run_rea_synthetic.py --rea "$REA_SCRIPT" --ghidra "$GHIDRA_DIR" \
  --java-home "$JDK_HOME" --output local-private/new-rea-test
python3 tools/check_rea_synthetic.py local-private/new-rea-test/result.json \
  --output local-private/new-rea-comparison
python3 tools/run_ghidra_entry.py "$BULLY_EXE" --ghidra "$GHIDRA_DIR" \
  --java-home "$JDK_HOME" --output local-private/new-retail-entry
```

REA uses its private Unix-domain bridge for the synthetic CLI session and closes
the ephemeral project on exit. No TCP bridge or persistent agent integration was
configured. A sandbox may require action-time approval to launch the owned Java
process; no security setting should be weakened to avoid that boundary.
