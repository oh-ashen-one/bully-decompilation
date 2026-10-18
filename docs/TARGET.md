# Exact target and evidence

Observed 2026-10-18 on Apple M3 Ultra, 256 GiB memory, macOS 27.0.1.
Host architecture is arm64; target architecture was read from PE headers.

| Field | Observation | Limit |
|---|---|---|
| Title/edition | Steam manifest: Bully: Scholarship Edition | User identifies owned PC installation |
| App/build | 12200 / 16483958 | Manifest only, not depot authenticity verification |
| SHA-256 | `36ff31682081a61ba564cb5e09cd6240f79791879cf1fbfb8e6252f75faddc6c` | Identifies these exact on-disk bytes |
| File size | 8,556,544 bytes | Original input read, not copied into Git |
| Format | PE32; machine 0x014c (i386) | LLVM independently reports coff-i386 |
| Endian/pointers | Little-endian / 32-bit | Per-function layouts still require evidence |
| Preferred image base | 0x00400000 | Runtime base not observed |
| Entry RVA | 0x01cf32ed, inside executable `.bind` section | Not established as original gameplay entry |
| Linker field | 8.0 | Suggests a toolchain family; not exact compiler proof |
| COFF timestamp | 1228925566 (2008-12-10 11:12:46 UTC) | A header value, not authenticated build time |
| Fixed file/product version | No version resource found by audit | Exact patch remains unknown |
| Rich metadata | No Rich marker before PE header | No tool-build IDs recovered |
| Debug directory | Size 0 | No PDB evidence from this directory |
| Region/language | Unknown | Do not infer from installation name |
| Reference environment | Owned Steam installation under CrossOver | Not launched or instrumented in this checkpoint |

Sections are `.text`, `.rdata`, `.data`, `.rsrc`, `.bind`. Executable section
virtual sizes are 5,220,754 bytes for `.text` and 352,256 bytes for `.bind`.
These are **section extents, not recovered code bytes or a function denominator**.

Imported DLL names observed: ADVAPI32, COMCTL32, d3dx9_38, DDRAW, DINPUT8,
GDI32, KERNEL32, ole32, OLEAUT32, SHELL32, USER32, vcomp, XINPUT1_3.
The linker 8.0 field and vcomp dependency are consistent with a Microsoft-era
toolchain, but do not establish exact compiler build, switches, CRT linkage,
SDK, OpenMP runtime version, exception model, LTCG, packing or object order.
Absence of a dynamic CRT import is not proof that the entire runtime is static.

The bounded entry audit first tried LLVM `-d`, which returned no instructions.
The entry section has execute permission but no code-content flag. A 256-byte
`-D` window produced 56 decoded lines; these are not verified instruction or
function boundaries. No behavior or protection-bypass claim follows. Raw output
is local-only and keyed by target hash. Both successful decode and initial
failure are retained as evidence.

The installed copy may contain updates or modifications; no clean-depot or
publisher-hash comparison has been made. Steam verification, patching, unpacking,
game launch and save access were not performed. File hashes were rechecked after
analysis. Local provenance contains the installation path and sanitized manifest
fields; account identifiers were neither needed nor copied.

Format interpretation uses [Microsoft's PE specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
