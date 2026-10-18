# Bounded local import map

`tools/map_imports.py` parses the normal PE import lookup tables from the exact
hash-gated owned executable. It validates mapped file ranges, bounded table
termination, ordinal flags and unique IAT slots. It refuses a missing original
lookup table rather than guessing a bound-IAT interpretation. Delay imports are
outside this pass.

Measured: 13 DLL groups, 200 import slots, 195 named imports and 5 ordinal imports.
The raw names/addresses and mapping remain local. Public output is limited to
reviewed aggregate metadata in `evidence/import-map.json`.

As one bounded lead, the map locates a KERNEL32.GetTickCount IAT slot. Scanning
only initialized `.text` bytes for `FF 15` followed by that absolute slot address
finds **zero** patterns. This is a negative result for one direct-IAT-call encoding;
it does not prove the API is unused. Thunks, register-indirect calls and paths in
other sections require separate evidence. No offset was borrowed from upstream.

The scan is deliberately not a disassembler. Patterns can overlap data or other
instructions; even a hit would not prove a call site or function boundary. The
invented fixtures exercise that limitation, normal/ordinal entries, missing
lookup tables, invalid flags and duplicate slots.

No function enters the recovered-function ledger. This map is preparation for
local analyzer navigation, not an engine implementation or oracle comparison.
