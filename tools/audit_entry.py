#!/usr/bin/env python3
"""Exact-build-gated, local-only 256-byte entry inspection. Never executes game."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from fingerprint import PE

TARGET = '36ff31682081a61ba564cb5e09cd6240f79791879cf1fbfb8e6252f75faddc6c'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('executable', type=Path)
    args = parser.parse_args()
    data = args.executable.read_bytes()
    if hashlib.sha256(data).hexdigest() != TARGET:
        parser.error('unexpected executable hash; no analysis performed')
    pe = PE(data)
    entry = pe.u32(pe.opt + 16)
    pe.offset(entry, 256)
    sections = [s for s in pe.sections if s['rva'] <= entry < s['rva']+s['virtual_size']]
    if len(sections) != 1 or not sections[0]['flags'] & 0x20000000:
        parser.error('entry not in one executable section')
    out = Path(__file__).resolve().parent.parent/'local-private'/TARGET/'entry-audit'
    out.mkdir(parents=True, exist_ok=False)
    start = pe.u32(pe.opt + 28) + entry
    common = [f'--start-address={start}',f'--stop-address={start+256}',str(args.executable)]
    results = []
    for mode in ['-d','-D']:
        result = subprocess.run(['xcrun','llvm-objdump',mode,*common],capture_output=True,text=True)
        (out/f'{mode[1:]}.asm').write_text(result.stdout)
        (out/f'{mode[1:]}.stderr.txt').write_text(result.stderr)
        results.append(dict(mode=mode,exit_code=result.returncode,
                            decoded_lines=len(re.findall(r'^\s*[0-9a-f]+:',result.stdout,re.M)),
                            raw_output_sha256=hashlib.sha256(result.stdout.encode()).hexdigest()))
        if result.returncode:
            parser.exit(1,'local disassembler failed; inspect private stderr\n')
    if hashlib.sha256(args.executable.read_bytes()).hexdigest() != TARGET:
        parser.exit(1,'target changed during analysis; discard inference\n')
    receipt = dict(target_sha256=TARGET,window_bytes=256,entry_rva=hex(entry),
                   section=sections[0]['name'],results=results,
                   input_unchanged=True,executed=False,game_functions_recovered=0,
                   limitation='linear decode only; function boundary and executed path unverified')
    (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print('Private bounded entry audit saved; target unchanged; no game execution.')


if __name__ == '__main__':
    main()
