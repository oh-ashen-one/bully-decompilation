#!/usr/bin/env python3
"""Compile original fixtures only. No game access, network or model loading."""
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run(args):
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f'{args[0]} failed ({result.returncode}): {result.stderr}')
    return result.stdout


def main():
    (ROOT/'build').mkdir(exist_ok=True)
    unit = subprocess.run(['python3','-B','-m','unittest','discover','-s','tests','-v'],
                          cwd=ROOT, text=True,capture_output=True)
    if unit.returncode:
        raise RuntimeError(unit.stderr)
    (ROOT/'build/fingerprint-tests.txt').write_text(unit.stderr)
    native_flags = ['-std=c11','-O2','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined','tests/synthetic_handle_test.c',
                    '-o','build/synthetic_handle_test']
    run(['clang', *native_flags])
    stdout = run(['./build/synthetic_handle_test'])
    coff_flags = ['-target','i686-pc-windows-msvc','-std=c11','-O2',
                  '-ffreestanding','-fno-stack-protector','-mno-incremental-linker-compatible',
                  '-c','src/synthetic_handle.c',
                  '-o','build/synthetic_handle.obj']
    run(['clang',*coff_flags])
    coff = (ROOT/'build/synthetic_handle.obj').read_bytes()
    timestamp = struct.unpack_from('<I', coff, 4)[0]
    if timestamp != 0:
        raise RuntimeError('COFF timestamp is not deterministic zero')
    disassembly = run(['xcrun','llvm-objdump','-d','build/synthetic_handle.obj'])
    symbols = run(['xcrun','llvm-nm','build/synthetic_handle.obj'])
    (ROOT/'build/synthetic_handle.asm').write_text(disassembly)
    if '_synthetic_handle_matches_stdcall@16' not in symbols or '_synthetic_handle_matches' not in symbols:
        raise RuntimeError('expected i386 ABI symbol decorations absent')
    if 'retl\t$0x10' not in disassembly and 'retl\t$16' not in disassembly:
        raise RuntimeError('stdcall stack-cleanup instruction not found')
    result = dict(schema_version=1,scope='original synthetic fixtures only; no original-game parity',
                  compiler=run(['clang','--version']).splitlines()[0],
                  native_flags=native_flags,coff_flags=coff_flags,
                  native_result=stdout.strip(),
                  fingerprint_tests=re.sub(r'Ran (\d+) tests in [0-9.]+s', r'Ran \1 tests (timing omitted)', unit.stderr.strip()),
                  coff_sha256=hashlib.sha256(coff).hexdigest(),
                  coff_timestamp=timestamp,
                  x86_coff_compiled=True,x86_executed=False,
                  stdcall_symbol_and_stack_cleanup_verified=True,
                  original_game_oracle_tests=0,binary_matched_game_functions=0)
    (ROOT/'evidence/qualification.json').write_text(json.dumps(result,indent=2)+'\n')
    print(stdout.strip())
    print('PE audit tests and x86 COFF ABI checks passed; no x86 runtime execution claimed.')


if __name__ == '__main__':
    main()
