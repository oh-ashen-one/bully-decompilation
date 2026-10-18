#!/usr/bin/env python3
"""Compile original fixtures only. No game access, network or model loading."""
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run(args, *, log_name, log_dir=None, reject_stderr=False):
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True)
    logs = ROOT/'build' if log_dir is None else Path(log_dir)
    logs.mkdir(parents=True, exist_ok=True)
    (logs/f'{log_name}.stdout.txt').write_text(result.stdout)
    (logs/f'{log_name}.stderr.txt').write_text(result.stderr)
    if result.returncode:
        raise RuntimeError(f'{args[0]} failed ({result.returncode}): {result.stderr}')
    if reject_stderr and result.stderr:
        raise RuntimeError(f'{args[0]} emitted unexpected diagnostics: {result.stderr}')
    return result.stdout


def verify_symbols(output):
    symbols = {parts[2] for line in output.splitlines()
               if len(parts := line.split()) == 3 and parts[1] in {'T', 't'}}
    required = {'_synthetic_handle_matches', '_synthetic_handle_matches_stdcall@16'}
    if not required.issubset(symbols):
        raise RuntimeError('expected exact defined i386 ABI symbols absent')


def main():
    (ROOT/'build').mkdir(exist_ok=True)
    unit = subprocess.run(['python3','-B','-m','unittest','discover','-s','tests','-v'],
                          cwd=ROOT, text=True,capture_output=True)
    (ROOT/'build/fingerprint-tests.txt').write_text(unit.stdout + unit.stderr)
    if unit.returncode:
        raise RuntimeError(unit.stderr)
    native_flags = ['-std=c11','-O2','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined','-fno-sanitize-recover=all',
                    'tests/synthetic_handle_test.c',
                    '-o','build/synthetic_handle_test']
    run(['clang', *native_flags], log_name='native-compile')
    stdout = run(['./build/synthetic_handle_test'], log_name='native-run', reject_stderr=True)
    coff_flags = ['-target','i686-pc-windows-msvc','-std=c11','-O2',
                  '-ffreestanding','-fno-stack-protector','-mno-incremental-linker-compatible',
                  '-c','src/synthetic_handle.c',
                  '-o','build/synthetic_handle.obj']
    run(['clang',*coff_flags], log_name='coff-compile')
    coff = (ROOT/'build/synthetic_handle.obj').read_bytes()
    timestamp = struct.unpack_from('<I', coff, 4)[0]
    if timestamp != 0:
        raise RuntimeError('COFF timestamp is not deterministic zero')
    disassembly = run(['xcrun','llvm-objdump','-d','build/synthetic_handle.obj'], log_name='coff-disassembly')
    symbols = run(['xcrun','llvm-nm','build/synthetic_handle.obj'], log_name='coff-symbols')
    (ROOT/'build/synthetic_handle.asm').write_text(disassembly)
    verify_symbols(symbols)
    if 'retl\t$0x10' not in disassembly and 'retl\t$16' not in disassembly:
        raise RuntimeError('stdcall stack-cleanup instruction not found')
    result = dict(schema_version=2,scope='original synthetic fixtures only; no original-game parity',
                  compiler=run(['clang','--version'], log_name='compiler-version').splitlines()[0],
                  native_flags=native_flags,coff_flags=coff_flags,
                  native_result=stdout.strip(),
                  python_tests=re.sub(r'Ran (\d+) tests in [0-9.]+s', r'Ran \1 tests (timing omitted)', unit.stderr.strip()),
                  python_test_count=int(re.search(r'Ran (\d+) tests', unit.stderr).group(1)),
                  coff_sha256=hashlib.sha256(coff).hexdigest(),
                  coff_timestamp=timestamp,
                  x86_coff_compiled=True,x86_executed=False,
                  stdcall_symbol_and_stack_cleanup_verified=True,
                  exact_defined_cdecl_and_stdcall_symbols_verified=True,
                  sanitizer_recovery_disabled=True,native_stderr_empty=True,
                  original_game_oracle_tests=0,binary_matched_game_functions=0)
    (ROOT/'evidence/qualification.json').write_text(json.dumps(result,indent=2)+'\n')
    print(stdout.strip())
    print(f"{result['python_test_count']} infrastructure tests and x86 COFF ABI checks passed; no x86 runtime execution claimed.")


if __name__ == '__main__':
    main()
