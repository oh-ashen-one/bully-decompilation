#!/usr/bin/env python3
"""Recompile reviewed REA output from our synthetic fixture; no game input."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_SHA = 'bfae632830f91dc73b91c72e7cd9cec985ba4c1ceaa807ce94eaad153b082f5a'

def main():
    p = argparse.ArgumentParser()
    p.add_argument('evidence', type=Path)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    evidence = json.loads(a.evidence.read_text())
    if (evidence['subject']['digest']['sha256'] != FIXTURE_SHA or
        evidence['operation'] != 'procedure_pseudo_code' or
        evidence['provider'] != {'id':'ghidra','name':'Ghidra','version':'12.1.4'}):
        raise ValueError('unexpected synthetic evidence identity')
    pseudocode = evidence['normalized_result']
    # Only the already reviewed synthetic expression may be compiled by this runner.
    digest = hashlib.sha256(pseudocode.encode()).hexdigest()
    expected_path = ROOT/'evidence/rea-synthetic-reviewed.json'
    if digest != json.loads(expected_path.read_text())['pseudocode_sha256']:
        raise ValueError('unreviewed pseudocode')
    out = a.output.resolve()
    if not out.is_relative_to(ROOT/'local-private'):
        raise ValueError('private output directory required')
    out.mkdir(parents=True,exist_ok=False)
    source = '#include <stdbool.h>\n#include <stdio.h>\ntypedef unsigned int uint;\ntypedef unsigned short ushort;\n'
    source += f'#include "{ROOT / "src/synthetic_handle.c"}"\n' + pseudocode
    source += r'''
int main(void) {
    const uint hs[]={0,1,2,0xfffe,0xffff,0x10000,0x10002,0x10003,0x7fff0000,0x80000000,0xffff0000,0xffffffff};
    const uint ns[]={0,1,2,3,65534,65535,65536,0xffffffff};
    const ushort gs[]={0,1,2,32767,32768,65535};
    const unsigned char ls[]={0,1,127,128,255};
    unsigned count=0;
    for(unsigned h=0;h<12;h++) for(unsigned n=0;n<8;n++)
    for(unsigned g=0;g<6;g++) for(unsigned l=0;l<5;l++) {
        int want=synthetic_handle_matches(hs[h],ns[n],gs[g],ls[l]);
        int got=entry(hs[h],ns[n],gs[g],(char)ls[l]);
        if(want!=got) return 1;
        count++;
    }
    printf("synthetic pseudocode: %u boundary combinations passed\n",count);
    return 0;
}
'''
    c = out/'comparison.c'; c.write_text(source)
    flags=['-std=c11','-O2','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
           '-fno-sanitize-recover=all']
    for name,command in [('compile',['clang',*flags,str(c),'-o',str(out/'comparison')]),
                         ('run',[str(out/'comparison')])]:
        result=subprocess.run(command,capture_output=True,text=True,timeout=60)
        (out/f'{name}.stdout.log').write_text(result.stdout)
        (out/f'{name}.stderr.log').write_text(result.stderr)
        if result.returncode or result.stderr: raise RuntimeError(f'{name} failed; inspect local logs')
    receipt={'scope':'original synthetic fixture only','boundary_combinations':2880,
             'native_arm64_comparison_passed':True,'x86_executed':False,
             'pseudocode_sha256':digest,'sanitizers':'address,undefined; recovery disabled',
             'game_oracle_tests':0,'windows_abi_qualified_by_this_test':False,
             'rea_raw_compiler_spec':evidence['analysis_profile']['parameters']['compiler_spec_id']}
    (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt))

if __name__=='__main__': main()
