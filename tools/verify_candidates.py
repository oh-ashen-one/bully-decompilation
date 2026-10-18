#!/usr/bin/env python3
"""Cross-check private contiguous candidate boundaries using LLVM and PE mapping."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
try:
    from .fingerprint import PE
    from .run_ghidra_entry import TARGET, validate_summary
except ImportError:
    from fingerprint import PE
    from run_ghidra_entry import TARGET, validate_summary

ROOT=Path(__file__).resolve().parent.parent

def main():
    p=argparse.ArgumentParser();p.add_argument('input',type=Path)
    p.add_argument('--scan',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();data=a.input.read_bytes()
    if hashlib.sha256(data).hexdigest()!=TARGET:raise ValueError('target hash mismatch')
    validate_summary(json.loads((a.scan/'summary.json').read_text()),TARGET,candidate=True)
    out=a.output.resolve()
    if not out.is_relative_to(ROOT/'local-private'):raise ValueError('private output required')
    out.mkdir(parents=True,exist_ok=False);pe=PE(data);base=pe.u32(pe.opt+28)
    rows=json.loads((a.scan/'private-candidates.json').read_text());receipts=[]
    for row in rows:
        if not row.get('closed_leaf_candidate'):continue
        if row['body_range_count']!=1:raise ValueError('noncontiguous body unsupported by this cross-check')
        start,end=int(row['body_min'],16),int(row['body_max'],16)
        size=end-start+1
        if not 1<=size<=256 or start!=int(row['entry_va'],16):raise ValueError('invalid candidate extent')
        offset=pe.offset(start-base,size);raw=data[offset:offset+size]
        name=f"candidate-{row['id']}"
        (out/(name+'.bin')).write_bytes(raw)
        result=subprocess.run(['xcrun','llvm-objdump','-D',f'--start-address={start}',
                               f'--stop-address={end+1}',str(a.input)],capture_output=True,text=True,timeout=30)
        (out/(name+'.asm')).write_text(result.stdout);(out/(name+'.stderr.log')).write_text(result.stderr)
        if result.returncode or result.stderr:raise RuntimeError('LLVM failed; inspect private logs')
        decoded=[]
        for line in result.stdout.splitlines():
            match=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*([^\n]*)$',line)
            if match:decoded.append((int(match[1],16),bytes.fromhex(match[2]),match[3]))
        ghidra_addresses=sorted(int(line.split()[0],16) for line in (a.scan/(name+'.asm')).read_text().splitlines())
        llvm_addresses=[x[0] for x in decoded]
        if llvm_addresses!=ghidra_addresses or b''.join(x[1] for x in decoded)!=raw:
            raise ValueError('independent decoder boundary or byte disagreement')
        ret_pops=[]
        for _,code,_ in decoded:
            if code==b'\xc3':ret_pops.append(0)
            elif len(code)==3 and code[0]==0xc2:ret_pops.append(int.from_bytes(code[1:],'little'))
        if sorted(set(ret_pops))!=row['return_pop_bytes'] or len(ret_pops)!=row['returns']:
            raise ValueError('return encoding disagreement')
        receipts.append({'candidate_id':row['id'],'section':row['section'],'body_bytes':size,
                         'instruction_count':len(decoded),'decoder_addresses_agree':True,
                         'llvm_bytes_equal_original_file':True,'return_pop_bytes':ret_pops,
                         'standard_frame_prologue':raw.startswith(bytes.fromhex('558bec')),
                         'body_sha256':hashlib.sha256(raw).hexdigest(),
                         'semantic_contract_established':False,'original_execution_observed':False})
    if hashlib.sha256(a.input.read_bytes()).hexdigest()!=TARGET:raise ValueError('input changed')
    receipt={'target_sha256':TARGET,'cross_checked_candidates':len(receipts),'candidates':receipts,
             'input_unchanged':True,'game_functions_recovered':0,'original_oracle_tests':0,
             'limitation':'Static closed-leaf hypotheses in startup wrapper; no gameplay or reachability claim.'}
    (out/'summary.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))

if __name__=='__main__':main()
