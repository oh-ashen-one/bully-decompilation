#!/usr/bin/env python3
"""Bounded encoding-pattern leads, not decoded references or execution proof."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
try:
    from .fingerprint import PE
    from .run_ghidra_entry import TARGET
except ImportError:
    from fingerprint import PE
    from run_ghidra_entry import TARGET

ROOT=Path(__file__).resolve().parent.parent

def relative_target(base,offset,displacement):
    return (base+offset+5+displacement)&0xffffffff

def direct_patterns(data,base,target):
    hits=[]
    for offset in range(max(0,len(data)-4)):
        if data[offset] in (0xe8,0xe9) and relative_target(base,offset,struct.unpack_from('<i',data,offset+1)[0])==target:
            hits.append((offset,'rel32_call' if data[offset]==0xe8 else 'rel32_jump'))
    return hits

def main():
    p=argparse.ArgumentParser();p.add_argument('input',type=Path)
    p.add_argument('--candidates',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();data=a.input.read_bytes()
    if hashlib.sha256(data).hexdigest()!=TARGET:raise ValueError('target mismatch')
    pe=PE(data);base=pe.u32(pe.opt+28)
    candidates=[x for x in json.loads(a.candidates.read_text()) if x.get('closed_leaf_candidate')]
    if len(candidates)!=2:raise ValueError('candidate scope changed')
    hits=[];counts=[]
    for candidate in candidates:
        target=int(candidate['entry_va'],16)
        for section in pe.sections:
            raw=pe.take(section['raw_offset'],section['raw_size']);section_base=base+section['rva']
            patterns=[]
            for kind,pattern in [('absolute_va',struct.pack('<I',target)),('rva',struct.pack('<I',target-base))]:
                offset=-1
                while True:
                    offset=raw.find(pattern,offset+1)
                    if offset<0:break
                    patterns.append((offset,kind))
            if section['flags']&0x20000000:patterns+=direct_patterns(raw,section_base,target)
            kinds={}
            for offset,kind in patterns:
                hits.append({'candidate_id':candidate['id'],'kind':kind,'source_va':section_base+offset,
                             'target_va':target,'section':section['name']})
                kinds[kind]=kinds.get(kind,0)+1
            counts.append({'candidate_id':candidate['id'],'section':section['name'],'pattern_counts':kinds})
    direct=[x for x in hits if x['kind']=='rel32_call']
    if len(direct)>16:raise ValueError('reference budget exceeded')
    out=a.output.resolve()
    if not out.is_relative_to(ROOT/'local-private'):raise ValueError('private output required')
    out.mkdir(parents=True,exist_ok=False)
    (out/'private-patterns.json').write_text(json.dumps(hits,indent=2)+'\n')
    (out/'private-request.json').write_text(json.dumps({'entry_va':base+pe.u32(pe.opt+16),'section':'.bind',
        'references':direct,'inspect_indirect_dataflow':True},indent=2)+'\n')
    summary={'target_sha256':TARGET,'section_pattern_counts':counts,'direct_call_pattern_leads':len(direct),
             'instruction_boundaries_established':False,'execution_proven':False}
    (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary))

if __name__=='__main__':main()
