#!/usr/bin/env python3
"""Exact-build section statistics and bounded prologue leads; no semantic claims."""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
try:
    from .fingerprint import PE
    from .run_ghidra_entry import TARGET
except ImportError:
    from fingerprint import PE
    from run_ghidra_entry import TARGET

ROOT=Path(__file__).resolve().parent.parent

def main():
    p=argparse.ArgumentParser();p.add_argument('input',type=Path)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    data=a.input.read_bytes()
    if hashlib.sha256(data).hexdigest()!=TARGET:raise ValueError('target mismatch')
    pe=PE(data);base=pe.u32(pe.opt+28);stats=[];seeds=[]
    for section in pe.sections:
        raw=pe.take(section['raw_offset'],section['raw_size'])
        counts=Counter(raw)
        entropy=-sum((n/len(raw))*math.log2(n/len(raw)) for n in counts.values()) if raw else 0
        stats.append({'section':section['name'],'raw_bytes':len(raw),
                      'entropy_bits_per_byte':round(entropy,5),
                      'frame_prologue_pattern_count':raw.count(bytes.fromhex('558bec')),
                      'zero_fraction':round(raw.count(0)/len(raw),5) if raw else None})
        if section['name']=='.bind':
            position=-1
            while True:
                position=raw.find(bytes.fromhex('558bec'),position+1)
                if position<0:break
                if position+256<=len(raw):seeds.append(base+section['rva']+position)
    if not 1<=len(seeds)<=6:raise ValueError('seed budget changed; review before analysis')
    out=a.output.resolve()
    if not out.is_relative_to(ROOT/'local-private'):raise ValueError('private output required')
    out.mkdir(parents=True,exist_ok=False)
    (out/'seeds.txt').write_text(''.join(f'{x:x}\n' for x in seeds))
    (out/'section-statistics.json').write_text(json.dumps(stats,indent=2)+'\n')
    receipt={'target_sha256':TARGET,'seed_count':len(seeds),'section':'.bind',
             'maximum_window_bytes_per_seed':256,'selection':'standard frame-prologue byte pattern',
             'function_boundaries_established':False,'target_executed':False}
    (out/'summary.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt))

if __name__=='__main__':main()
