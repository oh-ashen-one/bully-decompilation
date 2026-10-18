#!/usr/bin/env python3
"""Independent static graph checks. Keeps all instruction text/addresses private."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
from collections import deque
try:
    from .fingerprint import PE
    from .run_ghidra_entry import TARGET, validate_summary
except ImportError:
    from fingerprint import PE
    from run_ghidra_entry import TARGET, validate_summary

ROOT=Path(__file__).resolve().parent.parent

def relative_destination(address,code):
    if len(code)==5 and code[0] in (0xe8,0xe9):
        return (address+5+struct.unpack_from('<i',code,1)[0])&0xffffffff
    if len(code)==2 and (code[0]==0xeb or 0x70<=code[0]<=0x7f or 0xe0<=code[0]<=0xe3):
        return (address+2+struct.unpack_from('<b',code,1)[0])&0xffffffff
    if len(code)==6 and code[0]==0x0f and 0x80<=code[1]<=0x8f:
        return (address+6+struct.unpack_from('<i',code,2)[0])&0xffffffff
    return None

def main():
    p=argparse.ArgumentParser();p.add_argument('input',type=Path)
    p.add_argument('--graph',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--additional-callee-graph',type=Path)
    a=p.parse_args();data=a.input.read_bytes()
    if hashlib.sha256(data).hexdigest()!=TARGET:raise ValueError('target mismatch')
    summary=json.loads((a.graph/'summary.json').read_text());validate_summary(summary,TARGET,graph=True)
    addresses={int(x.split()[0],16) for x in (a.graph/'reachable.asm').read_text().splitlines()}
    if not addresses:raise ValueError('empty graph')
    start,end=min(addresses),max(addresses)+15
    if end-start>65536:raise ValueError('linear cross-check span limit')
    out=a.output.resolve()
    if not out.is_relative_to(ROOT/'local-private'):raise ValueError('private output required')
    out.mkdir(parents=True,exist_ok=False)
    result=subprocess.run(['xcrun','llvm-objdump','-D',f'--start-address={start}',
                           f'--stop-address={end}',str(a.input)],capture_output=True,text=True,timeout=30)
    (out/'linear.asm').write_text(result.stdout);(out/'stderr.log').write_text(result.stderr)
    if result.returncode or result.stderr:raise RuntimeError('LLVM failed; inspect private logs')
    decoded={}
    for line in result.stdout.splitlines():
        match=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*([^\n]*)$',line)
        if match:decoded[int(match[1],16)]=bytes.fromhex(match[2])
    missing=addresses-decoded.keys()
    if missing:raise ValueError(f'linear decode disagrees at {len(missing)} graph starts; do not accept paths')
    pe=PE(data);base=pe.u32(pe.opt+28)
    for address in addresses:
        raw=decoded[address];off=pe.offset(address-base,len(raw))
        if raw!=data[off:off+len(raw)]:raise ValueError('decoded bytes disagree with original file')
    edges=json.loads((a.graph/'private-edges.json').read_text());supported=set();unsupported=0
    for edge in edges:
        source,dest=int(edge['from'],16),int(edge['to'],16);code=decoded.get(source)
        if code is None:raise ValueError('edge source absent from independent decode')
        if edge['kind']=='fallthrough':valid=source+len(code)==dest
        else:
            actual=relative_destination(source,code)
            if actual is None:unsupported+=1;continue
            valid=actual==dest
        if not valid:raise ValueError('independent edge disagreement')
        supported.add((source,dest))
    paths=json.loads((a.graph/'private-matched-paths.json').read_text());checked=[]
    if a.additional_callee_graph:
        callee=json.loads((a.additional_callee_graph/'reference-request.json').read_text())
        root=base+pe.u32(pe.opt+16);parents={root:None};queue=deque([root]);adj={}
        for edge in edges:
            if edge['kind']!='call':adj.setdefault(int(edge['from'],16),[]).append(int(edge['to'],16))
        # Deterministic parent assignment, independent of raw JSON key order.
        while queue:
            source=queue.popleft()
            for dest in sorted(adj.get(source,[])):
                if dest not in parents:parents[dest]=source;queue.append(dest)
        for edge in edges:
            source=int(edge['from'],16)
            if edge['kind']=='call' and int(edge['to'],16)==callee['entry_va'] and source in parents:
                path=[];cursor=source
                while cursor is not None:path.append(format(cursor,'x'));cursor=parents[cursor]
                paths.append(dict(candidate_id='additional-validated-callee',source_va=edge['from'],
                                  target_va=edge['to'],path=list(reversed(path))))
        (out/'private-checked-paths.json').write_text(json.dumps(paths,indent=2)+'\n')
    for item in paths:
        path=[int(x,16) for x in item['path']]
        if path[0]!=base+pe.u32(pe.opt+16) or path[-1]!=int(item['source_va'],16):
            raise ValueError('path root or endpoint mismatch')
        if any((x,y) not in supported for x,y in zip(path,path[1:])):
            raise ValueError('path edge lacks independent support')
        if relative_destination(path[-1],decoded[path[-1]])!=int(item['target_va'],16):
            raise ValueError('call target mismatch')
        checked.append({'candidate_id':item['candidate_id'],'path_instruction_count':len(path),
                        'all_path_edges_independently_checked':True,'actual_execution_proven':False})
    if hashlib.sha256(a.input.read_bytes()).hexdigest()!=TARGET:raise ValueError('input changed')
    receipt={'target_sha256':TARGET,'instruction_starts_checked':len(addresses),
             'supported_edges':len(supported),'unsupported_edge_encodings':unsupported,
             'call_paths_checked':len(checked),'paths':checked,'input_unchanged':True,
             'conditional_feasibility_evaluated':False,'call_returns_assumed':True,
             'game_functions_recovered':0,'original_oracle_tests':0}
    (out/'summary.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))

if __name__=='__main__':main()
