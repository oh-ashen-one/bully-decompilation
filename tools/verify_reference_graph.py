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

def instruction_flow(code):
    """Classify control-transfer encodings in LLVM-decoded 32-bit x86 instructions.

    System/trap and unhandled far transfers are not treated as ordinary fallthrough.
    This classifies flow only; LLVM remains responsible for instruction decoding.
    """
    if not code or len(code)>15:raise ValueError('invalid decoded instruction length')
    offset=0
    while offset<len(code) and code[offset] in (0x26,0x2e,0x36,0x3e,0x64,0x65,0x66,0x67,0xf0,0xf2,0xf3):offset+=1
    if offset==len(code):raise ValueError('prefix without instruction')
    op=code[offset];tail=code[offset:]
    if op==0xe8:return 'direct-call'
    if op in (0xe9,0xeb):return 'direct-jump'
    if 0x70<=op<=0x7f or 0xe0<=op<=0xe3 or (len(tail)>1 and op==0x0f and 0x80<=tail[1]<=0x8f):return 'conditional'
    if op==0xff:
        if len(tail)<2:raise ValueError('missing control-transfer ModRM')
        extension=(tail[1]>>3)&7
        if extension in (2,3):return 'indirect-call'
        if extension in (4,5):return 'indirect-jump'
    if op in (0xc2,0xc3,0xca,0xcb,0xcf):return 'return'
    if op in (0xea,0x9a,0xf4,0xcc,0xcd,0xce,0xf1):return 'unsupported-transfer'
    if len(tail)>1 and ((op==0x0f and tail[1] in (0x05,0x07,0x0b,0x34,0x35)) or
                       (op in (0xc6,0xc7) and tail[1]==0xf8)):
        return 'unsupported-transfer'
    return 'ordinary'

def relative_destination(address,code):
    if len(code)==5 and code[0] in (0xe8,0xe9):
        return (address+5+struct.unpack_from('<i',code,1)[0])&0xffffffff
    if len(code)==2 and (code[0]==0xeb or 0x70<=code[0]<=0x7f or 0xe0<=code[0]<=0xe3):
        return (address+2+struct.unpack_from('<b',code,1)[0])&0xffffffff
    if len(code)==6 and code[0]==0x0f and 0x80<=code[1]<=0x8f:
        return (address+6+struct.unpack_from('<i',code,2)[0])&0xffffffff
    return None

def validate_edge(source,dest,kind,code):
    if kind not in ('call','branch','fallthrough'):raise ValueError('unknown edge kind')
    if type(source) is not int or type(dest) is not int or not 0<=source<=0xffffffff or not 0<=dest<=0xffffffff:
        raise ValueError('invalid edge address')
    flow=instruction_flow(code)
    if kind=='fallthrough':
        valid=flow in ('ordinary','conditional','direct-call','indirect-call') and source+len(code)==dest
    else:
        permitted=('direct-call',) if kind=='call' else ('direct-jump','conditional')
        actual=relative_destination(source,code)
        valid=flow in permitted and actual is not None and actual==dest
    if not valid:raise ValueError('opcode, edge kind or destination disagreement')
    return True

def validate_call_path(path,source,target,root,decoded,supported):
    if not path or path[0]!=root or path[-1]!=source or any(x not in decoded for x in path):
        raise ValueError('path root, endpoint or instruction mismatch')
    if any(not any((x,y,kind) in supported for kind in ('branch','fallthrough')) for x,y in zip(path,path[1:])):
        raise ValueError('path edge lacks independent non-call support')
    validate_edge(source,target,'call',decoded[source])
    if (source,target,'call') not in supported:raise ValueError('call edge absent from graph')
    return True

def edge_fields(edge):
    if not isinstance(edge,dict) or edge.get('kind') not in ('call','branch','fallthrough'):
        raise ValueError('malformed edge kind')
    for key in ('from','to'):
        if not isinstance(edge.get(key),str) or not re.fullmatch('[0-9a-fA-F]{1,8}',edge[key]):
            raise ValueError('malformed edge address')
    return int(edge['from'],16),int(edge['to'],16),edge['kind']

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
        if match:
            if '<unknown>' in match[3] or match[3].lstrip().startswith('.'):continue
            decoded[int(match[1],16)]=bytes.fromhex(match[2])
    missing=addresses-decoded.keys()
    if missing:raise ValueError(f'linear decode disagrees at {len(missing)} graph starts; do not accept paths')
    pe=PE(data);base=pe.u32(pe.opt+28)
    for address in addresses:
        raw=decoded[address];off=pe.offset(address-base,len(raw))
        if raw!=data[off:off+len(raw)]:raise ValueError('decoded bytes disagree with original file')
    edges=json.loads((a.graph/'private-edges.json').read_text());supported=set()
    if not isinstance(edges,list):raise ValueError('malformed edge collection')
    for edge in edges:
        source,dest,kind=edge_fields(edge);code=decoded.get(source)
        if source not in addresses or code is None:raise ValueError('edge source absent from graph/decode')
        if kind!='call' and dest not in addresses:raise ValueError('edge leaves decoded graph')
        validate_edge(source,dest,kind,code)
        supported.add((source,dest,kind))
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
        validate_call_path(path,int(item['source_va'],16),int(item['target_va'],16),
                           base+pe.u32(pe.opt+16),decoded,supported)
        checked.append({'candidate_id':item['candidate_id'],'path_instruction_count':len(path),
                        'all_path_edges_independently_checked':True,'actual_execution_proven':False})
    if hashlib.sha256(a.input.read_bytes()).hexdigest()!=TARGET:raise ValueError('input changed')
    receipt={'target_sha256':TARGET,'instruction_starts_checked':len(addresses),
             'supported_edges':len(supported),'unsupported_edge_encodings':0,
             'opcode_edge_kinds_verified':True,'path_traversal_excludes_call_edges':True,
             'verifier_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
             'call_paths_checked':len(checked),'paths':checked,'input_unchanged':True,
             'conditional_feasibility_evaluated':False,'call_returns_assumed':True,
             'game_functions_recovered':0,'original_oracle_tests':0}
    (out/'summary.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))

if __name__=='__main__':main()
