#!/usr/bin/env python3
"""Map import metadata locally; scan only .text for one public API anchor.

The byte-pattern scan is a lead generator, NOT a disassembler or boundary oracle.
No raw import names/addresses are printed to a cloud-controlled terminal.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
try:
    from .fingerprint import PE, InvalidPE
    from .audit_entry import TARGET
except ImportError:
    from fingerprint import PE, InvalidPE
    from audit_entry import TARGET


def import_slots(pe):
    rva, size = pe.directory(1)
    if not rva:
        return []
    records = []
    occupied = set()
    base = pe.u32(pe.opt + 28)
    for i in range(min(size // 20, 4096)):
        fields = pe.unpack('<IIIII', pe.offset(rva+i*20,20))
        if not any(fields):
            return records
        lookup, _, _, name, iat = fields
        if not lookup:
            raise InvalidPE('missing original import lookup table; bound-IAT interpretation not guessed')
        dll = pe.cstring(name)
        for n in range(65536):
            entry = pe.u32(pe.offset(lookup+4*n,4))
            if not entry:
                break
            slot = iat+4*n
            pe.offset(slot,4)
            if slot in occupied or base+slot > 0xffffffff:
                raise InvalidPE('duplicate or overflowing IAT slot')
            occupied.add(slot)
            ordinal = entry & 65535 if entry & 0x80000000 else None
            if ordinal is not None and entry & 0x7fff0000:
                raise InvalidPE('reserved ordinal bits set')
            symbol = None
            if ordinal is None:
                pe.offset(entry,2)  # hint
                symbol = pe.cstring(entry+2,limit=1024)
            records.append(dict(dll=dll,name=symbol,ordinal=ordinal,iat_rva=slot,iat_va=base+slot))
        else:
            raise InvalidPE('unterminated import lookup table')
    raise InvalidPE('unterminated descriptor table')


def anchor_candidates(pe, slots, symbol='GetTickCount'):
    sections=[s for s in pe.sections if s['name']=='.text']
    if len(sections)!=1:
        raise InvalidPE('expected one .text section')
    section=sections[0]
    # Bound to initialized .text bytes; never scan virtual zero-fill or all files.
    data=pe.take(section['raw_offset'],min(section['raw_size'],section['virtual_size']))
    anchors=[r for r in slots if r['dll'].lower()=='kernel32.dll' and r['name']==symbol]
    result=[]
    for item in anchors:
        pattern=b'\xff\x15'+struct.pack('<I',item['iat_va'])
        pos=0
        while True:
            pos=data.find(pattern,pos)
            if pos<0:
                break
            result.append(dict(candidate_rva=section['rva']+pos,iat_rva=item['iat_rva']))
            pos+=1
    return anchors,result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('executable',type=Path)
    args=parser.parse_args()
    data=args.executable.read_bytes()
    if hashlib.sha256(data).hexdigest()!=TARGET:
        parser.error('unexpected target hash; no mapping performed')
    pe=PE(data); slots=import_slots(pe); anchors,candidates=anchor_candidates(pe,slots)
    out=Path(__file__).resolve().parent.parent/'local-private'/TARGET/'import-map-v1'
    out.mkdir(parents=True,exist_ok=False)
    (out/'imports.json').write_text(json.dumps(slots,indent=2)+'\n')
    (out/'get-tick-count-candidates.json').write_text(json.dumps(candidates,indent=2)+'\n')
    if hashlib.sha256(args.executable.read_bytes()).hexdigest()!=TARGET:
        parser.exit(1,'input changed during mapping; evidence invalid\n')
    receipt=dict(schema_version=1,target_sha256=TARGET,
                 import_descriptors=len({r['dll'].lower() for r in slots}),
                 imported_slots=len(slots),named_imports=sum(r['name'] is not None for r in slots),
                 ordinal_imports=sum(r['ordinal'] is not None for r in slots),
                 anchor='KERNEL32.GetTickCount',anchor_slots=len(anchors),
                 candidate_byte_patterns=len(candidates),
                 candidate_instruction_boundaries_verified=False,
                 recovered_game_functions=0,original_oracle_tests=0,input_unchanged=True,
                 scan_bound='initialized bytes of the single .text section',
                 limitation='FF 15 absolute-IAT patterns can occur inside data or instructions; candidates are unverified and not function coverage')
    (out/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print('Private import map and bounded anchor candidates saved; no raw map emitted.')


if __name__=='__main__':
    main()
