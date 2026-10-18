#!/usr/bin/env python3
"""Task-local REA/Ghidra qualification on the original synthetic fixture only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import time

ROOT = Path(__file__).resolve().parent.parent
COFF_SHA = 'ab00b31b6c5cc67210935ebdf06643b75aa5b14a7692436adcf3ccc777d25549'
TEXT_SHA = 'bfae632830f91dc73b91c72e7cd9cec985ba4c1ceaa807ce94eaad153b082f5a'

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--rea',type=Path,required=True,help='Pinned scripts/rea.mjs')
    p.add_argument('--ghidra',type=Path,required=True)
    p.add_argument('--java-home',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    data=(ROOT/'build/synthetic_handle.obj').read_bytes()
    if hashlib.sha256(data).hexdigest()!=COFF_SHA:
        raise ValueError('run tools/qualify.py with the qualified compiler first')
    text=None
    n=struct.unpack_from('<H',data,2)[0];opt=struct.unpack_from('<H',data,16)[0]
    for i in range(n):
        o=20+opt+40*i
        if data[o:o+8].rstrip(b'\0')==b'.text':
            size,offset=struct.unpack_from('<II',data,o+16)
            if struct.unpack_from('<H',data,o+32)[0]: raise ValueError('relocations unsupported')
            text=data[offset:offset+size]
    if text is None or hashlib.sha256(text).hexdigest()!=TEXT_SHA:
        raise ValueError('unexpected synthetic text')
    out=a.output.resolve()
    if not out.is_relative_to(ROOT/'local-private'): raise ValueError('private output required')
    out.mkdir(parents=True,exist_ok=False)
    (out/'tmp').mkdir(); target=out/'synthetic.bin'; target.write_bytes(text)
    env={k:v for k,v in os.environ.items() if k in ('PATH','LANG','USER','LOGNAME')}
    env.update(TMPDIR=str(out/'tmp'),GHIDRA_INSTALL_DIR=str(a.ghidra.resolve()),
               JAVA_HOME=str(a.java_home.resolve()),GHIDRA_HEADLESS_MAXMEM='512M',
               REA_GHIDRA_STARTUP_TIMEOUT_MS='180000',
               REA_DARWIN_MODULE_CACHE_PATH=str(out/'swift-cache'))
    cmd=['node',str(a.rea.resolve()),'decompile',str(target),'0x1000',
         '--target-format','raw-binary','--architecture','x86','--entry-point','0x1000',
         '--provider','ghidra','--json']
    start=time.monotonic(); timed_out=False
    with (out/'result.json').open('x') as stdout,(out/'stderr.log').open('x') as stderr:
        proc=subprocess.Popen(cmd,env=env,stdout=stdout,stderr=stderr,start_new_session=True)
        try: rc=proc.wait(timeout=210)
        except subprocess.TimeoutExpired:
            timed_out=True;proc.send_signal(signal.SIGTERM)
            try:rc=proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid,signal.SIGKILL);rc=proc.wait()
    receipt={'exit_code':rc,'timed_out':timed_out,'deadline_seconds':210,
             'elapsed_seconds':round(time.monotonic()-start,2),
             'fixture_sha256':TEXT_SHA,'configured_heap':'512M',
             'cpu_limit_exposed_by_rea':False,'heap_measured':False,
             'target_executed':False,'original_game_input':False}
    (out/'run.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt))
    if rc or timed_out: raise SystemExit(1)

if __name__=='__main__': main()
