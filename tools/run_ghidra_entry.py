#!/usr/bin/env python3
"""Bounded, local-only Ghidra entry audit; never runs the target executable."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parent.parent
TARGET = '36ff31682081a61ba564cb5e09cd6240f79791879cf1fbfb8e6252f75faddc6c'

def main():
    p = argparse.ArgumentParser()
    p.add_argument('input', type=Path)
    p.add_argument('--ghidra', type=Path, required=True)
    p.add_argument('--java-home', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--synthetic', action='store_true')
    a = p.parse_args()
    source, ghidra = a.input.resolve(), a.ghidra.resolve()
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    if a.synthetic:
        # Fixed, independently compiled synthetic text plus padding; no arbitrary input.
        if len(source.read_bytes()) != 256 or hashlib.sha256(source.read_bytes()[:122]).hexdigest() != 'bfae632830f91dc73b91c72e7cd9cec985ba4c1ceaa807ce94eaad153b082f5a' or any(source.read_bytes()[122:]):
            raise ValueError('unexpected synthetic fixture')
    elif digest != TARGET:
        raise ValueError('target SHA-256 mismatch')
    out = a.output.resolve()
    if not out.is_relative_to(ROOT/'local-private'):
        raise ValueError('raw evidence must stay under local-private')
    out.mkdir(parents=True, exist_ok=False)
    for child in ['home','tmp','cache','settings','project']:
        (out/child).mkdir()
    java = str(a.java_home.resolve()/'bin/java')
    env = {k:v for k,v in os.environ.items() if k in ('PATH','USER','LOGNAME','LANG')}
    env['TMPDIR'] = str(out/'tmp')
    isolated = [f'-Duser.home={out/"home"}', f'-Djava.io.tmpdir={out/"tmp"}',
                f'-Dapplication.cachedir={out/"cache"}', f'-Dapplication.settingsdir={out/"settings"}']
    support = subprocess.run([java, *isolated, '-cp', str(ghidra/'support/LaunchSupport.jar'),
                              'LaunchSupport', str(ghidra), '-vmargs'], env=env,
                             capture_output=True, text=True, timeout=30, check=True)
    (out/'launch-support.stderr.log').write_text(support.stderr)
    vmargs = support.stdout.splitlines()
    if any(not x.startswith('-') for x in vmargs):
        raise ValueError('invalid launch arguments')
    cmd = [java, *vmargs, *isolated, '-Xmx2G', '-XX:ActiveProcessorCount=2',
           '-XX:ParallelGCThreads=2', '-XX:CICompilerCount=2', '-Djava.awt.headless=true',
           '-cp', str(ghidra/'Ghidra/Framework/Utility/lib/Utility.jar'),
           'ghidra.Ghidra', 'ghidra.app.util.headless.AnalyzeHeadless',
           str(out/'project'), 'bounded-entry', '-import', str(source)]
    if a.synthetic:
        cmd += ['-loader','BinaryLoader','-loader-baseAddr','0x020f32ed',
                '-processor','x86:LE:32:default','-cspec','windows']
    cmd += ['-noanalysis','-max-cpu','2','-readOnly','-deleteProject',
            '-scriptPath',str(ROOT/'tools/ghidra'),'-postScript','BoundedEntryAudit.java',
            str(out),digest,'-log',str(out/'ghidra.log'),'-scriptlog',str(out/'script.log')]
    start = time.monotonic()
    with (out/'stdout.log').open('x') as stdout, (out/'stderr.log').open('x') as stderr:
        proc = subprocess.Popen(cmd, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
        timed_out = False
        try:
            rc = proc.wait(timeout=180)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(proc.pid, signal.SIGTERM)
            try: rc = proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                rc = proc.wait()
    unchanged = hashlib.sha256(source.read_bytes()).hexdigest() == digest
    receipt = {'input_sha256':digest,'synthetic':a.synthetic,'exit_code':rc,
               'deadline_seconds':180,'timed_out':timed_out,
               'elapsed_seconds':round(time.monotonic()-start,2),
               'input_unchanged':unchanged,'summary_written':(out/'summary.json').exists(),
               'configured_heap':'2G','configured_active_processors':2,
               'configured_ghidra_max_cpu':2,'target_executed':False}
    (out/'run.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt))
    if rc or timed_out or not unchanged or not receipt['summary_written']:
        raise SystemExit(1)

if __name__ == '__main__':
    main()
