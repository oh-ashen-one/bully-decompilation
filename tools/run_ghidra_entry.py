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
import struct

ROOT = Path(__file__).resolve().parent.parent
TARGET = '36ff31682081a61ba564cb5e09cd6240f79791879cf1fbfb8e6252f75faddc6c'

def validate_summary(summary, digest, candidate=False, graph=False):
    if not isinstance(summary,dict) or summary.get('target_sha256') != digest:
        raise ValueError('summary target identity mismatch')
    if summary.get('auto_analysis') is not False or summary.get('game_functions_recovered') != 0:
        raise ValueError('summary analysis scope mismatch')
    def number(key, low, high):
        value=summary.get(key)
        if type(value) is not int or not low<=value<=high:
            raise ValueError('invalid summary field: '+key)
        return value
    if graph:
        if summary.get('graph_completed') is not True or summary.get('budget_exhausted') is not False:
            raise ValueError('reference graph incomplete')
        leads=number('reference_leads',0,16)
        number('matched_call_paths',0,leads)
        count=number('visited_instruction_addresses',1,16384)
        number('decoded_bytes',1,65550)
        number('queued_at_stop',0,0)
        for key in ('calls','computed_calls','computed_jumps','returns','undecoded_destinations','destinations_outside_section'):
            number(key,0,count)
    elif candidate:
        if summary.get('scan_completed') is not True:
            raise ValueError('candidate scan incomplete')
        seeds=number('seed_count',1,6)
        closed=number('closed_leaf_candidates',0,seeds)
        number('decompiled_candidates',0,closed)
        number('window_bytes_per_seed',256,256)
        number('instruction_start_budget_bytes',242,242)
    else:
        if summary.get('disassembly_applied') is not True:
            raise ValueError('disassembly was not applied')
        number('window_bytes',256,256)
        number('instruction_start_budget_bytes',242,242)
        count=number('reachable_instruction_count',1,256)
        number('decoded_bytes',count,256)
        number('flow_edges_outside_window',0,512)
        number('terminal_instructions',0,count)
        number('call_instructions',0,count)
    return True

def main():
    p = argparse.ArgumentParser()
    p.add_argument('input', type=Path)
    p.add_argument('--ghidra', type=Path, required=True)
    p.add_argument('--java-home', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--synthetic', action='store_true')
    p.add_argument('--candidate-seeds', type=Path, help='Private hex VA seeds; bounded candidate scan instead of entry audit')
    p.add_argument('--reference-graph', type=Path, help='Private reference request; bounded entry graph instead of entry audit')
    a = p.parse_args()
    if a.candidate_seeds and a.reference_graph:
        raise ValueError('choose one analysis mode')
    source, ghidra = a.input.resolve(), a.ghidra.resolve()
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    if a.synthetic:
        if a.reference_graph:
            try: from .graph_fixture import fixture_bytes
            except ImportError: from graph_fixture import fixture_bytes
            if source.read_bytes() not in (fixture_bytes(),fixture_bytes(indirect=True),fixture_bytes(indirect=True,call_return=True)):
                raise ValueError('unexpected graph fixture')
        else:
        # Fixed, independently compiled synthetic text plus padding; no arbitrary input.
            expected_size=320 if a.candidate_seeds else 256
            if len(source.read_bytes()) != expected_size or hashlib.sha256(source.read_bytes()[:122]).hexdigest() != 'bfae632830f91dc73b91c72e7cd9cec985ba4c1ceaa807ce94eaad153b082f5a' or any(source.read_bytes()[122:]):
                raise ValueError('unexpected synthetic fixture')
    elif digest != TARGET:
        raise ValueError('target SHA-256 mismatch')
    out = a.output.resolve()
    if not out.is_relative_to(ROOT/'local-private'):
        raise ValueError('raw evidence must stay under local-private')
    out.mkdir(parents=True, exist_ok=False)
    script='BoundedEntryAudit.java'
    script_args=[str(out),digest]
    if a.candidate_seeds:
        seeds=a.candidate_seeds.resolve()
        if not seeds.is_relative_to(ROOT/'local-private'):
            raise ValueError('seed file must be private')
        lines=seeds.read_text().splitlines()
        if not 1<=len(lines)<=6 or any(not 0<=int(x,16)<=0xffffffff for x in lines):
            raise ValueError('invalid seed count/address')
        (out/'seeds.txt').write_text(seeds.read_text())
        script='BoundedCandidateScan.java'
        script_args.append(str(out/'seeds.txt'))
    if a.reference_graph:
        request=a.reference_graph.resolve()
        if not request.is_relative_to(ROOT/'local-private'):
            raise ValueError('reference request must be private')
        value=json.loads(request.read_text())
        if not isinstance(value.get('references'),list) or len(value['references'])>16:
            raise ValueError('invalid reference budget')
        if value.get('section')!=('ram' if a.synthetic else '.bind'):
            raise ValueError('reference graph section mismatch')
        if 'parent_call_site' in value:
            parent=Path(value['parent_graph']).resolve()
            if not parent.is_relative_to(ROOT/'local-private'):
                raise ValueError('parent evidence must be private')
            prior=json.loads((parent/'summary.json').read_text())
            if prior.get('target_sha256')!=digest or prior.get('graph_completed') is not True:
                raise ValueError('parent evidence identity/completion mismatch')
            call=value['parent_call_site'];target=value['entry_va']
            if not any(x['kind']=='call' and int(x['from'],16)==call and int(x['to'],16)==target
                       for x in json.loads((parent/'private-edges.json').read_text())):
                raise ValueError('parent does not establish requested direct edge')
            if a.synthetic: offset=call-0x020f32ed
            else:
                try: from .fingerprint import PE
                except ImportError: from fingerprint import PE
                pe=PE(source.read_bytes());offset=pe.offset(call-pe.u32(pe.opt+28),5)
            code=source.read_bytes()[offset:offset+5]
            if len(code)!=5 or code[0]!=0xe8 or (call+5+struct.unpack_from('<i',code,1)[0])&0xffffffff!=target:
                raise ValueError('original bytes do not validate direct call')
        elif value.get('entry_va')!=0x020f32ed:
            raise ValueError('reference graph must start at the verified entry')
        (out/'reference-request.json').write_text(request.read_text())
        script='BoundedReferenceGraph.java'
        script_args.append(str(out/'reference-request.json'))
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
            '-scriptPath',str(ROOT/'tools/ghidra'),'-postScript',script,
            *script_args,'-log',str(out/'ghidra.log'),'-scriptlog',str(out/'script.log')]
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
    summary_valid=False; summary_error=None
    try:
        summary_valid=validate_summary(json.loads((out/'summary.json').read_text()),digest,
                                       candidate=bool(a.candidate_seeds),graph=bool(a.reference_graph))
    except (ValueError,OSError) as error:
        summary_error=type(error).__name__+': '+str(error)
    receipt = {'input_sha256':digest,'synthetic':a.synthetic,'exit_code':rc,
               'script':script,
               'deadline_seconds':180,'timed_out':timed_out,
               'elapsed_seconds':round(time.monotonic()-start,2),
               'input_unchanged':unchanged,'summary_written':(out/'summary.json').exists(),
               'summary_structurally_valid':summary_valid,'summary_validation_error':summary_error,
               'configured_heap':'2G','configured_active_processors':2,
               'configured_ghidra_max_cpu':2,'target_executed':False}
    (out/'run.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt))
    if rc or timed_out or not unchanged or not summary_valid:
        raise SystemExit(1)

if __name__ == '__main__':
    main()
