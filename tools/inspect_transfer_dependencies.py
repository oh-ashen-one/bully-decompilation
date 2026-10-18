#!/usr/bin/env python3
"""Query a private cached value index; does not execute or emulate retail code."""
import argparse
from collections import Counter,deque
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent

def inspect_index(index,sites,node_limit=4096,mode='transfers'):
    if mode not in ('transfers','returns','call-arguments'):raise ValueError('unknown root mode')
    nodes={x['id']:x for x in index['nodes']};ops={x['id']:x for x in index['operations']}
    if len(nodes)!=len(index['nodes']) or len(ops)!=len(index['operations']):raise ValueError('duplicate index identities')
    if len(nodes)>50000 or len(ops)>50000:raise ValueError('index size budget')
    for op in ops.values():
        if any(x not in nodes for x in op['inputs']):raise ValueError('dangling input')
        output=op.get('output')
        if output is not None and (output not in nodes or nodes[output].get('definition')!=op['id']):
            raise ValueError('inconsistent output/definition')
    reports=[];private=[]
    roots=[]
    for op in ops.values():
        if mode=='returns' and op['opcode']=='RETURN':
            roots.extend((op,i) for i in range(1,len(op['inputs'])))
        elif mode=='call-arguments' and op['site'] in sites and op['opcode'] in ('CALL','CALLIND'):
            roots.extend((op,i) for i in range(1,len(op['inputs'])))
        elif mode=='transfers' and op['site'] in sites and op['opcode'] in ('CALLIND','BRANCHIND'):
            roots.append((op,0))
    for root,root_input in roots:
        root_id=root['inputs'][root_input]
        queue=deque([root_id]);visited=set();used_ops=set();kinds=Counter()
        calls=set();direct_calls=set();loads=set();dynamic_loads=set();input_nodes=set();side_effects=set()
        while queue and len(visited)<node_limit:
            node_id=queue.popleft()
            if node_id in visited:continue
            visited.add(node_id);node=nodes[node_id]
            if node['constant']:continue
            definition=node.get('definition')
            if definition is None:input_nodes.add(node_id);continue
            if definition not in ops:raise ValueError('dangling definition')
            op=ops[definition];code=op['opcode'];used_ops.add(definition);kinds[code]+=1
            if code in ('CALL','CALLIND'):
                calls.add(definition)
                # Follow callee identity, not a speculative model of its returned value.
                if code=='CALL':direct_calls.add(definition)
                else:queue.append(op['inputs'][0])
            elif code=='LOAD':
                loads.add(definition)
                if not nodes[op['inputs'][1]]['constant']:dynamic_loads.add(definition)
                queue.append(op['inputs'][1])
            elif code=='INDIRECT':
                side_effects.add(definition);queue.append(op['inputs'][0])
            else:queue.extend(op['inputs'])
        reports.append({'root_is_constant':nodes[root_id]['constant'],
                        'visited_values':len(visited),'operation_counts':dict(sorted(kinds.items())),
                        'call_return_boundaries':len(calls),'memory_value_boundaries':len(loads),
                        'direct_callee_return_boundaries':len(direct_calls),
                        'computed_callee_return_boundaries':len(calls-direct_calls),
                        'dynamic_address_memory_reads':len(dynamic_loads),'unbound_input_leaves':len(input_nodes),
                        'indirect_side_effect_markers':len(side_effects),'budget_exhausted':bool(queue),
                        'resolved_constant_root':nodes[root_id]['constant'],
                        'execution_or_semantics_proven':False})
        private.append({'root_operation':root['id'],'site':root['site'],'node_ids':sorted(visited),
                        'root_input_index':root_input,
                        'operation_ids':sorted(used_ops),'call_boundary_ops':sorted(calls),
                        'load_boundary_ops':sorted(loads),'input_node_ids':sorted(input_nodes)})
    return reports,private

def main():
    p=argparse.ArgumentParser();p.add_argument('--graph',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--mode',choices=('transfers','returns','call-arguments'),default='transfers')
    p.add_argument('--callee-graph',type=Path);a=p.parse_args()
    index_path=a.graph/'private-value-index.json';index=json.loads(index_path.read_text())
    terminals=json.loads((a.graph/'private-terminals.json').read_text())
    sites={x['address'] for x in terminals if x['kind']=='computed-flow'}
    if a.mode=='call-arguments':
        if a.callee_graph is None:raise ValueError('callee graph required')
        request=json.loads((a.callee_graph/'reference-request.json').read_text())
        target=request['entry_va'];nodes={x['id']:x for x in index['nodes']}
        sites={x['site'] for x in index['operations'] if x['opcode']=='CALL' and
               int(nodes[x['inputs'][0]]['offset'],16)==target}
    reports,private=inspect_index(index,sites,mode=a.mode)
    out=a.output.resolve()
    if not out.is_relative_to(ROOT/'local-private'):raise ValueError('private output required')
    out.mkdir(parents=True,exist_ok=False)
    (out/'private-slices.json').write_text(json.dumps(private,indent=2)+'\n')
    receipt={'target_sha256':json.loads((a.graph/'summary.json').read_text())['target_sha256'],
             'value_index_sha256':hashlib.sha256(index_path.read_bytes()).hexdigest(),
             'index_nodes':len(index['nodes']),'index_operations':len(index['operations']),
             'selected_sites':len(sites),'dependency_roots_found':len(reports),'reports':reports,
             'root_mode':a.mode,
             'method':'Backward value/callee-identity slice; call returns and memory reads remain unknown values.',
             'game_functions_recovered':0,'original_oracle_tests':0}
    (out/'summary.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))

if __name__=='__main__':main()
