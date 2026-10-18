import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from test_fingerprint import fixture
from tools import verify_reference_graph as verifier


class ReferenceEdgeSemanticsTests(unittest.TestCase):
    def test_no_fallthrough_after_returns(self):
        for raw in ('c3','c2 08 00','cb','ca 08 00','f3 c3','cf'):
            code=bytes.fromhex(raw)
            with self.subTest(raw=raw),self.assertRaises(ValueError):
                verifier.validate_edge(0x1000,0x1000+len(code),'fallthrough',code)

    def test_no_fallthrough_after_unconditional_jumps(self):
        for raw in ('e9 00 00 00 00','eb 00','ff e0','ff 20','2e ff e0'):
            code=bytes.fromhex(raw)
            with self.subTest(raw=raw),self.assertRaises(ValueError):
                verifier.validate_edge(0x1000,0x1000+len(code),'fallthrough',code)

    def test_jump_is_not_call_or_call_a_branch(self):
        for raw,kind in [('e9 00 00 00 00','call'),('eb 03','call'),
                         ('75 03','call'),('e8 00 00 00 00','branch')]:
            with self.subTest(raw=raw),self.assertRaises(ValueError):
                verifier.validate_edge(0x1000,0x1005,kind,bytes.fromhex(raw))

    def test_valid_call_conditional_and_ordinary_edges(self):
        for raw,kind,dest in [('e8 00 00 00 00','call',0x1005),
                              ('e8 00 00 00 00','fallthrough',0x1005),
                              ('ff d0','fallthrough',0x1002),('75 03','branch',0x1005),
                              ('75 03','fallthrough',0x1002),('90','fallthrough',0x1001)]:
            self.assertTrue(verifier.validate_edge(0x1000,dest,kind,bytes.fromhex(raw)))

    def test_call_edge_cannot_be_a_path_step(self):
        decoded={0x1000:bytes.fromhex('e8 00 00 00 00'),0x1005:bytes.fromhex('e8 00 00 00 00')}
        supported={(0x1000,0x1005,'call'),(0x1005,0x100a,'call')}
        with self.assertRaises(ValueError):
            verifier.validate_call_path([0x1000,0x1005],0x1005,0x100a,0x1000,decoded,supported)

    def test_endpoint_requires_actual_call_even_with_forged_relation(self):
        decoded={0x1000:bytes.fromhex('e9 fb ff ff ff')}
        with self.assertRaises(ValueError):
            verifier.validate_call_path([0x1000],0x1000,0x1000,0x1000,decoded,{(0x1000,0x1000,'call')})

    def test_malformed_edges_and_unsupported_transfers_fail_closed(self):
        for edge in [None,{},dict(kind='jump',**{'from':'1000','to':'1001'}),
                     dict(kind='call',**{'from':1000,'to':'1001'}),
                     dict(kind='call',**{'from':'1000','to':'100000000'})]:
            with self.subTest(edge=edge),self.assertRaises(ValueError):verifier.edge_fields(edge)
        for raw in ('cc','cd 80','f4','0f 0b','0f 34','ea 00 00 00 00 00 00'):
            code=bytes.fromhex(raw)
            with self.subTest(raw=raw),self.assertRaises(ValueError):
                verifier.validate_edge(0x1000,0x1000+len(code),'fallthrough',code)

    def test_reviewers_synthetic_main_reproducer_is_rejected(self):
        data=bytearray(fixture());data[0x200:0x208]=bytes.fromhex('c3 90 e9 fb ff ff ff c3')
        digest=hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();private=root/'local-private';graph=private/'graph';graph.mkdir(parents=True)
            source=private/'invented.exe';source.write_bytes(data)
            summary=dict(target_sha256=digest,auto_analysis=False,game_functions_recovered=0,
                graph_completed=True,budget_exhausted=False,reference_leads=1,matched_call_paths=1,
                visited_instruction_addresses=3,decoded_bytes=7,queued_at_stop=0,calls=1,
                computed_calls=0,computed_jumps=0,returns=1,undecoded_destinations=0,destinations_outside_section=0)
            (graph/'summary.json').write_text(json.dumps(summary))
            (graph/'reachable.asm').write_text('401000 RET\n401001 NOP\n401002 JMP 401002\n')
            edges=[dict(zip(('from','to','kind'),row)) for row in
                   [('401000','401001','fallthrough'),('401001','401002','fallthrough'),('401002','401002','call')]]
            (graph/'private-edges.json').write_text(json.dumps(edges))
            (graph/'private-matched-paths.json').write_text(json.dumps([dict(candidate_id='invented',
                source_va='401002',target_va='401002',path=['401000','401001','401002'])]))
            llvm='401000: c3 retl\n401001: 90 nop\n401002: e9 fb ff ff ff jmp 401002\n'
            output=private/'check'
            with patch.object(verifier,'ROOT',root),patch.object(verifier,'TARGET',digest),\
                 patch.object(sys,'argv',['check',str(source),'--graph',str(graph),'--output',str(output)]),\
                 patch.object(verifier.subprocess,'run',return_value=subprocess.CompletedProcess([],0,llvm,'')),\
                 self.assertRaisesRegex(ValueError,'opcode, edge kind'):
                verifier.main()
            self.assertFalse((output/'summary.json').exists())
