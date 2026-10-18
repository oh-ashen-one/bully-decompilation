import unittest
from tools.scan_candidate_references import direct_patterns,relative_target
from tools.verify_reference_graph import relative_destination
from tools.graph_fixture import fixture_bytes,fixture_request
from tools.run_ghidra_entry import validate_summary

class ReferenceGraphTests(unittest.TestCase):
    def test_signed_and_wrapped_rel32(self):
        self.assertEqual(relative_target(0x1000,0,-5),0x1000)
        self.assertEqual(relative_target(0xfffffffe,0,0),3)
        self.assertEqual(direct_patterns(bytes.fromhex('e8 fb ff ff ff'),0x1000,0x1000),[(0,'rel32_call')])

    def test_truncated_and_noncall_encodings(self):
        self.assertEqual(direct_patterns(bytes.fromhex('e8 00 00 00'),0,5),[])
        self.assertEqual(direct_patterns(bytes.fromhex('90 00 00 00 00'),0,5),[])
        self.assertEqual(direct_patterns(bytes.fromhex('e9 00 00 00 00'),0,5),[(0,'rel32_jump')])

    def test_independent_relative_decoder(self):
        self.assertEqual(relative_destination(0x1000,bytes.fromhex('75 fe')),0x1000)
        self.assertEqual(relative_destination(0x1000,bytes.fromhex('0f 84 fa ff ff ff')),0x1000)
        self.assertIsNone(relative_destination(0x1000,bytes.fromhex('ff e0')))

    def test_synthetic_contains_unreachable_encoding_lead(self):
        for indirect in (False,True):
            data=fixture_bytes(indirect);request=fixture_request(indirect);base=request['entry_va']
            refs=request['references']
            self.assertEqual(len(refs),3)
            self.assertEqual(len(direct_patterns(data,base,refs[0]['target_va'])),2)
            for ref in refs:
                offset=ref['source_va']-base
                self.assertEqual(relative_destination(ref['source_va'],data[offset:offset+5]),ref['target_va'])

    def test_graph_summary_rejects_budget_and_bad_counts(self):
        row=dict(target_sha256='target',auto_analysis=False,game_functions_recovered=0,
                 graph_completed=True,budget_exhausted=False,reference_leads=3,matched_call_paths=2,
                 visited_instruction_addresses=9,decoded_bytes=23,queued_at_stop=0,calls=2,
                 computed_calls=0,computed_jumps=0,returns=1,undecoded_destinations=0,destinations_outside_section=0)
        self.assertTrue(validate_summary(row,'target',graph=True))
        for key,value in [('budget_exhausted',True),('graph_completed',False),('matched_call_paths',4),
                          ('decoded_bytes',0),('computed_calls',10),('queued_at_stop',1)]:
            broken=dict(row);broken[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):validate_summary(broken,'target',graph=True)
