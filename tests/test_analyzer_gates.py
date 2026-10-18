import unittest
from tools.check_rea_synthetic import require_native_arm64
from tools.run_ghidra_entry import validate_summary

class AnalyzerGates(unittest.TestCase):
    def entry(self):
        return dict(target_sha256='expected',auto_analysis=False,game_functions_recovered=0,
                    disassembly_applied=True,window_bytes=256,instruction_start_budget_bytes=242,
                    reachable_instruction_count=21,decoded_bytes=56,flow_edges_outside_window=0,
                    terminal_instructions=1,call_instructions=0)

    def test_actual_platform_required(self):
        self.assertEqual(require_native_arm64('arm64','Darwin')['machine'],'arm64')
        for machine,system in [('x86_64','Darwin'),('arm64','Linux'),('unknown','Darwin')]:
            with self.subTest(machine=machine,system=system),self.assertRaises(ValueError):
                require_native_arm64(machine,system)

    def test_valid_entry(self):
        self.assertTrue(validate_summary(self.entry(),'expected'))

    def test_existence_alone_is_not_success(self):
        for value in [{},[],None]:
            with self.subTest(value=value),self.assertRaises(ValueError):
                validate_summary(value,'expected')

    def test_failed_disassembly_and_bad_counts_rejected(self):
        for key,value in [('disassembly_applied',False),('reachable_instruction_count',0),
                          ('decoded_bytes',257),('decoded_bytes',10),('call_instructions',22),
                          ('reachable_instruction_count',True),('auto_analysis',True),
                          ('target_sha256','different')]:
            row=self.entry();row[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                validate_summary(row,'expected')

    def test_candidate_counts_and_completion(self):
        row=dict(target_sha256='expected',auto_analysis=False,game_functions_recovered=0,
                 scan_completed=True,seed_count=6,closed_leaf_candidates=1,
                 decompiled_candidates=1,window_bytes_per_seed=256,instruction_start_budget_bytes=242)
        self.assertTrue(validate_summary(row,'expected',candidate=True))
        for key,value in [('scan_completed',False),('closed_leaf_candidates',7),
                          ('decompiled_candidates',2),('seed_count',0)]:
            bad=dict(row);bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):
                validate_summary(bad,'expected',candidate=True)
