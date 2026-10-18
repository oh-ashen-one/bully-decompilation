from pathlib import Path
import sys
import tempfile
import unittest
from tools.qualify import ROOT, run, verify_symbols


class QualificationTests(unittest.TestCase):
    def test_exact_symbols(self):
        verify_symbols('00000000 T _synthetic_handle_matches\n00000040 T _synthetic_handle_matches_stdcall@16\n')

    def test_missing_cdecl(self):
        with self.assertRaises(RuntimeError):
            verify_symbols('00000040 T _synthetic_handle_matches_stdcall@16\n')

    def test_missing_stdcall(self):
        with self.assertRaises(RuntimeError):
            verify_symbols('00000000 T _synthetic_handle_matches\n')

    def test_undefined_symbols_do_not_count(self):
        with self.assertRaises(RuntimeError):
            verify_symbols('U _synthetic_handle_matches\n00000040 T _synthetic_handle_matches_stdcall@16\n')

    def test_zero_exit_diagnostic_rejected_and_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(RuntimeError,'unexpected diagnostics'):
                run([sys.executable,'-c','import sys; sys.stderr.write("synthetic diagnostic\\n")'],
                    log_name='diagnostic',log_dir=tmp,reject_stderr=True)
            self.assertEqual((Path(tmp)/'diagnostic.stderr.txt').read_text(),'synthetic diagnostic\n')

    def test_injected_undefined_behavior_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'intentional_ub.c';binary=root/'intentional_ub'
            source.write_text('int main(void) { volatile int x=2147483647; volatile int y=x+1; (void)y; return 0; }\n')
            run(['clang','-O1','-fsanitize=undefined','-fno-sanitize-recover=all',str(source),'-o',str(binary)],
                log_name='ub-compile',log_dir=root)
            with self.assertRaisesRegex(RuntimeError,'failed'):
                run([str(binary)],log_name='ub-run',log_dir=root,reject_stderr=True)
            diagnostic=(root/'ub-run.stderr.txt').read_text()
            self.assertIn('runtime error',diagnostic)
            (ROOT/'build').mkdir(exist_ok=True)
            (ROOT/'build/expected-ubsan-negative.stderr.txt').write_text(
                diagnostic.replace(str(root),'<synthetic-temporary-dir>'))


if __name__ == '__main__':
    unittest.main()
