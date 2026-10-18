import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from tools.audit_entry import MODE_OUTPUTS, capture_window


class EntryAuditTests(unittest.TestCase):
    def test_output_names_are_casefold_unique(self):
        names = [f'{label}.{ext}'.casefold() for _,label in MODE_OUTPUTS
                 for ext in ['asm','stderr.txt']]
        self.assertEqual(len(names),len(set(names)))

    def test_both_results_preserved(self):
        def fake(args, **kwargs):
            mode=args[2]
            return subprocess.CompletedProcess(args,0,f'synthetic {mode}\n',f'note {mode}\n')
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)
            results=capture_window('invented-input',0x1000,out,runner=fake)
            for result in results:
                content=(out/result['output_file']).read_text()
                self.assertEqual(content,f"synthetic {result['mode']}\n")
                self.assertEqual(hashlib.sha256(content.encode()).hexdigest(),result['raw_output_sha256'])
            self.assertFalse((out/'code-only.asm').samefile(out/'all-sections.asm'))


if __name__ == '__main__':
    unittest.main()
