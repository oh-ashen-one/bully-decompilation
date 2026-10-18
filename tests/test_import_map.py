import struct
import unittest
from tools.fingerprint import PE, InvalidPE
from tools.map_imports import import_slots, anchor_candidates
from test_fingerprint import fixture


def imports_fixture():
    b=fixture()
    b[0x178:0x180]=b'.text\0\0\0'
    struct.pack_into('<II',b,0x98+104,0x1000,40)
    struct.pack_into('<IIIII',b,0x200,0x1060,0,0,0x1080,0x1050)
    struct.pack_into('<III',b,0x260,0x10a0,0x80000007,0)
    b[0x280:0x28d]=b'KERNEL32.dll\0'
    b[0x2a2:0x2af]=b'GetTickCount\0'
    # Invented pattern both in "code" and arbitrary bytes: scanner cannot distinguish.
    b[0x300:0x306]=b'\xff\x15'+struct.pack('<I',0x401050)
    b[0x310:0x316]=b'\xff\x15'+struct.pack('<I',0x401050)
    return b


class ImportMapTests(unittest.TestCase):
    def test_named_and_ordinal_slots(self):
        p=PE(imports_fixture());rows=import_slots(p)
        self.assertEqual(len(rows),2)
        self.assertEqual(rows[0]['name'],'GetTickCount')
        self.assertEqual(rows[1]['ordinal'],7)
        self.assertEqual(rows[0]['iat_va'],0x401050)

    def test_candidates_are_not_instruction_boundaries(self):
        p=PE(imports_fixture());anchors,candidates=anchor_candidates(p,import_slots(p))
        self.assertEqual(len(anchors),1)
        self.assertEqual([r['candidate_rva'] for r in candidates],[0x1100,0x1110])

    def test_missing_lookup_fails_closed(self):
        b=imports_fixture();struct.pack_into('<I',b,0x200,0)
        with self.assertRaises(InvalidPE):import_slots(PE(b))

    def test_reserved_ordinal_bits_rejected(self):
        b=imports_fixture();struct.pack_into('<I',b,0x264,0x80010007)
        with self.assertRaises(InvalidPE):import_slots(PE(b))

    def test_duplicate_slots_rejected(self):
        b=imports_fixture();struct.pack_into('<I',b,0x98+108,60)
        b[0x214:0x228]=b[0x200:0x214]
        with self.assertRaises(InvalidPE):import_slots(PE(b))


if __name__=='__main__':
    unittest.main()
