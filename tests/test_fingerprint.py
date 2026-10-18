import struct
import unittest
from tools.fingerprint import PE, InvalidPE


def fixture():
    """Invented PE32; contains no executable instructions or retail data."""
    b = bytearray(0x400)
    b[:2] = b'MZ'
    struct.pack_into('<I', b, 0x3c, 0x80)
    b[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HH', b, 0x84, 0x14c, 1)
    struct.pack_into('<H', b, 0x94, 224)
    o = 0x98
    struct.pack_into('<H', b, o, 0x10b)
    b[o+2] = 8
    struct.pack_into('<I', b, o+16, 0x1000)
    struct.pack_into('<I', b, o+28, 0x400000)
    struct.pack_into('<I', b, o+56, 0x2000)
    struct.pack_into('<I', b, o+60, 0x200)
    struct.pack_into('<I', b, o+92, 16)
    s = o + 224
    b[s:s+8] = b'.test\0\0\0'
    struct.pack_into('<IIII', b, s+8, 0x300, 0x1000, 0x200, 0x200)
    return b


class FingerprintTests(unittest.TestCase):
    def test_basic(self):
        p = PE(fixture())
        self.assertEqual(p.report()['pointer_bits'], 32)
        self.assertEqual(p.offset(0x1000), 0x200)
        self.assertEqual(p.report()['fixed_versions'], [])

    def test_all_header_truncations(self):
        b = fixture()
        for size in range(0x200):
            with self.subTest(size=size), self.assertRaises(InvalidPE):
                PE(b[:size])

    def test_virtual_tail_and_crossing(self):
        p = PE(fixture())
        for rva, length in [(0x1200,1),(0x11ff,2),(0xffffffff,2),(-1,1),(0x1000,0)]:
            with self.subTest(rva=rva), self.assertRaises(InvalidPE):
                p.offset(rva,length)

    def test_not_x86(self):
        b = fixture()
        struct.pack_into('<H', b, 0x84, 0x8664)
        with self.assertRaises(InvalidPE): PE(b)

    def test_bad_directory_count(self):
        b = fixture()
        struct.pack_into('<I', b, 0x98+92, 17)
        with self.assertRaises(InvalidPE): PE(b)

    def test_ambiguous_mapping(self):
        p = PE(fixture())
        p.sections.append(dict(p.sections[0]))
        with self.assertRaises(InvalidPE): p.offset(0x1000)

    def test_import_and_terminator(self):
        b = fixture()
        struct.pack_into('<II', b, 0x98+104, 0x1000, 40)
        struct.pack_into('<IIIII', b, 0x200, 0,0,0,0x1080,0)
        b[0x280:0x28b] = b'example.dll'
        self.assertEqual(PE(b).imports(), ['example.dll'])
        struct.pack_into('<I', b, 0x98+108, 20)
        with self.assertRaises(InvalidPE): PE(b).imports()

    def test_unterminated_name(self):
        b = fixture()
        b[0x200:0x400] = b'x' * 0x200
        with self.assertRaises(InvalidPE): PE(b).cstring(0x1000)

    def test_version_resource(self):
        b = fixture()
        struct.pack_into('<II', b, 0x98+112, 0x1000, 0x100)
        # Three directories: type, name, language; then a data entry.
        for off, key, child in [(0x200,16,0x80000020),(0x220,1,0x80000040),(0x240,1033,0x60)]:
            struct.pack_into('<H', b, off+14, 1)
            struct.pack_into('<II', b, off+16, key, child)
        struct.pack_into('<II', b, 0x260, 0x1100, 92)
        struct.pack_into('<HHH', b, 0x300, 92,52,0)
        key = 'VS_VERSION_INFO\0'.encode('utf-16le')
        b[0x306:0x306+len(key)] = key
        struct.pack_into('<13I', b, 0x328, 0xfeef04bd,0x10000,0x10002,0x30004,0x50006,0x70008,*([0]*7))
        self.assertEqual(PE(b).versions()[0]['file_version'], '1.2.3.4')
        struct.pack_into('<H', b, 0x302, 100)
        with self.assertRaises(InvalidPE): PE(b).versions()


if __name__ == '__main__':
    unittest.main()
