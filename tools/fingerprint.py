#!/usr/bin/env python3
"""Read-only PE32 identity audit. Outputs metadata, never code or strings dumps.

Format reference: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
This is deliberately limited to i386 PE32; it is not a general executable loader.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path


class InvalidPE(ValueError):
    pass


class PE:
    def __init__(self, data):
        self.data = data
        self.sections = []
        if self.take(0, 2) != b'MZ':
            raise InvalidPE('missing DOS signature')
        self.pe = self.u32(0x3c)
        if self.take(self.pe, 4) != b'PE\0\0':
            raise InvalidPE('missing PE signature')
        c = self.pe + 4
        self.machine, count = self.unpack('<HH', c)
        size = self.u16(c + 16)
        self.opt = c + 20
        self.take(self.opt, size)
        if self.machine != 0x14c or size < 96 or self.u16(self.opt) != 0x10b:
            raise InvalidPE('only i386 PE32 supported')
        if not 1 <= count <= 96:
            raise InvalidPE('invalid section count')
        self.header_size = self.u32(self.opt + 60)
        if self.header_size > len(data):
            raise InvalidPE('headers exceed file')
        self.directory_count = self.u32(self.opt + 92)
        if self.directory_count > (size - 96) // 8:
            raise InvalidPE('directories exceed optional header')
        for i in range(count):
            off = self.opt + size + i * 40
            name = self.take(off, 8).rstrip(b'\0').decode('ascii', errors='replace')
            vs, rva, raw_size, raw = self.unpack('<IIII', off + 8)
            flags = self.u32(off + 36)
            if raw_size:
                self.take(raw, raw_size)
            self.sections.append(dict(name=name, rva=rva, virtual_size=vs,
                                      raw_size=raw_size, raw_offset=raw, flags=flags))

    def take(self, offset, size):
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise InvalidPE('file range out of bounds')
        return self.data[offset:offset + size]

    def unpack(self, fmt, offset):
        return struct.unpack(fmt, self.take(offset, struct.calcsize(fmt)))

    def u16(self, offset):
        return self.unpack('<H', offset)[0]

    def u32(self, offset):
        return self.unpack('<I', offset)[0]

    def offset(self, rva, size=1):
        if rva < 0 or size < 1 or rva + size > 0x100000000:
            raise InvalidPE('invalid RVA range')
        candidates = []
        if rva + size <= self.header_size:
            candidates.append(rva)
        for s in self.sections:
            delta = rva - s['rva']
            if delta >= 0 and delta + size <= s['raw_size']:
                candidates.append(s['raw_offset'] + delta)
        if len(candidates) != 1:
            raise InvalidPE('RVA unmapped, virtual-only, crossing, or ambiguous')
        self.take(candidates[0], size)
        return candidates[0]

    def directory(self, index):
        if index >= self.directory_count:
            return 0, 0
        return self.unpack('<II', self.opt + 96 + index * 8)

    def cstring(self, rva, limit=260):
        out = bytearray()
        for i in range(limit):
            b = self.data[self.offset(rva + i)]
            if not b:
                return out.decode('ascii')
            out.append(b)
        raise InvalidPE('unterminated metadata string')

    def imports(self):
        rva, size = self.directory(1)
        if not rva:
            return []
        names = []
        for n in range(min(size // 20, 4096)):
            off = self.offset(rva + n * 20, 20)
            fields = self.unpack('<IIIII', off)
            if not any(fields):
                return sorted(set(names), key=str.lower)
            names.append(self.cstring(fields[3]))
        raise InvalidPE('import descriptor terminator missing')

    def versions(self):
        rva, size = self.directory(2)
        if not rva:
            return []

        def resource(rel, length):
            if rel < 0 or rel + length > size:
                raise InvalidPE('resource range out of bounds')
            return self.offset(rva + rel, length)

        def entries(rel):
            off = resource(rel, 16)
            named, ids = self.unpack('<HH', off + 12)
            if named + ids > 4096:
                raise InvalidPE('resource directory too large')
            resource(rel + 16, (named + ids) * 8) if named + ids else None
            return [self.unpack('<II', off + 16 + i * 8) for i in range(named + ids)]

        result = []
        for kind, child in entries(0):
            if kind != 16 or not child & 0x80000000:
                continue
            for _, name_child in entries(child & 0x7fffffff):
                if not name_child & 0x80000000:
                    raise InvalidPE('version name is not a directory')
                for language, leaf in entries(name_child & 0x7fffffff):
                    if leaf & 0x80000000:
                        raise InvalidPE('version language is not a leaf')
                    off = resource(leaf, 16)
                    value_rva, length = self.unpack('<II', off)
                    value = self.take(self.offset(value_rva, length), length)
                    if len(value) < 6:
                        raise InvalidPE('short version resource')
                    total, value_len, typ = struct.unpack_from('<HHH', value)
                    key = 'VS_VERSION_INFO\0'.encode('utf-16le')
                    fixed = (6 + len(key) + 3) & ~3
                    if total > len(value) or value[6:6+len(key)] != key:
                        raise InvalidPE('invalid version key or length')
                    if typ != 0 or value_len < 52 or fixed + value_len > total:
                        raise InvalidPE('invalid fixed version info length')
                    fields = struct.unpack_from('<13I', value, fixed)
                    if fields[0] != 0xfeef04bd:
                        raise InvalidPE('invalid fixed version signature')
                    def dotted(a, b):
                        return '.'.join(map(str, (a >> 16, a & 65535, b >> 16, b & 65535)))
                    result.append(dict(language_id=language,
                                       file_version=dotted(fields[2], fields[3]),
                                       product_version=dotted(fields[4], fields[5])))
        return result

    def report(self):
        o = self.opt
        entry = self.u32(o + 16)
        return dict(schema_version=1, sha256=hashlib.sha256(self.data).hexdigest(),
                    size_bytes=len(self.data), machine='IMAGE_FILE_MACHINE_I386',
                    pe_format='PE32', endian='little', pointer_bits=32,
                    image_base=hex(self.u32(o + 28)), entry_rva=hex(entry),
                    entry_file_offset=self.offset(entry),
                    linker_version=f'{self.data[o+2]}.{self.data[o+3]}',
                    coff_timestamp=self.u32(self.pe + 8),
                    image_size=self.u32(o + 56), sections=self.sections,
                    import_dlls=self.imports(), fixed_versions=self.versions(),
                    debug_directory_size=self.directory(6)[1])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('executable', type=Path)
    p.add_argument('--output', type=Path, required=True,
                   help='private JSON output; review metadata before publication')
    args = p.parse_args()
    if args.output.resolve() == args.executable.resolve():
        p.error('output must not overwrite the input')
    try:
        report = PE(args.executable.read_bytes()).report()
        with args.output.open('x') as f:
            json.dump(report, f, indent=2)
            f.write('\n')
    except (OSError, ValueError) as e:
        p.exit(2, f'audit failed: {e}\n')


if __name__ == '__main__':
    main()
