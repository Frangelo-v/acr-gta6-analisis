# dumps the strings embedded in the virtualized code of stage2
# layout: key(1) pad(3) ?(4) len(4) utf16^key

import argparse
import struct

import dnfile

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", required=True)
args = parser.parse_args()

pe = dnfile.dnPE(args.file)
raw = bytes(pe.__data__)
fields = sorted({(r.Rva, str(r.Field.row.Name)) for r in pe.net.mdtables.FieldRva.rows})


def is_text(s):
    if len(s) < 2 or not all(0x20 <= ord(c) < 0x2500 or c in "\r\n\t" for c in s):
        return False
    return sum(ord(c) < 256 for c in s) >= len(s) * 0.9


def dump(d):
    p = 0
    while p < len(d) - 14:
        for a in (8, 4):
            n = struct.unpack_from("<i", d, p + a)[0]
            if n < 4 or n % 2 or n > len(d) - p - 12:
                continue
            x = bytes(c ^ d[p] for c in d[p + 12 : p + 12 + n])
            if x[-2:] == b"\0\0":
                x = x[:-2]
            s = x.decode("utf-16le", "replace")
            if "�" not in s and is_text(s):
                yield s
                p += 11 + n
                break
        p += 1


for i, (rva, name) in enumerate(fields):
    off = pe.get_offset_from_rva(rva)
    end = pe.get_offset_from_rva(fields[i + 1][0]) if i + 1 < len(fields) else off + 4000
    for s in dump(raw[off:end]):
        print(name, repr(s))
