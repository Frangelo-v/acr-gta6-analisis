# splits the container of stage2 (the files are still encrypted, use decrypt.py)
# magic(4) count(4) [ namelen(2) name offset(4) size(4) ] * count

import argparse
import base64
import os
import re
import struct

import dnfile

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", required=True)
parser.add_argument("-o", "--out", default="out")
args = parser.parse_args()

pe = dnfile.dnPE(args.file)
raw = bytes(pe.__data__)


def parse(d):
    if len(d) < 12:
        return None
    count = struct.unpack_from("<I", d, 4)[0]
    if count < 1 or count > 64:
        return None
    p = 8
    files = []
    for _ in range(count):
        try:
            n = struct.unpack_from("<H", d, p)[0]
            name = d[p + 2 : p + 2 + n].decode("ascii")
            off, size = struct.unpack_from("<II", d, p + 2 + n)
        except (struct.error, UnicodeDecodeError):
            return None
        if not re.fullmatch(r"[\w.-]{3,60}", name) or off + size > len(d):
            return None
        files.append((name, off, size))
        p += 10 + n
    return files


def from_resource():
    for r in pe.net.resources or []:
        d = bytes(r.data)
        for skip in range(256):
            if parse(d[skip:]):
                return d[skip:]


def from_strings():
    # base64 in thousands of small strings, same layout as dotnet_strings.py
    for r in pe.net.mdtables.FieldRva.rows:
        off = pe.get_offset_from_rva(r.Rva)
        d = raw[off : off + 6000000]
        parts = []
        p = miss = 0
        while p < len(d) - 14 and miss < 60000:
            n = struct.unpack_from("<i", d, p + 8)[0]
            if 4 <= n <= len(d) - p - 12 and n % 2 == 0:
                x = d[p + 12 : p + 12 + n]
                if x[1::2] == bytes([d[p]]) * (n // 2):
                    s = bytes(c ^ d[p] for c in x[0::2]).rstrip(b"\0")
                    if len(s) > 1 and re.fullmatch(rb"[ -~]+", s):
                        parts.append(s)
                        p += 12 + n
                        miss = 0
                        continue
            p += 1
            miss += 1
        parts = [s for s in parts if len(s) > 30 and re.fullmatch(rb"[A-Za-z0-9+/=]+", s)]
        if sum(len(s) for s in parts) < 100000:
            continue
        for i, s in enumerate(parts):
            head = base64.b64decode(s[: len(s) // 4 * 4])
            if len(head) < 12 or not 1 <= struct.unpack_from("<I", head, 4)[0] <= 64:
                continue
            b = b"".join(parts[i:])
            b = base64.b64decode(b[: len(b) // 4 * 4])
            if parse(b):
                return b


data = from_resource() or from_strings()
if not data:
    raise SystemExit("container not found")

os.makedirs(args.out, exist_ok=True)
for name, off, size in parse(data):
    open(os.path.join(args.out, name), "wb").write(data[off : off + size])
    print(name, size)
