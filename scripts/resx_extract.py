# extracts the .NET payload hidden in Resources.resx
# key = the .csproj itself, xor-folded to 32 bytes -> RC4 -> 4 bytes checksum + PE

import argparse
import glob
import hashlib
import os
import re

from Crypto.Cipher import ARC4

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--dir", help="folder with the csproj and the resx", required=True)
parser.add_argument("-o", "--out", default="stage2.bin")
args = parser.parse_args()


def xor_fold(data):
    key = bytearray(32)
    for i in range(32):
        x = 0
        for c in data[i::32]:
            x ^= c
        key[i] = x
    return bytes(key)


def get_chunks(resx):
    # Note0xw4, Note0xw5 ... -> {"Note0xw": {4: ..., 5: ...}}
    groups = {}
    for name, num, value in re.findall(rb'name="([A-Za-z0-9_]*?)(\d+)"[^>]*>\s*<value>([^<]*)</value>', resx):
        # junk letter after every byte: 6egb9gc6g...
        value = re.sub(rb"[^0-9a-fA-F]", b"", value)
        if len(value) > 100:
            groups.setdefault(name, {})[int(num)] = value
    return [[g[k] for k in sorted(g)] for g in groups.values() if len(g) > 20]


def decrypt(chunks, key):
    for start in range(min(12, len(chunks))):
        test = ARC4.new(key).decrypt(bytes.fromhex(chunks[start][:100].decode()))
        if test[4:6] != b"MZ":
            continue
        for end in range(len(chunks), start, -1):
            h = b"".join(chunks[start:end]).decode()
            data = ARC4.new(key).decrypt(bytes.fromhex(h[: len(h) // 2 * 2]))
            if data[:4] == xor_fold(data[4:])[:4]:
                return data[4:]


resx = open(glob.glob(os.path.join(args.dir, "*.resx"))[0], "rb").read()
groups = get_chunks(resx)

for f in glob.glob(os.path.join(args.dir, "*")):
    if f.endswith(".resx") or not os.path.isfile(f):
        continue
    key = xor_fold(open(f, "rb").read())
    for chunks in groups:
        payload = decrypt(chunks, key)
        if payload:
            print("[+] key file:", os.path.basename(f))
            print("[+] rc4 key:", key.hex())
            print("[+] sha256:", hashlib.sha256(payload).hexdigest())
            open(args.out, "wb").write(payload)
            raise SystemExit

print("[-] nothing found")
