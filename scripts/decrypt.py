import argparse
import hashlib
import lzma

from Crypto.Cipher import ARC4

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", required=True)
parser.add_argument("-k", "--key", help="rc4 key", required=True)
parser.add_argument("-o", "--out", required=True)
args = parser.parse_args()

data = ARC4.new(args.key.encode()).decrypt(open(args.file, "rb").read())
if data[:1] == b"\x5d":  # lzma alone
    data = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(data)

open(args.out, "wb").write(data)
print(data[:2], len(data), hashlib.sha256(data).hexdigest())
