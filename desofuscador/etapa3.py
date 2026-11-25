"""Descifra un archivo del contenedor: RC4 y, si corresponde, LZMA.

    python etapa3.py archivo.js LLAVE salida.bin

Las llaves salen de emular la etapa 2 o 3 (ver cil.py). Las de estas muestras estan en el README.
"""
import hashlib
import lzma
import sys

from Crypto.Cipher import ARC4

x = ARC4.new(sys.argv[2].encode()).decrypt(open(sys.argv[1], "rb").read())
if x[:1] == b"]":
    x = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(x)
open(sys.argv[3], "wb").write(x)
print(len(x), "bytes ", x[:2], " sha256", hashlib.sha256(x).hexdigest())
