"""Saca la segunda etapa (.NET) escondida en el Resources.resx del proyecto de MSBuild.

    python etapa2.py CARPETA salida.bin

El .resx trae miles de valores en hexadecimal repartidos en claves numeradas (Note0xw4, Note0xw5...).
Van en RC4 y la llave es el propio .csproj doblado a 32 bytes con XOR. Los primeros 4 bytes del
resultado son una suma de control, despues viene el PE.
"""
import hashlib
import re
import sys
from collections import defaultdict
from pathlib import Path

from Crypto.Cipher import ARC4


def doblar(datos, n=32):
    k = bytearray(n)
    for i in range(n):
        x = 0
        for c in datos[i::n]:
            x ^= c
        k[i] = x
    return bytes(k)


def grupos(resx):
    """Valores del resx por prefijo de clave, en orden numerico."""
    g = defaultdict(dict)
    for m in re.finditer(rb'name="([A-Za-z0-9_]*?)(\d+)"[^>]*>\s*<value>([^<]*)</value>', resx):
        g[m.group(1)][int(m.group(2))] = m.group(3)
    return {p: [v[k] for k in sorted(v)] for p, v in g.items() if len(v) > 20}


def probar(trozos, llave):
    # cada byte viene separado por una letra de relleno (una "g", por ejemplo)
    limpio = [re.sub(rb"[^0-9a-fA-F]", b"", t) for t in trozos]
    hexa = [len(c) > 0.6 * len(t) > 100 for c, t in zip(limpio, trozos)]
    trozos = limpio
    for ini in range(min(12, len(trozos))):
        if not hexa[ini]:
            continue
        cab = trozos[ini][:256]
        cab = bytes.fromhex(cab[: len(cab) // 2 * 2].decode())
        if ARC4.new(llave).decrypt(cab)[4:6] != b"MZ":
            continue
        # la cola puede traer relleno: se recorta hasta que cuadre la suma
        for fin in range(len(trozos), ini, -1):
            if not all(hexa[ini:fin]):
                continue
            h = b"".join(trozos[ini:fin])
            p = ARC4.new(llave).decrypt(bytes.fromhex(h[: len(h) // 2 * 2].decode()))
            if p[:4] == doblar(p[4:])[:4]:
                return p[4:]
    return None


def main():
    carpeta, salida = Path(sys.argv[1]), Path(sys.argv[2])
    resx = next(carpeta.glob("*.resx")).read_bytes()
    for archivo in sorted(carpeta.iterdir()):
        if archivo.suffix == ".resx" or not archivo.is_file():
            continue
        llave = doblar(archivo.read_bytes())
        for prefijo, trozos in grupos(resx).items():
            pe = probar(trozos, llave)
            if pe:
                salida.write_bytes(pe)
                print("llave:", archivo.name, llave.hex())
                print("claves:", prefijo.decode() + "*")
                print(len(pe), "bytes  sha256", hashlib.sha256(pe).hexdigest())
                return
    sys.exit("nada: ninguna combinacion de archivo y clave dio un PE")


if __name__ == "__main__":
    main()
