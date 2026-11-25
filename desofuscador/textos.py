"""Lista los textos que el ofuscador mete en el codigo virtualizado de la etapa 2.

    python textos.py etapa2.bin [salida.json]

Cada texto va como [clave][3 bytes][4 bytes][largo][utf-16 xor clave] dentro de los campos con
datos iniciales (FieldRva). No hace falta correr nada.
"""
import json
import struct
import sys
from collections import defaultdict

import dnfile


def legible(s):
    if len(s) < 2:
        return False
    if not all(0x20 <= ord(c) < 0x2500 or c in "\r\n\t" for c in s):
        return False
    return sum(ord(c) < 256 for c in s) >= len(s) * 0.9


def bloques(pe):
    datos = bytes(pe.__data__)
    filas = sorted({(r.Rva, str(r.Field.row.Name)) for r in pe.net.mdtables.FieldRva.rows})
    for i, (rva, nombre) in enumerate(filas):
        ini = pe.get_offset_from_rva(rva)
        fin = pe.get_offset_from_rva(filas[i + 1][0]) if i + 1 < len(filas) else ini + 4000
        yield nombre, datos[ini:fin]


def textos(d):
    p = 0
    while p < len(d) - 14:
        for a in (8, 4):
            largo = struct.unpack_from("<i", d, p + a)[0]
            ini = p + 12
            if not (4 <= largo <= len(d) - ini and largo % 2 == 0):
                continue
            x = bytes(c ^ d[p] for c in d[ini:ini + largo])
            if x.endswith(b"\0\0"):
                x = x[:-2]
            try:
                s = x.decode("utf-16le")
            except UnicodeDecodeError:
                continue
            if legible(s):
                yield s
                p = ini + largo - 1
                break
        p += 1


def main():
    pe = dnfile.dnPE(sys.argv[1])
    g = defaultdict(list)
    for nombre, d in bloques(pe):
        for s in textos(d):
            g[nombre].append(s)
    if len(sys.argv) > 2:
        json.dump(g, open(sys.argv[2], "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(sum(map(len, g.values())), "textos en", len(g), "bloques")
    for nombre, v in g.items():
        print(nombre, len(v), [s[:70] for s in v[:4]])


if __name__ == "__main__":
    main()
