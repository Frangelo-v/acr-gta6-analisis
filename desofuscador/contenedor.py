"""Saca el contenedor de la etapa 2 y lo parte en sus archivos (todavia cifrados).

    python contenedor.py etapa2.bin carpeta_salida

Hay dos variantes: en una el contenedor va como recurso del ensamblado; en la otra va en base64
partido en miles de textos dentro del codigo virtualizado. El formato es el mismo en las dos:
    magia (4)  cantidad (4)  y por cada archivo: largo nombre (2) nombre, posicion (4), tamano (4)
"""
import base64
import re
import struct
import sys
from pathlib import Path

import dnfile


def leer_tabla(d):
    n = struct.unpack_from("<I", d, 4)[0]
    if not 1 <= n <= 64:
        return None
    p, filas = 8, []
    try:
        for _ in range(n):
            largo = struct.unpack_from("<H", d, p)[0]
            nombre = d[p + 2:p + 2 + largo].decode("ascii")
            if not re.fullmatch(r"[\w.\-]{3,60}", nombre):
                return None
            p += 2 + largo
            pos, tam = struct.unpack_from("<II", d, p)
            p += 8
            filas.append((nombre, pos, tam))
    except (struct.error, UnicodeDecodeError):
        return None
    if any(pos + tam > len(d) for _, pos, tam in filas):
        return None
    return filas


def de_recursos(pe):
    for r in pe.net.resources or []:
        d = bytes(r.data)
        # delante puede venir una cabecera
        for salto in range(0, min(256, len(d) - 8)):
            t = leer_tabla(d[salto:])
            if t:
                return d[salto:], t


def de_textos(pe):
    """Junta los trozos de base64: [clave][3][4][largo][utf-16 xor clave]."""
    datos = bytes(pe.__data__)
    for r in pe.net.mdtables.FieldRva.rows:
        o = pe.get_offset_from_rva(r.Rva)
        d = datos[o:o + 6_000_000]
        if len(d) < 1000:
            continue
        trozos, p, fallos = [], 0, 0
        while p < len(d) - 14 and fallos < 60_000:
            largo = struct.unpack_from("<i", d, p + 8)[0]
            ini = p + 12
            if 4 <= largo <= len(d) - ini and largo % 2 == 0:
                k = d[p]
                alto = d[ini + 1:ini + largo:2]
                if alto == bytes([k]) * len(alto):
                    s = bytes(c ^ k for c in d[ini:ini + largo:2]).rstrip(b"\0")
                    if len(s) > 1 and all(32 <= c < 127 for c in s):
                        trozos.append(s)
                        p, fallos = ini + largo, 0
                        continue
            p += 1
            fallos += 1
        b64 = [s for s in trozos if len(s) > 30 and re.fullmatch(rb"[A-Za-z0-9+/=]+", s)]
        if sum(map(len, b64)) < 100_000:
            continue
        for i in range(len(b64)):
            cab = base64.b64decode(b64[i][: len(b64[i]) // 4 * 4] + b"")
            if len(cab) > 12 and 1 <= struct.unpack_from("<I", cab, 4)[0] <= 64:
                t = b"".join(b64[i:])
                d2 = base64.b64decode(t[: len(t) // 4 * 4])
                tabla = leer_tabla(d2)
                if tabla:
                    return d2, tabla


def main():
    pe = dnfile.dnPE(sys.argv[1])
    sal = Path(sys.argv[2])
    sal.mkdir(parents=True, exist_ok=True)
    r = de_recursos(pe) or de_textos(pe)
    if not r:
        sys.exit("no encontre el contenedor")
    d, tabla = r
    print("magia", d[:4][::-1].hex())
    for nombre, pos, tam in tabla:
        (sal / nombre).write_bytes(d[pos:pos + tam])
        print("%-34s %9d bytes" % (nombre, tam))


if __name__ == "__main__":
    main()
