"""Saca las llaves RC4 de la etapa 3 emulando el metodo que las devuelve.

    python llaves.py etapa3.bin

Busca una clase con un bool, un int y tres textos (la configuracion que le pasa la etapa 2), le pone
valores de mentira y corre los metodos estaticos sin argumentos que devuelven texto. El resultado es
"archivo1|llave1|archivo2|llave2".
"""
import sys
from collections import defaultdict

import bcl
import cil
from cil import Arr, Falta, NetEx, Obj

E = cil.monta(cil.Emu(sys.argv[1]))
bcl.monta(E)
E.tolera = True
B = E.BCL
B["System.Security.Cryptography.CryptoConfig::CreateFromName"] = \
    lambda e, a: "SHA256" if "256" in a[0] and "SHA" in a[0].upper() else cil.Aes_()
for p in ("Mode", "Padding", "KeySize"):
    B["System.Security.Cryptography.SymmetricAlgorithm::set_" + p] = lambda e, a: None


class Escritor:
    def __init__(self, st):
        self.st = st
        self.n = 0


def escribir(e, a):
    import struct
    a[0].n += 1
    v = a[1]
    if a[0].n == 3:
        a[0].st.d += bytes([v & 255])
    else:
        a[0].st.d += bytes(v.b) if isinstance(v, Arr) else struct.pack("<i", v)


B["System.IO.BinaryWriter::.ctor"] = lambda e, a: Escritor(a[0])
B["System.IO.BinaryWriter::Write"] = escribir
B["System.IO.BinaryWriter::Flush"] = B["System.IO.Stream::Dispose"] = lambda e, a: None

campos = defaultdict(list)
for i, f in enumerate(E.FT):
    campos[E.tipos[E.fdue.get(i + 1, 1)]].append((i + 1, E.ftipo(i + 1)))
PEDIDO = sorted(["System.Boolean", "System.Int32"] + ["System.String"] * 3)
clases = [t for t, v in campos.items() if sorted(x for _, x in v if x != "System.IntPtr[]") == PEDIDO]


def firma(rid):
    return E.msig(E.blob(E.MT[rid - 1].Signature))[0]


for clase in clases:
    for ok in (0, 1):
        o = Obj(clase)
        textos = iter(("AAA", "BBB", "CCC"))
        o.f = {}
        for rid, tipo in campos[clase]:
            if tipo == "System.Boolean":
                o.f[rid] = ok
            elif tipo == "System.Int32":
                o.f[rid] = 7
            elif tipo == "System.String":
                o.f[rid] = next(textos)
        for i, m in enumerate(E.MT):
            sg = firma(i + 1)
            if sg[1] == clase and not sg[2] and not sg[0] and m.Rva:
                E.sobre[E.tipos[E.due[i + 1]] + "::" + str(m.Name)] = lambda e, a, o=o: o
        for i, m in enumerate(E.MT):
            sg = firma(i + 1)
            if sg[1] != "System.String" or sg[2] or sg[0] or not m.Rva or len(E.cuerpo(i + 1)[0]) < 100:
                continue
            try:
                r = E.corre(i + 1, [])
            except (Falta, NetEx, RecursionError):
                continue
            except Exception as e:
                continue
            if isinstance(r, str) and r.count("|") >= 3:
                print(clase, m.Name)
                print(r)
                sys.exit()
sys.exit("no salio ninguna llave")
