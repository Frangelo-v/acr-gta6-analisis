# emulates stage3 to get the names and rc4 keys of the final payloads
# output: file1|key1|file2|key2

import argparse
import struct

import bcl_stubs
import cil_emu
from cil_emu import Arr, Obj

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", required=True)
args = parser.parse_args()

E = cil_emu.monta(cil_emu.Emu(args.file))
bcl_stubs.monta(E)
E.tolera = True

AES = "System.Security.Cryptography.SymmetricAlgorithm::set_"
E.BCL["System.Security.Cryptography.CryptoConfig::CreateFromName"] = (
    lambda e, a: "SHA256" if "256" in a[0] and "SHA" in a[0].upper() else cil_emu.Aes_()
)
for p in ("Mode", "Padding", "KeySize"):
    E.BCL[AES + p] = lambda e, a: None


class Writer:
    def __init__(self, st):
        self.st = st
        self.n = 0


def write(e, a):
    w, v = a[0], a[1]
    w.n += 1
    if w.n == 3:
        w.st.d += bytes([v & 255])
    elif isinstance(v, Arr):
        w.st.d += bytes(v.b)
    else:
        w.st.d += struct.pack("<i", v)


E.BCL["System.IO.BinaryWriter::.ctor"] = lambda e, a: Writer(a[0])
E.BCL["System.IO.BinaryWriter::Write"] = write
E.BCL["System.IO.BinaryWriter::Flush"] = lambda e, a: None
E.BCL["System.IO.Stream::Dispose"] = lambda e, a: None


def sig(rid):
    return E.msig(E.blob(E.MT[rid - 1].Signature))[0]


def method_name(rid):
    return E.tipos[E.due[rid]] + "::" + str(E.MT[rid - 1].Name)


# config class: 1 bool, 1 int, 3 strings
fields = {}
for i in range(len(E.FT)):
    fields.setdefault(E.tipos[E.fdue.get(i + 1, 1)], []).append((i + 1, E.ftipo(i + 1)))
wanted = sorted(["System.Boolean", "System.Int32"] + ["System.String"] * 3)
classes = [c for c, v in fields.items() if sorted(t for _, t in v if t != "System.IntPtr[]") == wanted]

methods = [i + 1 for i in range(len(E.MT)) if E.MT[i].Rva and not sig(i + 1)[0] and not sig(i + 1)[2]]

for c in classes:
    for flag in (0, 1):
        cfg = Obj(c)
        dummy = ["CCC", "BBB", "AAA"]
        for rid, t in fields[c]:
            if t == "System.Boolean":
                cfg.f[rid] = flag
            elif t == "System.Int32":
                cfg.f[rid] = 7
            elif t == "System.String":
                cfg.f[rid] = dummy.pop()
        for m in methods:
            if sig(m)[1] == c:
                E.sobre[method_name(m)] = lambda e, a, cfg=cfg: cfg
        for m in methods:
            if sig(m)[1] != "System.String" or len(E.cuerpo(m)[0]) < 100:
                continue
            try:
                r = E.corre(m, [])
            except Exception:
                continue
            if isinstance(r, str) and r.count("|") >= 3:
                print(r)
                raise SystemExit
print("not found")
