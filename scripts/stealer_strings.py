# decrypts the stealer strings calling its own functions in the emulator (hardcoded addresses, 4.6.7-alpha1)
import sys, os, struct, io, contextlib

AQUI = os.environ.get("OUT", ".")
os.environ["VER"] = "0"
from stealer_hooks import *

with contextlib.redirect_stdout(io.StringIO()):
    llama(BASE + pe.OPTIONAL_HEADER.AddressOfEntryPoint, BASE, 1, 0)
    ar, _ = ustr("C:\\Users\\u\\AppData")
    llama(BASE + 0x1090, ar)


def getter(ini):
    esp = 0x001E0000
    w32(esp, FIN)
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, 0x001E8000)
    try:
        uc.emu_start(ini, FIN, 0, int(os.environ.get("CT", "5000000")))
    except (UcError, OSError) as e:
        print("UC", e, hex(uc.reg_read(UC_X86_REG_EIP)))
    return uc.reg_read(UC_X86_REG_EAX)


import re, collections
from capstone import *

T0 = 0x20F71000
t = bytes(uc.mem_read(T0, 0x6EF94))
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.skipdata = True
L = list(md.disasm(t, T0))
R = []
for i, q in enumerate(L):
    if q.mnemonic != "call" or not q.op_str.startswith("0x"):
        continue
    prev = L[max(0, i - 11) : i]
    # corta en el ultimo salto o llamada que consuma la pila
    src = None
    modo = None
    for p in prev:
        m = re.fullmatch(r"edx, (0x20f[ef][0-9a-f]{4}|0x20fe[0-9a-f]{4}|0x20ff[0-9a-f]{4})", p.op_str)
        if p.mnemonic == "mov" and m:
            src = int(m.group(1), 16)
            modo = "A"
        if p.mnemonic == "push" and re.fullmatch(r"0x20f[ef][0-9a-f]{4}", p.op_str):
            src = int(p.op_str, 16)
            modo = "B"
    if not src:
        continue
    ps = [p for p in prev if p.mnemonic == "push"]
    key = None
    for k, p in enumerate(ps):
        if (
            re.fullmatch(r"0x[0-9a-f]{7,8}", p.op_str)
            and int(p.op_str, 16) != src
            and not 0x20F70000 <= int(p.op_str, 16) < 0x21048000
        ):
            key = k
    if key is None or key == 0:
        continue
    num = lambda p: int(p.op_str, 0) if re.fullmatch(r"0x[0-9a-f]+|\d+", p.op_str) else None
    ln = num(ps[key - 1])
    wd = num(ps[key + 1]) if key + 1 < len(ps) else None
    R.append((q.address, int(q.op_str, 16), modo, src, int(ps[key].op_str, 16), ln, wd))
print("sitios", len(R), flush=True)
o = open(AQUI + "/stealer_strings.txt", "w", encoding="utf-8")
ok = 0
B0 = aloc(8192)
HB = hp[0]
for site, fn, modo, src, key, ln, wd in R:
    hp[0] = HB
    uc.mem_write(B0, b"\0" * 4096)
    esp = 0x001E0000
    n = ln or 200
    w = wd or 50
    st = [FIN, w, key, n] if modo == "A" else [FIN, B0, src, w, key, n]
    for k, v in enumerate(st):
        w32(esp + 4 * k, v)
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, 0x001E8000)
    for r_, v in (
        (UC_X86_REG_ECX, B0),
        (UC_X86_REG_EDX, src),
        (UC_X86_REG_ESI, B0),
        (UC_X86_REG_EBX, B0),
        (UC_X86_REG_EDI, B0),
    ):
        uc.reg_write(r_, v)
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            uc.emu_start(fn, FIN, 0, 200000)
    except Exception:
        pass
    d = bytes(uc.mem_read(B0, 1024))
    s = d.split(b"\0")[0]
    if len(s) == 1 and d[1] == 0 and d[2]:
        s = d[::2].split(b"\0")[0]
    tx = s.decode("latin1")
    ok += bool(tx)
    o.write("%x %s %s %r\n" % (site, ln, wd, tx))
o.close()
print("con texto", ok)
