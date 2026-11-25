# small CIL interpreter. the assembly is never loaded, BCL calls have to be stubbed (bcl_stubs.py)
import struct, bisect, hashlib, dnfile, sys
from dncil.cil.body import CilMethodBody
from dncil.cil.body.reader import CilMethodBodyReaderBase
from dncil.clr.token import Token, StringToken, InvalidToken

sys.setrecursionlimit(20000)


class Rd(CilMethodBodyReaderBase):
    def __init__(s, b, off):
        s.b = b
        s.o = off

    def read(s, n):
        d = s.b[s.o : s.o + n]
        s.o += n
        return bytes(d)

    def tell(s):
        return s.o

    def seek(s, o):
        s.o = o
        return o


class L(int):
    pass  # int64


class N(int):
    pass  # nativo (32 bits)


class NetEx(Exception):
    def __init__(s, o):
        s.o = o
        super().__init__(str(o))


class Falta(Exception):
    pass


class Obj:
    __slots__ = ("t", "f")

    def __init__(s, t):
        s.t = t
        s.f = {}

    def __repr__(s):
        return f"<{s.t}>"


class Ref:
    __slots__ = ("get", "set")

    def __init__(s, g, st):
        s.get = g
        s.set = st


class Fn:
    __slots__ = ("m", "o")

    def __init__(s, m, o=None):
        s.m = m
        s.o = o


class Deleg:
    __slots__ = ("o", "fn")

    def __init__(s, o, fn):
        s.o = o
        s.fn = fn


class Tipo:
    __slots__ = ("n",)

    def __init__(s, n):
        s.n = n

    def __repr__(s):
        return "T:" + str(s.n)


def i32(v):
    v &= 0xFFFFFFFF
    return v - (1 << 32) if v & 0x80000000 else v


def i64(v):
    v &= (1 << 64) - 1
    return L(v - (1 << 64) if v >> 63 else v)


def ni(v):
    return N(i32(v))


class Mem:
    def __init__(s):
        s.bases = []
        s.bufs = []
        s.sig = 0x10000
        s.de = {}

    def base(s, buf):
        k = id(buf)
        if k in s.de:
            return s.de[k]
        b = s.sig
        s.sig += (len(buf) + 0x2F) & ~0xF
        s.bases.append(b)
        s.bufs.append(buf)
        s.de[k] = b
        return b

    def loc(s, a):
        a &= 0xFFFFFFFF
        i = bisect.bisect_right(s.bases, a) - 1
        if i < 0:
            raise Falta("puntero %x" % a)
        return s.bufs[i], a - s.bases[i]


MEM = Mem()
FMT = {
    "I1": "b",
    "U1": "B",
    "I2": "h",
    "U2": "H",
    "I4": "i",
    "U4": "I",
    "I8": "q",
    "U8": "Q",
    "R4": "f",
    "R8": "d",
    "C": "H",
    "B": "B",
    "I": "i",
}
TAM = {k: struct.calcsize(v) for k, v in FMT.items()}
PRIM = {
    "System.Byte": "U1",
    "System.SByte": "I1",
    "System.Int16": "I2",
    "System.UInt16": "U2",
    "System.Int32": "I4",
    "System.UInt32": "U4",
    "System.Int64": "I8",
    "System.UInt64": "U8",
    "System.Boolean": "B",
    "System.Char": "C",
    "System.Single": "R4",
    "System.Double": "R8",
}


class Arr:
    __slots__ = ("e", "b", "l", "t")

    def __init__(s, e, n=0, data=None, t=None):
        s.e = e
        s.t = t
        s.l = None
        s.b = None
        if e:
            s.b = bytearray(data) if data is not None else bytearray(TAM[e] * n)
        else:
            s.l = list(data) if data is not None else [None] * n

    def __len__(s):
        return len(s.l) if s.b is None else len(s.b) // TAM[s.e]

    def ck(s, i):
        if i < 0 or i >= len(s):
            raise NetEx(Obj("System.IndexOutOfRangeException"))

    def get(s, i):
        s.ck(i)
        if s.b is None:
            return s.l[i]
        return num(struct.unpack_from("<" + FMT[s.e], s.b, i * TAM[s.e])[0], s.e)

    def put(s, i, v):
        s.ck(i)
        if s.b is None:
            s.l[i] = v
        else:
            struct.pack_into("<" + FMT[s.e], s.b, i * TAM[s.e], recorta(v, s.e))

    def __repr__(s):
        return f"<arr {s.e} {len(s)}>"


def num(v, e):
    if e in ("I8", "U8"):
        return i64(v)
    if e == "U4":
        return i32(v)
    if e == "I":
        return N(v)
    return v


def recorta(v, e):
    if e in ("R4", "R8"):
        return float(v)
    if isinstance(v, bool):
        v = int(v)
    if v is None:
        v = 0
    if isinstance(v, Fn):
        v = asa(v)
    if not isinstance(v, int):
        raise Falta("guardar %r en memoria" % (v,))
    m = TAM[e] * 8
    v = int(v) & ((1 << m) - 1)
    return v - (1 << m) if FMT[e].islower() and v >> (m - 1) else v


def barr(b):
    return Arr("U1", data=b)


def nombre(r):
    ns = str(getattr(r, "TypeNamespace", "") or "")
    n = str(getattr(r, "TypeName", "") or "")
    return (ns + "." if ns else "") + n


ASAS = {}
ASAI = {}


def asa(f):
    k = f.m[1]
    if k not in ASAI:
        ASAI[k] = 0x70000000 + len(ASAI) * 16
        ASAS[ASAI[k]] = f
    return ASAI[k]


def fn(v):
    return ASAS[int(v)] if isinstance(v, int) and int(v) in ASAS else v


class Emu:
    def __init__(s, ruta):
        s.pe = dnfile.dnPE(ruta)
        s.b = bytes(s.pe.__data__)
        s.md = s.pe.net.mdtables
        s.MT = s.md.MethodDef.rows
        s.FT = s.md.Field.rows
        s.due = {}
        s.fdue = {}
        s.cct = {}
        s.tipos = {}
        for ti, t in enumerate(s.md.TypeDef.rows):
            nm = nombre(t)
            s.tipos[ti + 1] = nm
            for m in t.MethodList:
                s.due[m.row_index] = ti + 1
                if str(m.row.Name) == ".cctor":
                    s.cct[ti + 1] = m.row_index
            for f in t.FieldList:
                s.fdue[f.row_index] = ti + 1
        s.rva = {r.Field.row_index: r.Rva for r in s.md.FieldRva.rows} if s.md.FieldRva else {}
        s.lay = {}
        if s.md.ClassLayout:
            for r in s.md.ClassLayout.rows:
                s.lay[r.Parent.row_index] = r.ClassSize
        s.est = {}
        s.hechos = set()
        s.cache = {}
        s.rvab = {}
        s.BCL = {}
        s.pasos = 0
        s.traza = None
        s.firmas = {}
        s.maxpasos = 10**9
        s.porn = {}
        for i, m in enumerate(s.MT):
            s.porn.setdefault(s.tipos[s.due.get(i + 1, 1)] + "::" + str(m.Name), []).append(i + 1)
        s.sobre = {}

    # --- firmas
    def comp(s, b, o):
        x = b[o]
        if x < 0x80:
            return x, o + 1
        if x < 0xC0:
            return ((x & 0x3F) << 8) | b[o + 1], o + 2
        return ((x & 0x1F) << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3], o + 4

    EL = {
        1: "System.Void",
        2: "System.Boolean",
        3: "System.Char",
        4: "System.SByte",
        5: "System.Byte",
        6: "System.Int16",
        7: "System.UInt16",
        8: "System.Int32",
        9: "System.UInt32",
        10: "System.Int64",
        11: "System.UInt64",
        12: "System.Single",
        13: "System.Double",
        14: "System.String",
        0x16: "System.TypedReference",
        0x18: "System.IntPtr",
        0x19: "System.UIntPtr",
        0x1C: "System.Object",
    }

    def tsig(s, b, o):
        e = b[o]
        o += 1
        if e in s.EL:
            return s.EL[e], o
        if e in (0x11, 0x12):
            c, o = s.comp(b, o)
            tab = c & 3
            rid = c >> 2
            t = s.tnom(Token((0x02, 0x01, 0x1B)[tab] << 24 | rid))
            return ("v:" if e == 0x11 else "") + t, o
        if e in (0x0F, 0x10, 0x45, 0x1D):
            t, o = s.tsig(b, o)
            return {0x0F: t + "*", 0x10: t + "&", 0x45: t, 0x1D: t + "[]"}[e], o
        if e == 0x15:
            o += 1
            c, o = s.comp(b, o)
            t = s.tnom(Token((0x02, 0x01, 0x1B)[c & 3] << 24 | c >> 2))
            n, o = s.comp(b, o)
            a = []
            for _ in range(n):
                x, o = s.tsig(b, o)
                a.append(x)
            return t + "<" + ",".join(a) + ">", o
        if e in (0x13, 0x1E):
            c, o = s.comp(b, o)
            return "!%d" % c, o
        if e == 0x14:
            t, o = s.tsig(b, o)
            r, o = s.comp(b, o)
            k, o = s.comp(b, o)
            for _ in range(k):
                _, o = s.comp(b, o)
            k, o = s.comp(b, o)
            for _ in range(k):
                _, o = s.comp(b, o)
            return t + "[,]", o
        if e in (0x1F, 0x20):
            _, o = s.comp(b, o)
            return s.tsig(b, o)
        if e == 0x1B:
            ms, o = s.msig(b, o)
            return "fn", o
        raise Falta("sig %x" % e)

    def msig(s, b, o=0):
        cc = b[o]
        o += 1
        g = 0
        if cc & 0x10:
            g, o = s.comp(b, o)
        n, o = s.comp(b, o)
        r, o = s.tsig(b, o)
        ps = []
        for _ in range(n):
            if b[o] == 0x41:
                o += 1
            p, o = s.tsig(b, o)
            ps.append(p)
        return (bool(cc & 0x20), r, ps), o

    def blob(s, x):
        return bytes(getattr(x, "value", x) if not isinstance(x, (bytes, bytearray)) else x)

    def tnom(s, tok):
        tab, rid = tok.table, tok.rid
        if tab == 2:
            return s.tipos[rid]
        if tab == 1:
            return nombre(s.md.TypeRef.rows[rid - 1])
        if tab == 0x1B:
            return s.tsig(s.blob(s.md.TypeSpec.rows[rid - 1].Signature), 0)[0]
        return "?%x" % tok.value

    def met(s, tok):
        # -> (rid interno o None, nombre completo, (hasthis, ret, params))
        k = tok.value
        if k in s.firmas:
            return s.firmas[k]
        tab, rid = tok.table, tok.rid
        if tab == 6:
            m = s.MT[rid - 1]
            r = (rid, s.tipos[s.due[rid]] + "::" + str(m.Name), s.msig(s.blob(m.Signature))[0])
        elif tab == 0x0A:
            m = s.md.MemberRef.rows[rid - 1]
            kl = m.Class
            tn = {"TypeRef": 1, "TypeDef": 2, "TypeSpec": 0x1B}.get(
                kl.table.name if hasattr(kl.table, "name") else "", 1
            )
            t = s.tnom(Token(tn << 24 | kl.row_index))
            sg = s.msig(s.blob(m.Signature))[0]
            rr = None
            if tn == 2 or (tn == 0x1B and "<" in t):
                for c in s.porn.get(t.split("<")[0].replace("v:", "") + "::" + str(m.Name), []):
                    if len(s.msig(s.blob(s.MT[c - 1].Signature))[0][2]) == len(sg[2]):
                        rr = c
                        break
            r = (rr, t + "::" + str(m.Name), sg)
        elif tab == 0x2B:
            m = s.md.MethodSpec.rows[rid - 1]
            kl = m.Method
            r = s.met(Token((6 if kl.table.name == "MethodDef" else 0x0A) << 24 | kl.row_index))
            try:
                bb = s.blob(m.Instantiation)
                n, o = s.comp(bb, 1)
                ta = []
                for _ in range(n):
                    x, o = s.tsig(bb, o)
                    ta.append(x)
                r = (r[0], r[1] + "<" + ",".join(ta) + ">", r[2])
            except Exception:
                pass
        else:
            raise Falta("met %x" % k)
        s.firmas[k] = r
        return r

    def fld(s, tok):
        if tok.table == 4:
            return tok.rid, s.tipos[s.fdue[tok.rid]] + "::" + str(s.FT[tok.rid - 1].Name)
        m = s.md.MemberRef.rows[tok.rid - 1]
        kl = m.Class
        tn = {"TypeRef": 1, "TypeDef": 2, "TypeSpec": 0x1B}.get(kl.table.name, 1)
        t = s.tnom(Token(tn << 24 | kl.row_index))
        return None, t + "::" + str(m.Name)

    def ftipo(s, rid):
        try:
            return s.tsig(s.blob(s.FT[rid - 1].Signature), 1)[0]
        except Exception:
            return "?"

    def cero(s, t):
        if t in PRIM:
            return (
                L(0)
                if t in ("System.Int64", "System.UInt64")
                else 0.0 if t in ("System.Single", "System.Double") else 0
            )
        if t in ("System.IntPtr", "System.UIntPtr"):
            return N(0)
        if t.startswith("v:"):
            q = t[2:]
            if q.startswith("System.ValueTuple"):
                return Obj(q)
            return Obj(q) if s.esstruct(q) else (0 if q in s.enums() else Obj(q))
        return None

    def enums(s):
        if not hasattr(s, "_en"):
            s._en = {
                nombre(t)
                for t in s.md.TypeDef.rows
                if t.Extends and t.Extends.row and nombre(t.Extends.row) == "System.Enum"
            } | {"System.StringComparison", "System.IO.FileMode", "System.Security.Cryptography.CipherMode"}
        return s._en

    def esstruct(s, q):
        if not hasattr(s, "_st"):
            s._st = {
                nombre(t)
                for t in s.md.TypeDef.rows
                if t.Extends and t.Extends.row and nombre(t.Extends.row) == "System.ValueType"
            }
        return q in s._st

    def cuerpo(s, rid):
        if rid in s.cache:
            return s.cache[rid]
        m = s.MT[rid - 1]
        if not m.Rva:
            raise Falta("sin cuerpo " + str(m.Name))
        cb = CilMethodBody(Rd(s.b, s.pe.get_offset_from_rva(m.Rva)))
        ins = [(i.offset, i.opcode.name, i.operand, i.offset + i.size) for i in cb.instructions]
        ix = {q[0]: k for k, q in enumerate(ins)}
        loc = []
        if cb.local_var_sig_tok and cb.local_var_sig_tok.value:
            rr = cb.local_var_sig_tok.rid
            bb = s.blob(s.md.StandAloneSig.rows[rr - 1].Signature)
            n, o = s.comp(bb, 1)
            for _ in range(n):
                t, o = s.tsig(bb, o)
                loc.append(t)
        eh = []
        for e in cb.exception_handlers:
            q0 = ins[0][0] if e.try_start < ins[0][0] else 0
            eh.append((e.try_start + q0, e.try_end + q0, e.handler_start + q0, e.handler_end + q0, e))
        sg = s.msig(s.blob(m.Signature))[0]
        r = (ins, ix, loc, eh, sg)
        s.cache[rid] = r
        return r

    def ini(s, ti):
        if ti in s.hechos:
            return
        s.hechos.add(ti)
        if ti in s.cct:
            try:
                s.corre(s.cct[ti], [])
            except Falta as e:
                if not getattr(s, "tolera", False):
                    raise
                print("  (cctor %s cortado: %s)" % (s.tipos[ti], str(e)[:110]))

    def datos(s, rid):
        if rid not in s.rvab:
            r = s.rva[rid]
            o = s.pe.get_offset_from_rva(r)
            t = s.ftipo(rid)
            n = 0
            q = t[2:] if t.startswith("v:") else t
            for k, v in s.tipos.items():
                if v == q and k in s.lay:
                    n = s.lay[k]
                    break
            s.rvab[rid] = bytearray(s.b[o : o + (n or 4)])
        return s.rvab[rid]

    def carga(s, a, e):
        if isinstance(a, Ref):
            v = a.get()
            if e in TAM and isinstance(v, int):
                return num(struct.unpack("<" + FMT[e], struct.pack("<q", int(v))[: TAM[e]])[0], e)
            return v
        if isinstance(a, Obj):
            return a
        buf, o = MEM.loc(a)
        return num(struct.unpack_from("<" + FMT[e], buf, o)[0], e)

    def guarda(s, a, v, e):
        if isinstance(a, Ref):
            a.set(v)
            return
        buf, o = MEM.loc(a)
        struct.pack_into("<" + FMT[e], buf, o, recorta(v, e))

    def llama(s, info, args):
        rid, nm, sg = info
        h = s.sobre.get(nm) or s.sobre.get(nm.split("<")[0] if not nm.startswith("System") else nm)
        if h:
            return h(s, args)
        if rid is not None and s.MT[rid - 1].Rva:
            return s.corre(rid, args)
        f = s.BCL.get(nm)
        if f is None:
            base = nm
            while "<" in base and f is None:
                i = base.index("<")
                d = 0
                for j in range(i, len(base)):
                    if base[j] == "<":
                        d += 1
                    elif base[j] == ">":
                        d -= 1
                        if d == 0:
                            break
                base = base[:i] + base[j + 1 :]
                f = s.BCL.get(base)
        if f is None:
            raise Falta("llamada no simulada: %s %s" % (nm, [type(a).__name__ for a in args]))
        return f(s, args)

    def invoca(s, d, args):
        if isinstance(d, Deleg):
            f = d.fn
            st = s.msig(s.blob(s.MT[f.m[0] - 1].Signature))[0][0] if f.m[0] else f.m[2][0]
            return s.llama(f.m, ([d.o] if st else []) + args)
        raise Falta("invocar %r" % (d,))

    def corre(s, rid, args):
        ti = s.due[rid]
        if str(s.MT[rid - 1].Name) != ".cctor":
            s.ini(ti)
        ins, ix, lt, eh, sg = s.cuerpo(rid)
        loc = [s.cero(t) for t in lt]
        args = list(args)
        st = []
        pc = 0
        pend = []
        while True:
            try:
                return s.bucle(rid, ins, ix, lt, loc, args, st, pc, eh, pend, sg)
            except NetEx as e:
                off = s._off
                hecho = False
                for a, b, c, d, h in eh:
                    if a <= off < b and h.exception_type & 7 == 0:
                        st.clear()
                        st.append(e.o)
                        pc = ix[c]
                        hecho = True
                        break
                if not hecho:
                    raise

    def bucle(s, rid, ins, ix, lt, loc, args, st, pc, eh, pend, sg):
        pop = st.pop
        push = st.append
        while True:
            off, op, od, sig = ins[pc]
            pc += 1
            s.pasos += 1
            if s.pasos > s.maxpasos:
                raise Falta("demasiados pasos")
            try:
                if op[:5] == "ldloc":
                    if op.startswith("ldloca"):
                        k = od if isinstance(od, int) else getattr(od, "index", od)
                        v = loc[k]
                        if isinstance(v, Obj) and lt[k].startswith("v:"):
                            push(Ref(lambda k=k: loc[k], lambda x, k=k: loc.__setitem__(k, x)))
                        else:
                            push(Ref(lambda k=k: loc[k], lambda x, k=k: loc.__setitem__(k, x)))
                    else:
                        push(loc[int(op[6:]) if op[6:].isdigit() else getattr(od, "index", od)])
                elif op[:5] == "stloc":
                    k = int(op[6:]) if op[6:].isdigit() else getattr(od, "index", od)
                    v = pop()
                    t = lt[k]
                    if t in PRIM and isinstance(v, int):
                        e = PRIM[t]
                        v = num(recorta(v, e), e) if e not in ("B",) else int(v)
                    loc[k] = v
                elif op[:5] == "ldarg":
                    if op.startswith("ldarga"):
                        k = getattr(od, "index", od)
                        push(Ref(lambda k=k: args[k], lambda x, k=k: args.__setitem__(k, x)))
                    else:
                        push(args[int(op[6:]) if op[6:].isdigit() else getattr(od, "index", od)])
                elif op[:4] == "starg":
                    args[getattr(od, "index", od)] = pop()
                elif op.startswith("starg"):
                    args[getattr(od, "index", od)] = pop()
                elif op[:6] == "ldc.i4":
                    r = op[7:]
                    push(-1 if r in ("m1", "M1") else int(r) if r.isdigit() else i32(od))
                elif op == "ldc.i8":
                    push(i64(od))
                elif op in ("ldc.r4", "ldc.r8"):
                    push(float(od))
                elif op == "ldnull":
                    push(None)
                elif op == "ldstr":
                    push(str(s.pe.net.user_strings.get(od.rid).value))
                elif op == "dup":
                    push(st[-1])
                elif op == "pop":
                    pop()
                elif op in ("nop", "volatile.", "readonly.", "unaligned.", "constrained.", "tail.", "break"):
                    pass
                elif op in ("br", "br.s"):
                    pc = ix[od]
                elif op in ("brtrue", "brtrue.s", "brfalse", "brfalse.s"):
                    v = pop()
                    t = v is not None and (v != 0 if isinstance(v, (int, float)) else True)
                    if t == (op[2] == "t"):
                        pc = ix[od]
                elif op[0] == "b" and op.split(".")[0] in ("beq", "bne", "bge", "bgt", "ble", "blt"):
                    b = pop()
                    a = pop()
                    if s.cmp(
                        op[1:3] if not op.startswith("bne") else "ne",
                        a,
                        b,
                        ".un" in op and not op.startswith("bne"),
                    ):
                        pc = ix[od]
                elif op in ("ceq", "cgt", "cgt.un", "clt", "clt.un"):
                    b = pop()
                    a = pop()
                    push(int(s.cmp(op[1:3], a, b, op.endswith(".un"))))
                elif op == "switch":
                    v = pop() & 0xFFFFFFFF
                    if v < len(od):
                        pc = ix[od[v]]
                elif op in (
                    "add",
                    "sub",
                    "mul",
                    "and",
                    "or",
                    "xor",
                    "div",
                    "rem",
                    "div.un",
                    "rem.un",
                    "shl",
                    "shr",
                    "shr.un",
                ) or op[:4] in ("add.", "sub.", "mul."):
                    b = pop()
                    a = pop()
                    push(s.ari(op, a, b))
                elif op == "neg":
                    v = pop()
                    push(
                        -v
                        if isinstance(v, float)
                        else i64(-v) if isinstance(v, L) else ni(-v) if isinstance(v, N) else i32(-v)
                    )
                elif op == "not":
                    v = pop()
                    push(i64(~v) if isinstance(v, L) else ni(~v) if isinstance(v, N) else i32(~v))
                elif op[:4] == "conv":
                    push(s.conv(op, pop()))
                elif op[:5] == "ldind":
                    e = {
                        "i1": "I1",
                        "u1": "U1",
                        "i2": "I2",
                        "u2": "U2",
                        "i4": "I4",
                        "u4": "U4",
                        "i8": "I8",
                        "i": "I",
                        "r4": "R4",
                        "r8": "R8",
                        "ref": "REF",
                    }[op[6:]]
                    push(s.carga(pop(), e))
                elif op[:5] == "stind":
                    e = {
                        "i1": "I1",
                        "i2": "I2",
                        "i4": "I4",
                        "i8": "I8",
                        "i": "I",
                        "r4": "R4",
                        "r8": "R8",
                        "ref": "REF",
                    }[op[6:]]
                    v = pop()
                    s.guarda(pop(), v, e)
                elif op == "ldobj":
                    a = pop()
                    t = s.tnom(od)
                    push(s.carga(a, PRIM.get(t, "I")))
                elif op == "stobj":
                    v = pop()
                    a = pop()
                    s.guarda(a, v, PRIM.get(s.tnom(od), "I"))
                elif op == "newarr":
                    t = s.tnom(od)
                    n = pop()
                    push(Arr(PRIM.get(t), n, t=t))
                    if t not in PRIM:
                        z = (
                            s.cero("v:" + t)
                            if s.esstruct(t)
                            else N(0) if t in ("System.IntPtr", "System.UIntPtr") else None
                        )
                        if z is not None:
                            st[-1].l = [s.cero("v:" + t) if s.esstruct(t) else z for _ in range(n)]
                elif op == "ldlen":
                    push(N(len(s.nn(pop()))))
                elif op == "ldelema":
                    i = pop()
                    a = pop()
                    if a.b is not None:
                        a.ck(i)
                        push(N(MEM.base(a.b) + i * TAM[a.e]))
                    else:
                        push(Ref(lambda a=a, i=i: a.get(i), lambda x, a=a, i=i: a.put(i, x)))
                elif op[:6] == "ldelem":
                    i = pop()
                    push(s.nn(pop()).get(i))
                elif op[:6] == "stelem":
                    v = pop()
                    i = pop()
                    s.nn(pop()).put(i, v)
                elif op in ("ldsfld", "ldsflda", "stsfld"):
                    r, n = s.fld(od)
                    if r is None:
                        f = s.BCL.get("fld " + n)
                        if f is None:
                            raise Falta("campo " + n)
                        push(f(s))
                        continue
                    if r in s.rva and op == "ldsflda":
                        push(N(MEM.base(s.datos(r))))
                        continue
                    s.ini(s.fdue[r])
                    if r not in s.est:
                        if r in s.rva:
                            t = s.ftipo(r)
                            s.est[r] = num(
                                struct.unpack_from("<" + FMT[PRIM.get(t, "I4")], s.datos(r))[0],
                                PRIM.get(t, "I4"),
                            )
                        else:
                            s.est[r] = s.cero(s.ftipo(r))
                    if op == "ldsfld":
                        push(s.est[r])
                    elif op == "stsfld":
                        v = pop()
                        t = s.ftipo(r)
                        s.est[r] = (
                            num(recorta(v, PRIM[t]), PRIM[t]) if t in PRIM and isinstance(v, int) else v
                        )
                    else:
                        push(Ref(lambda r=r: s.est[r], lambda x, r=r: s.est.__setitem__(r, x)))
                elif op in ("ldfld", "ldflda", "stfld"):
                    v = pop() if op == "stfld" else None
                    o = pop()
                    if isinstance(o, Ref):
                        o = o.get()
                    r, n = s.fld(od)
                    if o is None:
                        raise NetEx(Obj("System.NullReferenceException"))
                    key = r if r is not None else n
                    if not isinstance(o, Obj):
                        raise Falta("campo %s de %r" % (n, o))
                    if op == "stfld":
                        o.f[key] = v
                    else:
                        if key not in o.f:
                            o.f[key] = s.cero(s.ftipo(r)) if r else None
                        if op == "ldfld":
                            push(o.f[key])
                        else:
                            push(Ref(lambda o=o, k=key: o.f[k], lambda x, o=o, k=key: o.f.__setitem__(k, x)))
                elif op in ("call", "callvirt"):
                    info = s.met(od)
                    hs, rt, ps = info[2]
                    n = len(ps) + (1 if hs else 0)
                    a = st[len(st) - n :] if n else []
                    if n:
                        del st[len(st) - n :]
                    if s.traza:
                        s.traza(s, rid, off, info, a)
                    if (
                        op == "callvirt"
                        and info[0]
                        and a
                        and isinstance(a[0], Obj)
                        and a[0].t != s.tipos[s.due[info[0]]]
                    ):
                        for c in s.porn.get(a[0].t + "::" + str(s.MT[info[0] - 1].Name), []):
                            if len(s.msig(s.blob(s.MT[c - 1].Signature))[0][2]) == len(ps):
                                info = (c, info[1], info[2])
                                break
                    r = s.llama(info, a)
                    if rt != "System.Void":
                        push(r)
                elif op == "newobj":
                    info = s.met(od)
                    n = len(info[2][2])
                    a = st[len(st) - n :] if n else []
                    if n:
                        del st[len(st) - n :]
                    if s.traza:
                        s.traza(s, rid, off, info, a)
                    t = info[1].rsplit("::", 1)[0]
                    if info[0] is None:
                        if t.split("<")[0].replace("v:", "") in (
                            "System.Func`1",
                            "System.Func`2",
                            "System.Func`3",
                            "System.Func`4",
                            "System.Func`5",
                            "System.Action",
                            "System.Action`1",
                            "System.Action`2",
                            "System.EventHandler",
                            "System.Threading.ThreadStart",
                            "System.Predicate`1",
                            "System.Comparison`1",
                        ):
                            push(Deleg(a[0], fn(a[1])))
                        else:
                            push(s.llama(info, a))
                    elif not s.MT[info[0] - 1].Rva and n == 2:
                        push(Deleg(a[0], fn(a[1])))
                    else:
                        o = Obj(t)
                        s.llama(info, [o] + a)
                        push(o)
                elif op == "calli":
                    f = fn(pop())
                    sgb = s.blob(s.md.StandAloneSig.rows[od.rid - 1].Signature)
                    hs, rt, ps = s.msig(sgb)[0]
                    n = len(ps) + (1 if hs else 0)
                    a = st[len(st) - n :] if n else []
                    if n:
                        del st[len(st) - n :]
                    if not isinstance(f, Fn):
                        raise Falta("calli a %r" % (f,))
                    r = s.llama(f.m, a)
                    if rt != "System.Void":
                        push(r)
                elif op == "ldftn":
                    push(Fn(s.met(od)))
                elif op == "ldvirtftn":
                    o = pop()
                    push(Fn(s.met(od)))
                elif op == "ret":
                    return pop() if sg[1] != "System.Void" and st else None
                elif op == "ldtoken":
                    push(Tipo(s.tnom(od)) if od.table in (1, 2, 0x1B) else od)
                elif op in ("castclass", "box", "unbox.any"):
                    if op == "unbox.any" and isinstance(st[-1], tuple) and st[-1][0] == "box":
                        pass
                elif op == "unbox":
                    v = pop()
                    push(Ref(lambda v=v: v, lambda x: None))
                elif op == "isinst":
                    t = s.tnom(od)
                    v = st[-1]
                    if not s.es(v, t):
                        st[-1] = None
                elif op == "initobj":
                    a = pop()
                    t = s.tnom(od)
                    if isinstance(a, Ref):
                        a.set(s.cero("v:" + t if t not in PRIM else t))
                elif op == "sizeof":
                    t = s.tnom(od)
                    push(TAM[PRIM[t]] if t in PRIM else 4)
                elif op == "localloc":
                    n = pop()
                    bb = bytearray(n)
                    s.rvab[("l", id(bb))] = bb
                    push(N(MEM.base(bb)))
                elif op == "throw":
                    raise NetEx(pop())
                elif op == "rethrow":
                    raise NetEx(Obj("rethrow"))
                elif op in ("leave", "leave.s"):
                    st.clear()
                    fs = [(c, d) for a, b, c, d, h in eh if a <= off < b and not (a <= od < b) and s.fin(h)]
                    if fs:
                        pend.append((list(fs[1:]), od))
                        pc = ix[fs[0][0]]
                    else:
                        pc = ix[od]
                elif op == "endfinally":
                    if pend:
                        fs, d = pend.pop()
                        if fs:
                            pend.append((fs[1:], d))
                            pc = ix[fs[0][0]]
                        else:
                            pc = ix[d]
                    else:
                        return None
                elif op in ("cpblk",):
                    n = pop()
                    o2 = pop()
                    d = pop()
                    b1, p1 = MEM.loc(o2)
                    b2, p2 = MEM.loc(d)
                    b2[p2 : p2 + n] = b1[p1 : p1 + n]
                elif op == "initblk":
                    n = pop()
                    v = pop()
                    d = pop()
                    b2, p2 = MEM.loc(d)
                    b2[p2 : p2 + n] = bytes([v & 255]) * n
                else:
                    raise Falta("op " + op)
            except NetEx:
                s._off = off
                raise
            except Falta as e:
                if not getattr(e, "pila", None):
                    e.pila = []
                e.pila.append("%s+%x %s" % (s.tipos[s.due[rid]] + "::" + str(s.MT[rid - 1].Name), off, op))
                raise

    def fin(s, h):
        return bool(h.exception_type & 6)

    def nn(s, a):
        if a is None:
            raise NetEx(Obj("System.NullReferenceException"))
        if isinstance(a, Ref):
            return a.get()
        return a

    def es(s, v, t):
        if v is None:
            return False
        if isinstance(v, str):
            return t in ("System.String", "System.Object")
        if isinstance(v, Arr):
            return t.endswith("[]") or t in ("System.Array", "System.Object")
        if isinstance(v, Obj):
            if v.t == t or t == "System.Object":
                return True
            for ti, n in s.tipos.items():
                if n == v.t:
                    r = s.md.TypeDef.rows[ti - 1].Extends
                    return bool(r and r.row and nombre(r.row) == t)
            return t in ("System.IDisposable",) or v.t.split(".")[-1] == t.split(".")[-1]
        return True

    def cmp(s, c, a, b, un):
        if c in ("eq", "be") or c == "ne":
            if a is None or b is None:
                r = (a is b) or (
                    a in (None, 0)
                    and b in (None, 0)
                    and not isinstance(a, (str, Arr, Obj))
                    and not isinstance(b, (str, Arr, Obj))
                )
            elif isinstance(a, (int, float)) and isinstance(b, (int, float)):
                r = a == b
            elif isinstance(a, Fn) and isinstance(b, Fn):
                r = a.m == b.m
            else:
                r = a is b if not isinstance(a, str) else a == b
            return r if c != "ne" else not r
        if a is None or b is None or not isinstance(a, (int, float)) or not isinstance(b, (int, float)):
            if c == "gt":
                return a is not None and a != 0 if b in (None, 0) else False
            raise Falta("cmp %r %r" % (a, b))
        if un and isinstance(a, int) and isinstance(b, int):
            m = (1 << 64) - 1 if isinstance(a, L) or isinstance(b, L) else 0xFFFFFFFF
            a &= m
            b &= m
        return {"ge": a >= b, "gt": a > b, "le": a <= b, "lt": a < b}[c]

    def ari(s, op, a, b):
        if isinstance(a, float) or isinstance(b, float):
            return {
                "add": lambda: a + b,
                "sub": lambda: a - b,
                "mul": lambda: a * b,
                "div": lambda: a / b,
                "rem": lambda: a - b * int(a / b),
            }[op.split(".")[0]]()
        if a is None:
            a = N(0)
        if b is None:
            b = N(0)
        if not isinstance(a, int) or not isinstance(b, int):
            raise Falta("ari %s %r %r" % (op, a, b))
        l = isinstance(a, L) or (isinstance(b, L) and op[:2] != "sh")
        n = isinstance(a, N) or (isinstance(b, N) and op[:2] != "sh")
        w = 64 if l else 32
        m = (1 << w) - 1
        x = int(a)
        y = int(b)
        o = op.split(".")[0]
        un = ".un" in op
        if o == "add":
            r = x + y
        elif o == "sub":
            r = x - y
        elif o == "mul":
            r = x * y
        elif o == "and":
            r = x & y
        elif o == "or":
            r = x | y
        elif o == "xor":
            r = x ^ y
        elif o == "shl":
            r = x << (y & (w - 1))
        elif o == "shr":
            r = ((x & m) if un else x) >> (y & (w - 1))
        else:
            if un:
                x &= m
                y &= m
            if y == 0:
                raise NetEx(Obj("System.DivideByZeroException"))
            q = abs(x) // abs(y)
            q = -q if (x < 0) != (y < 0) else q
            r = q if o == "div" else x - q * y
        return i64(r) if l else ni(r) if n else i32(r)

    def conv(s, op, v):
        t = op[5:].replace("ovf.", "").replace(".un", "")
        if isinstance(v, (Ref, Fn, Obj, Arr, str)):
            return v if not isinstance(v, str) else N(MEM.base(s.fija(v)))
        if v is None:
            v = 0
        un = op.endswith(".un")
        if t in ("r4", "r8", "r"):
            return float(
                (int(v) & ((1 << 64) - 1 if isinstance(v, L) else 0xFFFFFFFF))
                if un and isinstance(v, int)
                else v
            )
        x = int(v)
        if un and x < 0:
            x &= (1 << 64) - 1 if isinstance(v, L) else 0xFFFFFFFF
        if t == "i8":
            return i64(x)
        if t == "u8":
            return i64(x if isinstance(v, (L, float)) else x & 0xFFFFFFFF)
        if t in ("i", "u"):
            return ni(x)
        e = t.upper()
        return num(recorta(x, e), e)

    def fija(s, v):
        k = ("s", v)
        if k not in s.rvab:
            s.rvab[k] = bytearray(v.encode("utf-16le") + b"\0\0")
        return s.rvab[k]


# --- funciones del sistema simuladas
def b_(f):
    return lambda e, a: f(*a)


def val(x):
    return x.get() if isinstance(x, Ref) else x


def cstr(e, a):
    p = a[0]
    if isinstance(p, Arr):
        s_ = p.b.decode("utf-16le", "surrogatepass")
        return s_ if len(a) == 1 else s_[a[1] : a[1] + a[2]]
    if isinstance(p, Ref):
        p = p.get()
    if p == 0:
        return ""
    if len(a) == 2 and False:
        pass
    buf, o = MEM.loc(p)
    q = o
    while q + 1 < len(buf) and (buf[q] or buf[q + 1]):
        q += 2
    return bytes(buf[o:q]).decode("utf-16le", "surrogatepass")


def copia(e, a):
    if len(a) == 3:
        a = [a[0], 0, a[1], 0, a[2]]
    s_, si, d, di, n = a
    if s_.b is not None and d.b is not None:
        w = TAM[s_.e]
        d.b[di * w : (di + n) * w] = s_.b[si * w : (si + n) * w]
    else:
        d.l[di : di + n] = s_.l[si : si + n]


class NetRandom:
    def __init__(s, seed):
        sub = 2147483647 if seed == -2147483648 else abs(seed)
        mj = 161803398 - sub
        sa = [0] * 56
        sa[55] = mj
        mk = 1
        for i in range(1, 55):
            ii = (21 * i) % 55
            sa[ii] = mk
            mk = mj - mk
            if mk < 0:
                mk += 2147483647
            mj = sa[ii]
        for k in range(1, 5):
            for i in range(1, 56):
                sa[i] = i32(sa[i] - sa[1 + (i + 30) % 55])
                if sa[i] < 0:
                    sa[i] += 2147483647
        s.sa = sa
        s.a = 0
        s.b = 21

    def samp(s):
        s.a = s.a + 1 if s.a + 1 < 56 else 1
        s.b = s.b + 1 if s.b + 1 < 56 else 1
        r = s.sa[s.a] - s.sa[s.b]
        if r == 2147483647:
            r -= 1
        if r < 0:
            r += 2147483647
        s.sa[s.a] = r
        return r

    def next(s, *a):
        if not a:
            return s.samp()
        if len(a) == 1:
            return int(s.samp() * (1.0 / 2147483647) * a[0])
        return int(s.samp() * (1.0 / 2147483647) * (a[1] - a[0])) + a[0]


class Aes_:
    key = iv = None
    mode = 1


class Lista(list):
    __hash__ = object.__hash__


class SB(list):
    __hash__ = object.__hash__


def monta(E):
    import uuid
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad

    B = E.BCL
    mv = uuid.UUID(str(E.md.Module.rows[0].Mvid)).bytes_le
    B["System.Object::.ctor"] = lambda e, a: None if a else Obj("System.Object")
    B["System.String::.ctor"] = cstr
    B["System.Type::GetTypeFromHandle"] = b_(lambda t: t)
    B["System.Type::get_Module"] = B["System.Reflection.MemberInfo::get_Module"] = b_(lambda t: "MODULO")
    B["System.Reflection.Module::get_ModuleVersionId"] = b_(lambda m: ("guid", mv))
    B["System.Guid::ToByteArray"] = b_(lambda g: barr(val(g)[1]))
    for n in ("SHA256CryptoServiceProvider", "SHA256Managed"):
        B["System.Security.Cryptography.%s::.ctor" % n] = lambda e, a: "SHA256"
    B["System.Security.Cryptography.HashAlgorithm::ComputeHash"] = lambda e, a: barr(
        hashlib.sha256(bytes(a[1].b) if len(a) == 2 else bytes(a[1].b[a[2] : a[2] + a[3]])).digest()
    )
    B["System.Security.Cryptography.HashAlgorithm::Dispose"] = B["System.IDisposable::Dispose"] = (
        lambda e, a: None
    )
    B["System.Security.Cryptography.AesCryptoServiceProvider::.ctor"] = lambda e, a: Aes_()
    B["System.Security.Cryptography.SymmetricAlgorithm::set_Key"] = lambda e, a: setattr(
        a[0], "key", bytes(a[1].b)
    )
    B["System.Security.Cryptography.SymmetricAlgorithm::set_IV"] = lambda e, a: setattr(
        a[0], "iv", bytes(a[1].b)
    )
    B["System.Security.Cryptography.SymmetricAlgorithm::CreateDecryptor"] = lambda e, a: (
        (setattr(a[0], "key", bytes(a[1].b)), setattr(a[0], "iv", bytes(a[2].b)), a[0])[2]
        if len(a) == 3
        else a[0]
    )
    B["System.Security.Cryptography.ICryptoTransform::TransformFinalBlock"] = lambda e, a: barr(
        unpad(AES.new(a[0].key, AES.MODE_CBC, a[0].iv).decrypt(bytes(a[1].b[a[2] : a[2] + a[3]])), 16)
    )
    B["System.Array::Copy"] = copia

    def bcopia(e, a):
        a[2].b[a[3] : a[3] + a[4]] = a[0].b[a[1] : a[1] + a[4]]

    B["System.Buffer::BlockCopy"] = bcopia
    B["System.BitConverter::ToInt32"] = lambda e, a: struct.unpack_from("<i", a[0].b, a[1])[0]
    B["System.BitConverter::ToUInt32"] = lambda e, a: struct.unpack_from("<i", a[0].b, a[1])[0]
    B["System.Random::.ctor"] = lambda e, a: NetRandom(a[-1])
    B["System.Random::Next"] = lambda e, a: a[0].next(*a[1:])
    for n in ("UTF8", "ASCII", "Unicode", "Default"):
        B["System.Text.Encoding::get_" + n] = lambda e, a, n=n: n
    cod = {"UTF8": "utf-8", "ASCII": "latin1", "Unicode": "utf-16le", "Default": "latin1"}
    B["System.Text.Encoding::GetString"] = lambda e, a: (
        bytes(a[1].b) if len(a) == 2 else bytes(a[1].b[a[2] : a[2] + a[3]])
    ).decode(cod[a[0]], "replace")
    B["System.Text.Encoding::GetBytes"] = lambda e, a: barr(a[1].encode(cod[a[0]]))
    B["System.String::get_Length"] = b_(len)
    B["System.String::get_Chars"] = lambda e, a: ord(a[0][a[1]])
    B["System.String::Concat"] = lambda e, a: "".join(
        ("" if x is None else str(x)) for x in (a if not isinstance(a[0], Arr) else a[0].l)
    )
    B["System.String::Substring"] = lambda e, a: a[0][a[1] :] if len(a) == 2 else a[0][a[1] : a[1] + a[2]]
    B["System.String::Equals"] = B["System.String::op_Equality"] = lambda e, a: int(
        a[0] == a[1] if len(a) == 2 or a[2] % 2 == 0 else a[0].lower() == a[1].lower()
    )
    B["System.String::op_Inequality"] = lambda e, a: int(a[0] != a[1])
    B["System.String::IsNullOrEmpty"] = lambda e, a: int(not a[0])
    B["System.String::ToCharArray"] = lambda e, a: Arr("C", data=a[0].encode("utf-16le"))
    B["System.Char::ToString"] = lambda e, a: chr(val(a[0]))
    B["System.Convert::FromBase64String"] = lambda e, a: barr(__import__("base64").b64decode(a[0]))
    B["System.Convert::ToByte"] = lambda e, a: int(a[0], a[1]) if isinstance(a[0], str) else a[0]
    B["System.Array::get_Length"] = b_(len)
    B["System.Array::Reverse"] = lambda e, a: a[0].l.reverse() if a[0].b is None else a[0].b.reverse()
    B["System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray"] = lambda e, a: a[0].b.__setitem__(
        slice(0, len(a[0].b)), e.b[(lambda o: o)(e.pe.get_offset_from_rva(e.rva[a[1].rid])) :][: len(a[0].b)]
    )
    B["System.Runtime.CompilerServices.RuntimeHelpers::get_OffsetToStringData"] = lambda e, a: 0
    for n in ("List`1", "Queue`1", "Stack`1"):
        B["System.Collections.Generic.%s::.ctor" % n] = lambda e, a: Lista()
    G = "System.Collections.Generic.List`1::"
    B[G + "Add"] = lambda e, a: a[0].append(a[1])
    B[G + "get_Item"] = lambda e, a: a[0][a[1]]
    B[G + "set_Item"] = lambda e, a: a[0].__setitem__(a[1], a[2])
    B[G + "get_Count"] = lambda e, a: len(a[0])
    B[G + "ToArray"] = lambda e, a: Arr(None, data=a[0])
    for n in ("Func`1", "Func`2", "Func`3", "Func`4", "Func`5", "Action", "Action`1", "Action`2"):
        B["System.%s::Invoke" % n] = lambda e, a: e.invoca(a[0], a[1:])
    B["System.Text.StringBuilder::.ctor"] = lambda e, a: SB()

    def sba(e, a):
        a[0].append(chr(a[1]) if isinstance(a[1], int) else str(a[1]))
        return a[0]

    B["System.Text.StringBuilder::Append"] = sba
    B["System.Object::ToString"] = B["System.Text.StringBuilder::ToString"] = lambda e, a: (
        "".join(a[0]) if isinstance(a[0], SB) else str(val(a[0]))
    )
    B["System.IntPtr::op_Explicit"] = B["System.IntPtr::.ctor"] = lambda e, a: (
        N(int(a[-1])) if isinstance(a[-1], int) else a[-1]
    )
    B["fld System.IntPtr::Zero"] = lambda e: N(0)
    B["fld System.String::Empty"] = lambda e: ""
    return E
