# Sigue al ladron emulado: APIs nativas ficticias y registro de archivos, claves y conexiones que pide.
import sys, os, struct
AQUI = os.environ.get('SALIDA', '.')
os.environ['MAXI'] = os.environ.get('MAXI', '9000000000'); os.environ['VER'] = '0'
import x86 as uni
from x86 import *
def ous(p):
    if not p: return ''
    n, m, b = struct.unpack('<HHI', uc.mem_read(p, 8)); return bytes(uc.mem_read(b, n)).decode('utf-16le', 'replace')
def oa(p): return (hex(r32(p + 4)) if r32(p + 4) else '') + ous(r32(p + 8))
LOG = []
def lg(*a): print('   *', *a, flush=True)
HN = [0x100]; HS = {}
def nh(d): HN[0] += 4; HS[HN[0]] = d; return HN[0]
VAT = []
def malloc(u, a, s, d):
    esp = u.reg_read(UC_X86_REG_ESP); n = r32(esp + 4); u.reg_write(UC_X86_REG_EAX, aloc(n) if n < 0x200000 else 0); u.reg_write(UC_X86_REG_EIP, r32(esp)); u.reg_write(UC_X86_REG_ESP, esp + 4)
uc.hook_add(UC_HOOK_CODE, malloc, None, 0x20f729d8, 0x20f729d8)
def dup(sp, sh, tp, th, acc, at, op):
    if th: w32(th, nh(('dup', sh)))
    return 0
N['NtDuplicateObject'] = (7, dup)
def cf(ph, acc, o, iosb, *r): n = oa(o); lg('NtCreateFile', n); ret = 0 if 'Afd' in n or 'afd' in n else 0xC0000034; (w32(ph, nh(('f', n))) if not ret else 0); return ret
N['NtCreateFile'] = (11, cf)
N['NtOpenFile'] = (6, lambda ph, acc, o, i, s, x: (lg('NtOpenFile', oa(o)), 0xC0000034)[1])
N['NtOpenKey'] = (3, lambda ph, a, o: (lg('NtOpenKey', oa(o)), 0xC0000034)[1]); N['NtOpenKeyEx'] = (4, lambda ph, a, o, x: (lg('NtOpenKeyEx', oa(o)), 0xC0000034)[1])
N['NtQueryAttributesFile'] = (2, lambda o, b: (lg('attr', oa(o)), 0xC0000034)[1]); N['NtQueryFullAttributesFile'] = (2, lambda o, b: (lg('fattr', oa(o)), 0xC0000034)[1])
def ioctl(h, ev, apc, ctx, ios, code, ib, il, ob, ol):
    d = bytes(uc.mem_read(ib, min(il, 400))) if ib and il else b''; lg('IOCTL', HS.get(h), hex(code), il, d.hex()[:200], d);
    if ios: w32(ios, 0); w32(ios + 4, 0)
    return 0
N['NtDeviceIoControlFile'] = (10, ioctl)
N['NtCreateMutant'] = (4, lambda ph, a, o, i: (lg('Mutant', oa(o) if o else ''), w32(ph, nh('m')), 0)[2]); N['NtOpenMutant'] = (3, lambda ph, a, o: (lg('OpenMutant', oa(o)), 0xC0000034)[1])
N['NtCreateEvent'] = (5, lambda ph, a, o, t, i: (w32(ph, nh('e')), 0)[1]); N['NtOpenSection'] = (3, lambda ph, a, o: (lg('OpenSection', oa(o)), 0xC0000034)[1])
N['LdrLoadDll'] = (4, lambda p, f, n, ph: (lg('LdrLoadDll', ous(n)), w32(ph, ll(ous(n))), 0 if r32(ph) else 0xC0000135)[2])
N['NtOpenProcessToken'] = (3, lambda p, a, ph: (w32(ph, nh('tok')), 0)[1]); N['NtOpenProcessTokenEx'] = (4, lambda p, a, x, ph: (w32(ph, nh('tok')), 0)[1]); N['NtOpenProcess'] = (4, lambda ph, a, o, c: 0xC0000022)
def qit(h, c, b, n, r):
    if c == 1:  # usuario
        sid = struct.pack('<BB6B5I', 1, 5, 0, 0, 0, 0, 0, 5, 21, 111111111, 222222222, 333333333, 1001); need = 8 + len(sid)
        if r: w32(r, need)
        if n < need: return 0xC0000023
        uc.mem_write(b, struct.pack('<II', b + 8, 0) + sid); return 0
    if r: w32(r, 4)
    if n >= 4: w32(b, {18: 3, 20: 0, 25: 0}.get(c, 0)); return 0
    return 0xC0000023
N['NtQueryInformationToken'] = (5, qit)
for n_, k_, v_ in (('NtSetInformationFile', 5, 0), ('NtQueryInformationFile', 5, 0xC0000008), ('NtQueryDirectoryFile', 11, 0x80000006), ('NtReadFile', 9, 0xC0000008), ('NtWriteFile', 9, 0), ('NtCreateSection', 7, 0xC0000022), ('NtMapViewOfSection', 10, 0xC0000022), ('NtUnmapViewOfSection', 2, 0), ('NtQueryValueKey', 6, 0xC0000034), ('NtEnumerateKey', 6, 0x8000001A), ('NtClearEvent', 1, 0), ('NtResetEvent', 2, 0), ('NtWaitForMultipleObjects', 5, 0), ('NtTerminateThread', 2, 0), ('NtGetCurrentProcessorNumber', 0, 1), ('NtGetNextProcess', 5, 0x8000001A), ('NtQueryVolumeInformationFile', 5, 0xC0000008), ('RtlGetVersion', 1, 0), ('RtlExitUserProcess', 1, 0), ('NtAdjustPrivilegesToken', 6, 0), ('NtQueryTimerResolution', 3, 0), ('NtSetTimerResolution', 3, 0), ('NtQueryWnfStateData', 6, 0xC0000034), ('NtRaiseHardError', 6, 0), ('NtCreateKey', 7, 0xC0000022), ('NtSetValueKey', 6, 0xC0000022), ('NtDeleteFile', 1, 0), ('NtReleaseMutant', 2, 0), ('NtQueryEvent', 5, 0), ('NtCreateTimer', 4, 0xC0000022), ('NtTraceEvent', 4, 0), ('NtTraceControl', 6, 0xC0000022), ('NtPowerInformation', 5, 0xC0000022), ('NtQueryDebugFilterState', 2, 0), ('NtIsProcessInJob', 2, 0x122), ('NtQueryInformationJobObject', 5, 0xC0000022), ('NtQueryLicenseValue', 5, 0xC0000034), ('NtQueryPortInformationProcess', 0, 0), ('NtCreateUserProcess', 11, 0xC0000022)): simple(n_, k_, v_)
N['NtTerminateProcess'] = (2, lambda h, c: (lg('TERMINA', hex(h), hex(c)), uc.emu_stop(), 0)[2])
N['RtlExitUserProcess'] = (1, lambda c: (lg('SALE', hex(c)), uc.emu_stop(), 0)[2])
def gctx(h, c): return 0
def qpi(h, c, b, n, r):
    if c == 0x1B: # nombre
        s = '\\Device\\HarddiskVolume3\\Users\\u\\AppData\\Local\\Temp\\t\\DassmMQOJ.exe'.encode('utf-16le')
        if r: w32(r, 8 + len(s))
        if n < 8 + len(s): return 0xC0000004
        uc.mem_write(b, struct.pack('<HHI', len(s), len(s), b + 8) + s); return 0
    return uni.nqip(h, c, b, n, r)
N['NtQueryInformationProcess'] = (5, qpi)
ULT = []
o_at = uni.atiende
def traza_api(n):
    ULT.append(n)
DEC = {}
# textos que aparecen al salir de los descifradores
def tras(u, a, s, d):
    pass
ESP = set(int(x, 16) for x in os.environ.get('PAROS', '').split(',') if x)
def alto(u, a, s, d):
    if a in ESP: print('PARO', hex(a)); u.emu_stop()
for a_ in ESP: uc.hook_add(UC_HOOK_CODE, alto, None, a_, a_)
if __name__ == '__main__':
    llama(BASE + pe.OPTIONAL_HEADER.AddressOfEntryPoint, BASE, 1, 0); ar, _ = ustr('C:\\Users\\u\\AppData'); llama(BASE + 0x1090, ar)
    esp = uc.reg_read(UC_X86_REG_ESP); print('pila', [hex(r32(esp + 4 * q)) for q in range(12)])
    print(CNT.most_common(40)); open(AQUI + '/uni_heap.bin', 'wb').write(bytes(uc.mem_read(HEAP, al(hp[0] - HEAP))))
    h = bytes(uc.mem_read(HEAP + 0x149c000, hp[0] - HEAP - 0x149c000)); import re
    tx = sorted({m.group().decode() for m in re.finditer(rb'[\x20-\x7e]{5,}', h)} | {m.group().decode('utf-16le') for m in re.finditer(rb'(?:[\x20-\x7e]\x00){4,}', h)}, key=len); print(len(tx)); print(tx[-120:])

