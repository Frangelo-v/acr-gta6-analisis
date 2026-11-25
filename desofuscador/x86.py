# Emula XLBugHandler.dll (x86) con un Windows ficticio. Las DLL reales del sistema solo se leen como datos.
import sys, os, struct, pefile, collections, time
from unicorn import *
from unicorn.x86_const import *
AQUI = os.environ.get('SALIDA', '.')
D = os.environ['MUESTRA']   # carpeta con los .vir
MAXI = int(os.environ.get('MAXI', '400000000')); VER = int(os.environ.get('VER', '1'))
uc = Uc(UC_ARCH_X86, UC_MODE_32)
def al(n, a=0x1000): return (n + a - 1) & ~(a - 1)
MODS = {}; EXP = {}; RANG = []
def carga(ruta, nombre, base=None, datos=False):
    p = pefile.PE(ruta, fast_load=False); ib = p.OPTIONAL_HEADER.ImageBase; base = base or ib
    if base != ib: p.relocate_image(base)
    n = al(p.OPTIONAL_HEADER.SizeOfImage); uc.mem_map(base, n, UC_PROT_ALL)
    img = bytes(p.get_memory_mapped_image(ImageBase=base) if base != ib else p.get_memory_mapped_image()); uc.mem_write(base, img[:n])
    if base == ib: uc.mem_write(base, p.header[:4096] if len(p.header) else b'')
    MODS[nombre.lower()] = (base, n, p)
    if hasattr(p, 'DIRECTORY_ENTRY_EXPORT'):
        for e in p.DIRECTORY_ENTRY_EXPORT.symbols:
            if e.name: EXP[base + e.address] = (nombre, e.name.decode())
    if datos: RANG.append((base, base + n, nombre))
    return p, base
SW = r'C:\Windows\SysWOW64'
carga(SW + r'\ntdll.dll', 'ntdll.dll', 0x77000000, True); carga(SW + r'\kernel32.dll', 'KERNEL32.DLL', 0x76000000, True); carga(SW + r'\kernelbase.dll', 'KERNELBASE.dll', 0x75000000, True)
pe, BASE = carga(D + r'\XLBugHandler.dll.vir', 'XLBugHandler.dll', 0x10000000)
pex, EXB = carga(D + r'\DassmMQOJ.exe.vir', 'DassmMQOJ.exe', 0x400000)
EXTRA = ['advapi32.dll', 'user32.dll', 'shlwapi.dll', 'gdi32.dll', 'ole32.dll', 'combase.dll', 'rpcrt4.dll', 'sechost.dll', 'msvcrt.dll', 'shell32.dll', 'win32u.dll']
for i_, k_ in enumerate(EXTRA): carga(SW + chr(92) + k_, k_, 0x50000000 + i_ * 0x1000000, True)
# pila, heap, TEB/PEB
ST = 0x00200000 - 0x100000; uc.mem_map(0x00100000, 0x100000);
HEAP = 0x20000000; uc.mem_map(HEAP, 0x8000000); hp = [HEAP + 0x1000]; tam = {}
TEB = 0x7FFD0000; PEB = 0x7FFD3000; uc.mem_map(0x7FFD0000, 0x10000); uc.mem_map(0x7FFE0000, 0x1000, UC_PROT_READ)
LDR = 0x7FFD5000
def w32(a, v): uc.mem_write(a, struct.pack('<I', v & 0xFFFFFFFF))
def r32(a): return struct.unpack('<I', uc.mem_read(a, 4))[0]
def aloc(n, z=True):
    n = max(n, 1); a = hp[0]; hp[0] += al(n, 16) + 16; tam[a] = n
    if hp[0] > HEAP + 0x8000000: raise Exception('sin heap')
    return a
def cad(a, w=False, m=600):
    if not a: return None
    o = b''
    try:
        while len(o) < m:
            c = bytes(uc.mem_read(a + len(o), 2 if w else 1))
            if not any(c): break
            o += c
    except UcError: pass
    return o.decode('utf-16le' if w else 'latin1', 'replace')
def ustr(s):
    b = s.encode('utf-16le'); a = aloc(len(b) + 2); uc.mem_write(a, b + b'\0\0'); return a, len(b)
w32(TEB, 0xFFFFFFFF); w32(TEB + 4, 0x00200000); w32(TEB + 8, 0x00100000); w32(TEB + 0x18, TEB); w32(TEB + 0x20, 4321); w32(TEB + 0x24, 1234); w32(TEB + 0x30, PEB); w32(TEB + 0xC0, 0x70FFF000); w32(TEB + 0x2C, TEB + 0x1800)
w32(PEB + 8, EXB); w32(PEB + 0xC, LDR); w32(PEB + 0x18, 0x1230000); w32(PEB + 0xA4, 10); w32(PEB + 0xA8, 0); uc.mem_write(PEB + 0xAC, struct.pack('<H', 26300)); w32(PEB + 0x64, 8)
PP = 0x7FFD7000; w32(PEB + 0x10, PP);
for off, s in ((0x38, 'C:\\Users\\u\\AppData\\Local\\Temp\\t\\DassmMQOJ.exe'), (0x40, '"C:\\Users\\u\\AppData\\Local\\Temp\\t\\DassmMQOJ.exe"')):
    a, n = ustr(s); uc.mem_write(PP + off, struct.pack('<HHI', n, n + 2, a))
orden = ['dassmmqoj.exe', 'ntdll.dll', 'kernel32.dll', 'kernelbase.dll', 'xlbughandler.dll'] + EXTRA; ents = []
for i, n in enumerate(orden):
    e = 0x7FFD9000 + i * 0x80; ents.append(e); b, s, p = MODS[n]; real = {'kernel32.dll': 'KERNEL32.DLL', 'kernelbase.dll': 'KERNELBASE.dll', 'dassmmqoj.exe': 'DassmMQOJ.exe', 'xlbughandler.dll': 'XLBugHandler.dll'}.get(n, n)
    w32(e + 0x18, b); w32(e + 0x1C, b + p.OPTIONAL_HEADER.AddressOfEntryPoint); w32(e + 0x20, s); a, l = ustr('C:\\Windows\\SysWOW64\\' + real); uc.mem_write(e + 0x24, struct.pack('<HHI', l, l + 2, a)); a, l = ustr(real); uc.mem_write(e + 0x2C, struct.pack('<HHI', l, l + 2, a))
w32(LDR, 0x30); w32(LDR + 4, 1)
for k, off in ((0, 0xC), (8, 0x14), (0x10, 0x1C)):
    L = [LDR + off] + [e + k for e in ents]
    for i, x in enumerate(L): w32(x, L[(i + 1) % len(L)]); w32(x + 4, L[i - 1])
uc.mem_map(0x1230000, 0x2000); w32(0x1230040, 2)
# GDT para FS
GDT = 0x7FFDF000
def desc(b, l, acc, fl): return struct.pack('<Q', (l & 0xFFFF) | ((b & 0xFFFFFF) << 16) | (acc << 40) | (((l >> 16) & 0xF) << 48) | (fl << 52) | ((b >> 24) << 56))
uc.mem_write(GDT, b'\0' * 8 + desc(0, 0xFFFFF, 0x9B, 0xC) + desc(0, 0xFFFFF, 0x93, 0xC) + desc(TEB, 0xFFFFF, 0x93, 0x4) + desc(0, 0xFFFFF, 0x97, 0xC))
uc.reg_write(UC_X86_REG_GDTR, (0, GDT, 0x1000, 0))
uc.reg_write(UC_X86_REG_CS, 0x08); uc.reg_write(UC_X86_REG_DS, 0x10); uc.reg_write(UC_X86_REG_ES, 0x10); uc.reg_write(UC_X86_REG_GS, 0x10); uc.reg_write(UC_X86_REG_SS, 0x20); uc.reg_write(UC_X86_REG_FS, 0x18)
# trampolines de importacion
STUB = 0x70000000; uc.mem_map(STUB, 0x1000000); ns = [STUB + 0x1000]; SN = {}; porn = {}
def stub(n):
    if n not in porn: porn[n] = ns[0]; SN[ns[0]] = n; ns[0] += 16; uc.mem_write(porn[n], b'\xc3' * 16)
    return porn[n]
for e in pe.DIRECTORY_ENTRY_IMPORT:
    for i in e.imports: w32(i.address - pe.OPTIONAL_HEADER.ImageBase + BASE if i.address < BASE else i.address, stub((i.name or b'?').decode()))
FIN = stub('__FIN__')
CNT = collections.Counter(); tls = {}; nt = [1]; last = [0]; EVT = []
N = {}   # nombre -> (numero de argumentos, funcion)
def api(n, k):
    def d(f): N[n] = (k, f); return f
    return d
def simple(n, k, v): N[n] = (k, (lambda *a: v))
for n, k, v in (('GetProcessHeap', 0, 0x1230000), ('GetCurrentProcess', 0, 0xFFFFFFFF), ('GetCurrentThread', 0, 0xFFFFFFFE), ('GetCurrentProcessId', 0, 4321), ('GetCurrentThreadId', 0, 1234), ('IsDebuggerPresent', 0, 0), ('IsProcessorFeaturePresent', 1, 1), ('SetUnhandledExceptionFilter', 1, 0), ('InitializeSListHead', 1, 0), ('InterlockedFlushSList', 1, 0), ('EnterCriticalSection', 1, 0), ('LeaveCriticalSection', 1, 0), ('DeleteCriticalSection', 1, 0), ('InitializeCriticalSectionEx', 3, 1), ('InitializeCriticalSectionAndSpinCount', 2, 1), ('AcquireSRWLockExclusive', 1, 0), ('ReleaseSRWLockExclusive', 1, 0), ('TryAcquireSRWLockExclusive', 1, 1), ('GetACP', 0, 1252), ('GetOEMCP', 0, 437), ('IsValidCodePage', 1, 1), ('GetStdHandle', 1, 0), ('GetFileType', 1, 0), ('FreeEnvironmentStringsW', 1, 1), ('CloseHandle', 1, 1), ('IsThreadAFiber', 0, 0), ('CreateMutexA', 3, 0x44), ('ReleaseMutex', 1, 1), ('WaitForSingleObject', 2, 0), ('WaitForSingleObjectEx', 3, 0), ('SetLastError', 1, 0), ('GetConsoleMode', 2, 0), ('FreeLibrary', 1, 1), ('Sleep', 1, 0), ('SleepEx', 2, 0), ('InitOnceBeginInitialize', 4, 1), ('InitOnceComplete', 3, 1), ('FlushInstructionCache', 3, 1), ('RtlUnwind', 4, 0), ('SetErrorMode', 1, 0), ('HeapSetInformation', 4, 1), ('SetStdHandle', 2, 1), ('WriteFile', 5, 1), ('NtClose', 1, 0)): simple(n, k, v)
for p_ in ('Tls', 'Fls'):
    N[p_ + 'Alloc'] = (0 if p_ == 'Tls' else 1, lambda *a: (nt.__setitem__(0, nt[0] + 1), nt[0])[1]); N[p_ + 'Free'] = (1, lambda i: 1)
    N[p_ + 'GetValue'] = (1, lambda i: tls.get(i, 0)); N[p_ + 'SetValue'] = (2, lambda i, v: (tls.__setitem__(i, v), 1)[1])
N['FlsGetValue2'] = N['FlsGetValue']
N['GetLastError'] = (0, lambda: last[0])
N['EncodePointer'] = N['DecodePointer'] = (1, lambda x: x)
N['HeapAlloc'] = N['RtlAllocateHeap'] = (3, lambda h, f, n: aloc(n)); N['HeapFree'] = N['RtlFreeHeap'] = (3, lambda h, f, a: 1); N['HeapSize'] = (3, lambda h, f, a: tam.get(a, 0))
def rea(h, f, a, n):
    q = aloc(n); uc.mem_write(q, bytes(uc.mem_read(a, min(n, tam.get(a, 0))))) if a else None; return q
N['HeapReAlloc'] = N['RtlReAllocateHeap'] = (4, rea)
N['LocalAlloc'] = N['GlobalAlloc'] = (2, lambda f, n: aloc(n)); N['LocalFree'] = N['GlobalFree'] = (1, lambda a: 0)
def va(a, n, t, p): q = (hp.__setitem__(0, al(hp[0])), aloc(n))[1]; EVT.append(('VA', q, n, p)); return q
N['VirtualAlloc'] = (4, va); N['VirtualAllocEx'] = (5, lambda h, a, n, t, p: va(a, n, t, p)); N['VirtualFree'] = (3, lambda a, n, t: 1)
def vp(a, n, p, o): w32(o, 4); EVT.append(('VP', a, n, p)); return 1
N['VirtualProtect'] = (4, vp); N['VirtualProtectEx'] = (5, lambda h, a, n, p, o: vp(a, n, p, o))
def ntva(h, pa, z, ps, t, p): q = va(0, r32(ps), t, p); w32(pa, q); return 0
N['NtAllocateVirtualMemory'] = N['ZwAllocateVirtualMemory'] = (6, ntva)
def ntvp(h, pa, ps, p, o): w32(o, 4); EVT.append(('NVP', r32(pa), r32(ps), p)); return 0
N['NtProtectVirtualMemory'] = N['ZwProtectVirtualMemory'] = (5, ntvp)
def gmh(n):
    if not n: return EXB
    n = n.lower().split('\\')[-1]; n = n if '.' in n else n + '.dll'
    return MODS[n][0] if n in MODS else 0
N['GetModuleHandleA'] = (1, lambda a: gmh(cad(a))); N['GetModuleHandleW'] = (1, lambda a: gmh(cad(a, 1)))
fal = {}
def ll(n):
    b = gmh(n)
    if b: return b
    k = n.lower().split('\\')[-1]; k = k if '.' in k else k + '.dll'
    f = SW + '\\' + k
    if 'azfan' in k: f = D + r'\XLBugHandlerazfanugogos.dll.vir'
    if k.startswith(('api-', 'ext-')): return 0
    if os.path.exists(f):
        base = 0x60000000 + len(fal) * 0x1000000; fal[k] = base; carga(f, k, base, True); print('   [carga', k, hex(base), ']'); return base
    return 0
N['LoadLibraryA'] = (1, lambda a: ll(cad(a))); N['LoadLibraryW'] = (1, lambda a: ll(cad(a, 1))); N['LoadLibraryExW'] = (3, lambda a, h, f: ll(cad(a, 1))); N['LoadLibraryExA'] = (3, lambda a, h, f: ll(cad(a)))
def gpa(h, n):
    s = cad(n) if n > 0xFFFF else '#%d' % n
    if s in N or True:
        for a, (m, x) in EXP.items():
            if x == s and (MODS[m.lower()][0] == h): return a
    return 0
N['GetProcAddress'] = (2, gpa)
def gmhe(f, n, ph, w=False): w32(ph, BASE if f & 4 else gmh(cad(n, w))); return 1
N['GetModuleHandleExW'] = (3, lambda f, n, p: gmhe(f, n, p, True)); N['GetModuleHandleExA'] = (3, gmhe)
def gmf(h, b, n, w=False):
    s = 'C:\\Users\\u\\AppData\\Local\\Temp\\t\\' + ('XLBugHandler.dll' if h == BASE else 'DassmMQOJ.exe'); uc.mem_write(b, (s + '\0').encode('utf-16le' if w else 'latin1')); return len(s)
N['GetModuleFileNameA'] = (3, gmf); N['GetModuleFileNameW'] = (3, lambda h, b, n: gmf(h, b, n, True))
def qpc(a): uc.mem_write(a, struct.pack('<Q', 123456789012)); return 1
N['QueryPerformanceCounter'] = N['QueryPerformanceFrequency'] = (1, qpc); N['GetSystemTimeAsFileTime'] = N['GetSystemTimePreciseAsFileTime'] = (1, lambda a: (uc.mem_write(a, struct.pack('<Q', 134400000000000000)), 0)[1])
N['GetTickCount'] = (0, lambda: 5000000); N['GetTickCount64'] = (0, lambda: 5000000)
cl = aloc(200); uc.mem_write(cl, b'"C:\\Users\\u\\AppData\\Local\\Temp\\t\\DassmMQOJ.exe"\0'); clw = ustr('"C:\\Users\\u\\AppData\\Local\\Temp\\t\\DassmMQOJ.exe"')[0]
simple('GetCommandLineA', 0, cl); simple('GetCommandLineW', 0, clw)
env = aloc(64); uc.mem_write(env, 'A=B\0\0'.encode('utf-16le')); simple('GetEnvironmentStringsW', 0, env)
simple('GetEnvironmentVariableW', 3, 0); simple('GetEnvironmentVariableA', 3, 0)
def si(a): uc.mem_write(a, struct.pack('<I', 68) + b'\0' * 64); return 0
N['GetStartupInfoW'] = (1, si); N['GetCPInfo'] = (2, lambda c, a: (uc.mem_write(a, struct.pack('<I', 1) + b'?\0' + b'\0' * 12), 1)[1])
def mbw(cp, f, s, n, d, dn):
    b = bytes(uc.mem_read(s, n)) if n != 0xFFFFFFFF else cad(s, 0, 100000).encode('latin1') + b'\0'
    t = b.decode('latin1').encode('utf-16le')
    if dn: uc.mem_write(d, t[:dn * 2])
    return len(t) // 2
N['MultiByteToWideChar'] = (6, mbw)
def wmb(cp, f, s, n, d, dn, x, y):
    b = bytes(uc.mem_read(s, n * 2)) if n != 0xFFFFFFFF else cad(s, 1).encode('utf-16le') + b'\0\0'
    t = b.decode('utf-16le', 'replace').encode('latin1', 'replace')
    if dn: uc.mem_write(d, t[:dn])
    return len(t)
N['WideCharToMultiByte'] = (8, wmb)
N['LCMapStringW'] = (6, lambda l, f, s, n, d, dn: ((uc.mem_write(d, bytes(uc.mem_read(s, n * 2))) if dn else 0), n)[1]); N['LCMapStringEx'] = (9, lambda l, f, s, n, d, dn, x, y, z: ((uc.mem_write(d, bytes(uc.mem_read(s, n * 2))) if dn else 0), n)[1])
N['GetStringTypeW'] = (4, lambda t, s, n, o: (uc.mem_write(o, b'\0\0' * n), 1)[1])
N['lstrlenW'] = (1, lambda a: len(cad(a, 1)))
def stop(*a): print('EXIT', a); uc.emu_stop(); return 0
N['ExitProcess'] = (1, stop); N['TerminateProcess'] = (2, stop)
N['RaiseException'] = (4, lambda *a: stop('raise', [hex(x) for x in a])); N['GetCurrentDirectoryW'] = (2, lambda n, b: (uc.mem_write(b, 'C:\\x\0'.encode('utf-16le')), 4)[1])
simple('AreFileApisANSI', 0, 1); simple('AppPolicyGetProcessTerminationMethod', 2, 0xC0000225)
def nqip(h, c, b, n, r):
    if c == 7: w32(b, 0)
    elif c == 0x1E: return 0xC0000353
    elif c == 0x1F: w32(b, 1)
    elif c == 0: uc.mem_write(b, struct.pack('<6I', 0, PEB, 1, 8, 4321, 999))
    else: uc.mem_write(b, b'\0' * min(n, 64))
    if r: w32(r, n)
    return 0
N['NtQueryInformationProcess'] = (5, nqip)
N['NtSetInformationThread'] = (4, lambda h, c, b, n: 0xC0000004 if n else 0); simple('NtQueryObject', 5, 0xC0000008); simple('NtDelayExecution', 2, 0)
def nfree(h, pa, ps, t): return 0
N['NtFreeVirtualMemory'] = (4, nfree)
def nwvm(h, a, b, n, r):
    uc.mem_write(a, bytes(uc.mem_read(b, n))); EVT.append(('NWVM', a, n, h));
    if r: w32(r, n)
    return 0
N['NtWriteVirtualMemory'] = (5, nwvm)
def nrvm(h, a, b, n, r):
    try: uc.mem_write(b, bytes(uc.mem_read(a, n)))
    except UcError: return 0xC0000005
    if r: w32(r, n)
    return 0
N['NtReadVirtualMemory'] = (5, nrvm)
def nqit(h, c, b, n, r):
    if c == 0x11:
        if n != 1: return 0xC0000004
        uc.mem_write(b, b'\1')
    if r: w32(r, n)
    return 0
N['NtQueryInformationThread'] = (5, nqit)
def nqsi(c, b, n, r):
    if c == 0x23: uc.mem_write(b, b'\0\1'[:max(0, min(n, 2))]);
    elif n: uc.mem_write(b, b'\0' * min(n, 256))
    if r: w32(r, 2 if c == 0x23 else n)
    return 0
N['NtQuerySystemInformation'] = (4, nqsi)
def ngct(h, c): return 0
N['NtGetContextThread'] = (2, ngct); N['GetThreadContext'] = (2, lambda h, c: 1)
simple('NtSetContextThread', 2, 0); simple('NtYieldExecution', 0, 0x40000024); simple('NtQueryPerformanceCounter', 2, 0)
N['NtQuerySystemTime'] = (1, lambda a: (uc.mem_write(a, struct.pack('<Q', 134400000000000000)), 0)[1])
simple('CheckRemoteDebuggerPresent', 2, 1); simple('OutputDebugStringA', 1, 0); simple('OutputDebugStringW', 1, 0)
simple('NtOpenFile', 6, 0xC0000034); simple('NtOpenKey', 3, 0xC0000034); simple('NtTerminateProcess', 2, 0)
def gfa(a, w=True):
    s = (cad(a, w) or '').lower(); return 0x10 if s.rstrip('\\').endswith(('windows', 'system32', 'syswow64', 'temp', 'appdata')) else 0x20 if s.endswith(('ntdll.dll', 'kernel32.dll', 'dassmmqoj.exe', 'kernelbase.dll')) else 0xFFFFFFFF
N['GetFileAttributesW'] = (1, gfa); N['GetFileAttributesA'] = (1, lambda a: gfa(a, False))
def nofile(*a): last[0] = 2; return 0xFFFFFFFF
N['CreateFileW'] = (7, nofile); N['CreateFileA'] = (7, nofile); N['FindFirstFileW'] = (2, nofile); N['FindFirstFileExW'] = (6, nofile)
def gsi(a): uc.mem_write(a, struct.pack('<IIIIIIIIHH', 0, 4096, 0x10000, 0x7FFEFFFF, 255, 8, 586, 65536, 6, 0)); return 0
N['GetSystemInfo'] = N['GetNativeSystemInfo'] = (1, gsi)
def gms(a): uc.mem_write(a, struct.pack('<IIQQQQQQQ', 64, 40, 16 << 30, 9 << 30, 32 << 30, 20 << 30, 2 << 30, 1 << 30, 0)); return 1
N['GlobalMemoryStatusEx'] = (1, gms)
def gs(b, n, w): s = 'C:\\Windows\\System32'; uc.mem_write(b, (s + '\0').encode('utf-16le' if w else 'latin1')); return len(s)
N['GetSystemDirectoryW'] = N['GetSystemDirectoryA'] = None
N['GetSystemDirectoryW'] = (2, lambda b, n: gs(b, n, 1)); N['GetSystemDirectoryA'] = (2, lambda b, n: gs(b, n, 0)); N['GetWindowsDirectoryW'] = (2, lambda b, n: (uc.mem_write(b, 'C:\\Windows\0'.encode('utf-16le')), 10)[1])
def gcn(b, pn, w): s = 'LAPTOP-PRUEBA1'; uc.mem_write(b, (s + '\0').encode('utf-16le' if w else 'latin1')); w32(pn, len(s)); return 1
N['GetComputerNameW'] = (2, lambda b, p: gcn(b, p, 1)); N['GetUserNameW'] = (2, lambda b, p: gcn(b, p, 1)); N['GetComputerNameA'] = (2, lambda b, p: gcn(b, p, 0))
simple('GetSystemMetrics', 1, 1920); simple('GetDesktopWindow', 0, 0x10010); simple('GetModuleHandleA_', 1, 0); simple('CreateToolhelp32Snapshot', 2, 0xFFFFFFFF); simple('GetDiskFreeSpaceExW', 4, 1); simple('GetLogicalDrives', 0, 4); simple('GetDriveTypeW', 1, 3)
simple('IsWow64Process', 2, 1); simple('CreateMutexW', 3, 0x48); simple('OpenMutexW', 3, 0); simple('GetUserDefaultLangID', 0, 0x80A); simple('GetUserDefaultUILanguage', 0, 0x80A); simple('GetSystemDefaultLangID', 0, 0x80A); simple('GetKeyboardLayout', 1, 0x080A080A); simple('GetUserDefaultLCID', 0, 0x80A)
TK = [5000000]
def nde(a, p):
    q = struct.unpack('<q', uc.mem_read(p, 8))[0]; TK[0] += max(1, (-q if q < 0 else 0) // 10000); return 0
N['NtDelayExecution'] = (2, nde); N['Sleep'] = (1, lambda m: TK.__setitem__(0, TK[0] + m))
N['GetTickCount'] = N['GetTickCount64'] = (0, lambda: TK[0] & 0xFFFFFFFF)
def qpc2(a): uc.mem_write(a, struct.pack('<Q', TK[0] * 10000)); return 1
N['QueryPerformanceCounter'] = (1, qpc2); N['QueryPerformanceFrequency'] = (1, lambda a: (uc.mem_write(a, struct.pack('<Q', 10000000)), 1)[1])
N['GetSystemTimeAsFileTime'] = N['GetSystemTimePreciseAsFileTime'] = (1, lambda a: (uc.mem_write(a, struct.pack('<Q', 134400000000000000 + TK[0] * 10000)), 0)[1])
def rok(h, s, o, sa, ph): print('     clave', cad(s, 1)); return 2
N['RegOpenKeyExW'] = (5, rok); N['RegOpenKeyExA'] = (5, lambda h, s, o, sa, ph: 2); simple('RegCloseKey', 1, 0); simple('RegQueryValueExW', 6, 2); simple('RegEnumKeyExW', 8, 259)
simple('NtQuerySystemInformationEx', 6, 0xC0000003); simple('NtSetInformationProcess', 4, 0); simple('NtFlushInstructionCache', 3, 0); simple('NtOpenSection', 3, 0xC0000034); simple('NtTestAlert', 0, 0)
def vq(a, b, n):
    for nm, (bs, sz, p) in MODS.items():
        if bs <= a < bs + sz:
            s = [s for s in p.sections if bs + s.VirtualAddress <= a < bs + s.VirtualAddress + al(s.Misc_VirtualSize)]
            st, ln, pr = (bs + s[0].VirtualAddress, al(s[0].Misc_VirtualSize), 0x20 if s[0].Characteristics & 0x20000000 else 4 if s[0].Characteristics & 0x80000000 else 2) if s else (bs, 0x1000, 2)
            pg = a & ~0xFFF; uc.mem_write(b, struct.pack('<7I', pg, bs, 0x80, st + ln - pg, 0x1000, pr, 0x1000000)); return 28
    pg = a & ~0xFFF; uc.mem_write(b, struct.pack('<7I', pg, pg, 4, 0x1000, 0x1000, 4, 0x20000)); return 28
N['VirtualQuery'] = (3, vq); N['VirtualQueryEx'] = (4, lambda h, a, b, n: vq(a, b, n))
def nqvm(h, a, c, b, n, r):
    if c == 0: vq(a, b, n)
    else: return 0xC0000003
    if r: w32(r, 28)
    return 0
N['NtQueryVirtualMemory'] = (6, nqvm)
for n_, k_, v_ in (('AddVectoredExceptionHandler', 2, 0x77), ('RtlAddVectoredExceptionHandler', 2, 0x77), ('RemoveVectoredExceptionHandler', 1, 1), ('RtlRemoveVectoredExceptionHandler', 1, 1), ('NtContinue', 2, 0), ('CreateThread', 6, 0x99), ('NtCreateThreadEx', 11, 0), ('NtResumeThread', 2, 0), ('NtWaitForSingleObject', 3, 0), ('NtSetEvent', 2, 0), ('NtCreateEvent', 5, 0), ('TlsFree', 1, 1), ('GetThreadId', 1, 1234), ('SwitchToThread', 0, 0), ('GetConsoleWindow', 0, 0), ('FreeConsole', 0, 1), ('ShowWindow', 2, 0), ('CoInitializeEx', 2, 0), ('GetThreadLocale', 0, 0x80A), ('GetSystemDefaultUILanguage', 0, 0x80A), ('NtQueryDefaultLocale', 2, 0), ('NtQueryDefaultUILanguage', 1, 0)): simple(n_, k_, v_)
def puerta(u, a, s, d):
    esp = u.reg_read(UC_X86_REG_ESP)
    u.reg_write(UC_X86_REG_EAX, PEB if a == 0x20fdf878 else r32(TEB + 0xC0)); u.reg_write(UC_X86_REG_EIP, r32(esp)); u.reg_write(UC_X86_REG_ESP, esp + 4)
for a_ in (0x20fdf878, 0x20fdf8c8): uc.hook_add(UC_HOOK_CODE, puerta, None, a_, a_)
INTN = [0]; NAT = {}
LADR = []
def hl(u, a, s, d):
    if not LADR: LADR.append(a); print('>>> ENTRA AL LADRON en', hex(a), 'esp', hex(u.reg_read(UC_X86_REG_ESP)), [hex(r32(u.reg_read(UC_X86_REG_ESP) + 4 * q)) for q in range(5)], flush=True)
uc.hook_add(UC_HOOK_BLOCK, hl, None, 0x20f70000, 0x20f70000 + 0xd8000)
silen = {'HeapAlloc', 'HeapFree', 'TlsGetValue', 'TlsSetValue', 'FlsGetValue', 'FlsSetValue', 'GetLastError', 'SetLastError', 'EnterCriticalSection', 'LeaveCriticalSection', 'HeapReAlloc', 'GetProcessHeap', 'RtlAllocateHeap', 'RtlFreeHeap', 'FlsGetValue2', 'HeapSize', 'AcquireSRWLockExclusive', 'ReleaseSRWLockExclusive', 'InitializeCriticalSectionEx'}
desc_ = []
def atiende(n):
    esp = uc.reg_read(UC_X86_REG_ESP); ret = r32(esp); CNT[n] += 1
    if n[:2] == 'Zw': n = 'Nt' + n[2:]
    if n not in N:
        print('!! API sin simular:', n, 'desde', hex(ret), [hex(r32(esp + 4 + i * 4)) for i in range(6)], [cad(r32(esp + 4 + i * 4)) if 0x10000 < r32(esp + 4 + i * 4) < 0x7F000000 else None for i in range(3)]); desc_.append(n); uc.emu_stop(); return
    k, f = N[n]; a = [r32(esp + 4 + i * 4) for i in range(k)]
    v = f(*a)
    if VER and n not in silen and CNT[n] < 40: print('  %-28s %s = %s  <- %x' % (n, [hex(x) if x < 0x10000 or x > 0x7F000000 else (repr(cad(x, n.endswith('W'), 60)) if n[-1] in 'AW' or n in ('GetProcAddress',) else hex(x)) for x in a], hex(v) if isinstance(v, int) else v, ret), flush=True)
    uc.reg_write(UC_X86_REG_EAX, (v or 0) & 0xFFFFFFFF); uc.reg_write(UC_X86_REG_ESP, esp + 4 + k * 4); uc.reg_write(UC_X86_REG_EIP, ret)
def hcode(u, a, s, d):
    if a == FIN: uc.emu_stop(); return
    if a in SN: atiende(SN[a]); return
    if a in EXP: atiende(EXP[a][1]); return
    import bisect
    global EXS
    if 'EXS' not in globals(): EXS = sorted(EXP)
    i = bisect.bisect_right(EXS, a) - 1; n = EXP[EXS[i]][1]
    if a - EXS[i] < 64 and n[:2] in ('Nt', 'Zw'):
        # llamada indirecta: eax trae el numero de servicio real
        ssn = uc.reg_read(UC_X86_REG_EAX)
        if 'SSN' not in globals():
            globals()['SSN'] = {}
            for x in EXS:
                if EXP[x][1][:2] == 'Nt' and uc.mem_read(x, 1)[0] == 0xB8: SSN[r32(x + 1)] = EXP[x][1]
        atiende(SSN.get(ssn, n)); return
    esp = uc.reg_read(UC_X86_REG_ESP); ret = r32(esp); NAT.get(a) or print('interno', hex(a), n, hex(a - EXS[i]), 'ret', hex(ret), 'ecx', hex(uc.reg_read(UC_X86_REG_ECX)), 'edx', hex(uc.reg_read(UC_X86_REG_EDX)), [hex(r32(esp + 4 * q)) for q in range(1, 5)])
    if a != 0x770487ed and (0x10000000 <= uc.reg_read(UC_X86_REG_EIP) or 1):
        NAT[a] = NAT.get(a, 0) + 1
        return
    if 0x10000000 <= ret < 0x10300000 and INTN[0] < 4:
        INTN[0] += 1; uc.reg_write(UC_X86_REG_EAX, 0); uc.reg_write(UC_X86_REG_ESP, esp + 4); uc.reg_write(UC_X86_REG_EIP, ret); return
    print('ejecucion en sistema sin export', hex(a), n, hex(a - EXS[i])); uc.emu_stop()
uc.hook_add(UC_HOOK_CODE, hcode, None, STUB, STUB + 0xFFFFFF)
uc.hook_add(UC_HOOK_CODE, hcode, None, 0x50000000, 0x5FFFFFFF); uc.hook_add(UC_HOOK_CODE, hcode, None, 0x75000000, 0x77FFFFFF); uc.hook_add(UC_HOOK_CODE, hcode, None, 0x60000000, 0x6FFFFFFF)
def hmem(u, t, a, s, v, d):
    print('MEM', {16: 'R', 19: 'R', 20: 'W', 21: 'F', 17: 'W', 18: 'F'}.get(t, t), hex(a), s, 'eip', hex(uc.reg_read(UC_X86_REG_EIP))); return False
uc.hook_add(UC_HOOK_MEM_UNMAPPED, hmem)
def hint(u, n, d):
    esp = uc.reg_read(UC_X86_REG_ESP); e = uc.reg_read(UC_X86_REG_EIP)
    print('INT', hex(n), hex(e), bytes(uc.mem_read(e, 12)).hex(), [hex(r32(esp + 4 * q)) for q in range(8)], {k: hex(uc.reg_read(getattr(sys.modules['unicorn.x86_const'], 'UC_X86_REG_' + k))) for k in ('EAX', 'EBX', 'ECX', 'EDX', 'ESI', 'EDI', 'EBP')}); uc.emu_stop()
uc.hook_add(UC_HOOK_INTR, hint)
def llama(a, *args):
    esp = 0x001F0000
    for x in reversed(args): esp -= 4; w32(esp, x)
    esp -= 4; w32(esp, FIN); uc.reg_write(UC_X86_REG_ESP, esp); uc.reg_write(UC_X86_REG_EBP, 0x001F8000)
    t = time.time()
    try: uc.emu_start(a, FIN, 0, MAXI)
    except UcError as e: print('UC', e, 'eip', hex(uc.reg_read(UC_X86_REG_EIP)), {n: hex(uc.reg_read(getattr(sys.modules['unicorn.x86_const'], 'UC_X86_REG_' + n))) for n in ('EAX', 'EBX', 'ECX', 'EDX', 'ESI', 'EDI', 'EBP', 'ESP')})
    print('-- fin', hex(uc.reg_read(UC_X86_REG_EIP)), 'eax', hex(uc.reg_read(UC_X86_REG_EAX)), '%.1fs' % (time.time() - t)); return uc.reg_read(UC_X86_REG_EAX)
def vuelca():
    open(AQUI + '/uni_heap.bin', 'wb').write(bytes(uc.mem_read(HEAP, al(hp[0] - HEAP)))); open(AQUI + '/uni_img.bin', 'wb').write(bytes(uc.mem_read(BASE, MODS['xlbughandler.dll'][1])))
    print('heap usado', hex(hp[0] - HEAP)); [print('  ', e[0], hex(e[1]), hex(e[2]), hex(e[3])) for e in EVT[-30:]]; print(CNT.most_common(25))
if __name__ == '__main__':
    print('== DllMain'); llama(BASE + pe.OPTIONAL_HEADER.AddressOfEntryPoint, BASE, 1, 0)
    if not desc_:
        print('== SetBugReportRootDir'); ar, _ = ustr('C:\\Users\\u\\AppData'); r = llama(BASE + 0x1090, ar)
    vuelca()







