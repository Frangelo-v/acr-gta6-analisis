# fake BCL for cil_emu
import os, struct
import cil_emu as emu
from cil_emu import Arr, Obj, N, L, NetEx, Falta, barr, val, Deleg, Lista

RECURSO = os.environ.get("RESOURCE")  # recurso embebido de la etapa 2, si hace falta
R = open(RECURSO, "rb").read() if RECURSO else b""


class St:
    def __init__(s, d=b""):
        s.d = bytearray(d)
        s.p = 0


def monta(E):
    B = E.BCL
    B["System.Reflection.Assembly::GetManifestResourceStream"] = lambda e, a: St(R)
    B["System.Type::get_Assembly"] = lambda e, a: "ENS"
    B["System.IO.MemoryStream::.ctor"] = lambda e, a: St(
        bytes(a[0].b) if a and isinstance(a[0], Arr) else b""
    )

    def rd(e, a):
        d = a[0].d[a[0].p : a[0].p + a[3]]
        a[1].b[a[2] : a[2] + len(d)] = d
        a[0].p += len(d)
        return len(d)

    def wr(e, a):
        a[0].d += a[1].b[a[2] : a[2] + a[3]]

    B["System.IO.Stream::Read"] = rd
    B["System.IO.Stream::Write"] = wr
    B["System.IO.MemoryStream::ToArray"] = lambda e, a: barr(bytes(a[0].d))
    ENV = {
        "CEDEN_GIRAT_SAD_89d0": "C:\\Users\\u\\AppData\\Local\\Creative\\Storage\\MonoOptions.csproj",
        "VENUK_FENEX_CULAN_fa3e": "8a6d09",
    }
    B["System.Environment::GetEnvironmentVariable"] = lambda e, a: ENV.get(a[0])
    B["System.Environment::SetEnvironmentVariable"] = lambda e, a: ENV.__setitem__(a[0], a[1])
    B["System.Threading.Interlocked::CompareExchange"] = lambda e, a: (
        (lambda o: (a[0].set(a[1]) if o == a[2] else None, o)[1])(a[0].get())
        if isinstance(a[0], emu.Ref)
        else 0
    )
    B["System.Threading.Interlocked::Exchange"] = lambda e, a: (lambda o: (a[0].set(a[1]), o)[1])(a[0].get())
    B["System.Threading.Monitor::Enter"] = lambda e, a: (
        a[1].set(1) if len(a) > 1 and isinstance(a[1], emu.Ref) else None
    )
    B["System.Threading.Monitor::Exit"] = lambda e, a: None
    B["System.Threading.Thread::MemoryBarrier"] = lambda e, a: None
    B["System.Threading.Thread::Sleep"] = lambda e, a: None
    B["System.Threading.Thread::get_CurrentThread"] = lambda e, a: "HILO"
    B["System.Environment::get_TickCount"] = lambda e, a: 123456789
    B["System.Environment::get_ProcessorCount"] = lambda e, a: 8
    B["System.IntPtr::get_Size"] = lambda e, a: 4
    B["System.IntPtr::op_Equality"] = lambda e, a: int(a[0] == a[1])
    B["System.IntPtr::op_Inequality"] = lambda e, a: int(a[0] != a[1])
    B["System.IntPtr::Add"] = lambda e, a: N(a[0] + a[1])
    B["System.Math::Min"] = lambda e, a: min(a)
    B["System.Math::Max"] = lambda e, a: max(a)
    B["System.IO.Path::Combine"] = lambda e, a: "\\".join(x.rstrip("\\") for x in a if x)
    B["System.IO.Path::GetDirectoryName"] = lambda e, a: a[0].rsplit("\\", 1)[0]
    B["System.IO.Path::GetFileName"] = lambda e, a: a[0].rsplit("\\", 1)[-1]

    B["System.AppDomain::get_CurrentDomain"] = lambda e, a: "DOM"
    for q in (
        "add_ProcessExit",
        "add_UnhandledException",
        "add_AssemblyResolve",
        "add_DomainUnload",
        "add_FirstChanceException",
    ):
        B["System.AppDomain::" + q] = lambda e, a: None
    B["System.Threading.Tasks.TaskScheduler::add_UnobservedTaskException"] = lambda e, a: None
    B["System.EventHandler::.ctor"] = lambda e, a: Deleg(a[0], emu.fn(a[1]))
    B["System.Diagnostics.Process::GetCurrentProcess"] = lambda e, a: "PROC"
    B["System.Diagnostics.Process::get_MainModule"] = lambda e, a: "MOD"
    B["System.Diagnostics.Process::get_Id"] = lambda e, a: 4321
    B["System.Diagnostics.ProcessModule::get_FileName"] = (
        lambda e, a: "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe"
    )
    B["System.IO.File::Exists"] = lambda e, a: int(bool(a[0]) and a[0].endswith(".csproj"))
    B["System.IO.Directory::Exists"] = lambda e, a: 1
    B["System.Environment::ExpandEnvironmentVariables"] = (
        lambda e, a: a[0]
        .replace("%APPDATA%", "C:\\Users\\u\\AppData\\Roaming")
        .replace("%SystemRoot%", "C:\\Windows")
    )
    B["System.Environment::get_MachineName"] = lambda e, a: "PC"
    B["System.Environment::get_UserName"] = lambda e, a: "u"
    B["System.Environment::get_Is64BitOperatingSystem"] = lambda e, a: 1
    B["System.Environment::get_Is64BitProcess"] = lambda e, a: 0
    B["System.Environment::GetFolderPath"] = lambda e, a: "C:\\Users\\u\\AppData\\Roaming"
    B["System.String::Trim"] = lambda e, a: a[0].strip()
    B["System.String::Replace"] = lambda e, a: a[0].replace(
        chr(a[1]) if isinstance(a[1], int) else a[1], chr(a[2]) if isinstance(a[2], int) else a[2]
    )
    B["System.String::ToLowerInvariant"] = B["System.String::ToLower"] = lambda e, a: a[0].lower()
    B["System.String::ToUpperInvariant"] = lambda e, a: a[0].upper()
    B["System.String::IsNullOrWhiteSpace"] = lambda e, a: int(not a[0] or not a[0].strip())
    B["System.String::EndsWith"] = lambda e, a: int(a[0].lower().endswith(a[1].lower()))
    B["System.String::StartsWith"] = lambda e, a: int(a[0].lower().startswith(a[1].lower()))
    B["System.String::IndexOf"] = lambda e, a: a[0].find(
        chr(a[1]) if isinstance(a[1], int) else a[1],
        a[2] if len(a) > 2 and isinstance(a[2], int) and a[2] < len(a[0]) else 0,
    )
    B["System.String::LastIndexOf"] = lambda e, a: a[0].rfind(chr(a[1]) if isinstance(a[1], int) else a[1])
    B["System.String::Contains"] = lambda e, a: int(a[1] in a[0])
    B["System.String::Split"] = lambda e, a: Arr(
        None,
        data=__import__("re").split(
            "|".join(
                __import__("re").escape(chr(c)) for c in struct.unpack("<%dH" % (len(a[1].b) // 2), a[1].b)
            ),
            a[0],
        ),
    )
    B["System.String::Format"] = lambda e, a: __import__("re").sub(
        r"\{(\d+)(:[^}]*)?\}",
        lambda m: str((a[1].l if isinstance(a[1], Arr) else a[1:])[int(m.group(1))]),
        a[0],
    )
    B["System.String::Join"] = lambda e, a: a[0].join(
        str(x) for x in (a[1].l if isinstance(a[1], Arr) else a[1])
    )
    B["System.Int32::ToString"] = B["System.Int64::ToString"] = B["System.UInt32::ToString"] = lambda e, a: (
        (("%x" if a[1][0] == "x" else "%X") % (val(a[0]) & 0xFFFFFFFF)).zfill(int(a[1][1:] or 0))
        if len(a) > 1 and isinstance(a[1], str) and a[1][:1] in "xX"
        else str(int(val(a[0])))
    )
    B["System.Byte::ToString"] = B["System.Int32::ToString"]
    B["System.Type::GetType"] = lambda e, a: emu.Tipo(a[0])
    B["System.DateTime::get_UtcNow"] = B["System.DateTime::get_Now"] = lambda e, a: ("dt", 2026, 11, 24)
    B["System.DateTime::get_DayOfYear"] = lambda e, a: 328
    B["System.DateTime::get_Year"] = lambda e, a: 2026
    B["System.DateTime::get_Ticks"] = lambda e, a: L(639000000000000000)
    B["System.Security.Cryptography.RandomNumberGenerator::Create"] = B[
        "System.Security.Cryptography.RNGCryptoServiceProvider::.ctor"
    ] = lambda e, a: "RNG"
    B["System.Security.Cryptography.RandomNumberGenerator::GetBytes"] = lambda e, a: a[1].b.__setitem__(
        slice(None), bytes((i * 37 + 11) & 255 for i in range(len(a[1].b)))
    )
    B["System.Guid::NewGuid"] = lambda e, a: ("guid", bytes(range(16)))
    B["System.Guid::ToString"] = lambda e, a: "00010203040506070809"
    D = "System.Collections.Generic.Dictionary`2::"

    class Dic(dict):
        __hash__ = object.__hash__

    B[D + ".ctor"] = lambda e, a: Dic()
    B[D + "TryGetValue"] = lambda e, a: (a[2].set(a[0].get(a[1])), int(a[1] in a[0]))[1]
    B[D + "set_Item"] = B[D + "Add"] = lambda e, a: a[0].__setitem__(a[1], a[2])
    B[D + "get_Item"] = lambda e, a: a[0][a[1]]
    B[D + "ContainsKey"] = lambda e, a: int(a[1] in a[0])
    B["System.Threading.Mutex::.ctor"] = lambda e, a: "MUTEX"
    B["System.Threading.WaitHandle::WaitOne"] = lambda e, a: 1
    B["System.Threading.ManualResetEvent::.ctor"] = lambda e, a: "MRE"
    B["System.Threading.Thread::.ctor"] = lambda e, a: Obj("Hilo")
    B["System.Threading.Thread::set_IsBackground"] = B["System.Threading.Thread::Start"] = lambda e, a: None
    B["System.Runtime.InteropServices.Marshal::GetLastWin32Error"] = lambda e, a: 0
    B["System.Diagnostics.Stopwatch::StartNew"] = lambda e, a: "SW"
    B["System.Diagnostics.Stopwatch::get_ElapsedMilliseconds"] = lambda e, a: L(5)
    B["System.Reflection.Assembly::GetExecutingAssembly"] = lambda e, a: "ENS"
    B["System.Reflection.Assembly::get_Location"] = lambda e, a: ""

    B["System.AppDomain::IsDefaultAppDomain"] = lambda e, a: 1

    B["System.Object::GetHashCode"] = lambda e, a: 0x1234567

    B["System.Convert::ToInt32"] = lambda e, a: (
        int(a[0], a[1]) if len(a) > 1 and isinstance(a[0], str) else int(a[0])
    )
    B["System.Convert::ToString"] = lambda e, a: str(a[0])
    B["System.Char::ToString"] = lambda e, a: chr(val(a[0]))
