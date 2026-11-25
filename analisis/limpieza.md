# Qué buscar

Tareas programadas:

- `DeskSessionService`
- `SysAgentRuntime`

Programas instalados:

- "Audio Service Helper" 6.5 (Creative Technology)
- "Storage Controller Service" 7.0 (Marvell)

Procesos: `MSBuild.exe` corriendo sin que estés compilando nada, sobre todo si no está en la carpeta de .NET de
Windows. Los suyos vienen en su carpeta y la firma no cuadra (HashMismatch).

Archivos: `MonoOptions.wsf`, `FinancialReporting.wsf`, `Resources.resx` de más de 20 MB, `XLBugHandler.dll`.

Se copia en varias carpetas del usuario, así que borrar una no alcanza. Revisa también las exclusiones y directivas de
Windows Defender.

    schtasks /query /fo csv /v | findstr /i "wsf MSBuild"
    powershell "Get-CimInstance Win32_Process -Filter \"name='MSBuild.exe'\" | select ProcessId,CommandLine"
    powershell "Get-MpPreference | select Exclusion*"
