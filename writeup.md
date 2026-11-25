# Las capas

- [Arranque](#arranque)
- [El resx](#el-resx)
- [Stage2](#stage2)
- [Stage3 y payloads](#stage3-y-payloads)
- [Stealer](#stealer)
- [Proxy](#proxy)
- [Clipper](#clipper)
- [Qué buscar en el equipo](#qué-buscar-en-el-equipo)

Las dos carpetas de MSBuild usan el mismo armado, solo cambian nombres y keys. Tomo de ejemplo la del proxy.

## Arranque

Hay dos tareas programadas, `DeskSessionService` y `SysAgentRuntime`, que al iniciar sesión abren un .wsf. Lo que hace
es esto:

```js
var csproj = dir + "\\MonoOptions.csproj";
env("MSBUILDENABLEALLPROPERTYFUNCTIONS") = "1";
env("MSBUILDDISABLENODEREUSE") = "1";
...
var cmd = "\"" + msb + "\" \"" + csproj + "\" /nologo /v:q /nodereuse:false";
var rc = sh.Run(cmd, 0, true);
```

La primera variable es la importante. Normalmente en un .csproj solo puedes llamar a unas cuantas funciones de .NET desde
una propiedad, y con eso prendido puedes llamar a casi cualquiera. Así corre código sin compilar nada y sin usar inline
tasks, que es lo que suelen vigilar.

El .csproj importa `Build.props`, `Internal.targets` y el `.csproj.user`. La mayoría de lo que traen es relleno para que
parezca un proyecto de verdad: comentarios de NuGet, números de ticket, versiones que no existen.

## El resx

`Resources.resx` pesa 24 MB. Son valores numerados (`Note0xw4`, `Note0xw5`...) con hexadecimal, y entre byte y byte meten
una letra que no es hex para estorbar:

```
6egb9gc6gfag1bg81g2bg66g09g...
```

Se limpia, se junta y queda RC4. La key no está escrita en ningún lado: es el mismo .csproj doblado a 32 bytes con XOR. O
sea que si le cambias un espacio al proyecto deja de funcionar.

Los primeros 4 bytes de lo descifrado son un checksum (el mismo doblado, sobre lo que sigue) y después viene un PE de
.NET.

## Stage2

.NET con código virtualizado. Usa nombres de clases sacados del propio .NET (`System.Net.Mime...`,
`EtwSelfDescribing...`) para despistar. Los strings van metidos así:

```
key(1) pad(3) ?(4) len(4) utf16^key
```

Trae un contenedor con tres ".js" que no son js:

```
magic(4) count(4) [ namelen(2) name offset(4) size(4) ] * count
```

En el proxy el contenedor es un resource (magic `d1b56c39`). En el clipper va en base64 partido en miles de strings
adentro del código (magic `d08b4aea`). `unpack.py` saca los dos.

## Stage3 y payloads

El primer archivo del contenedor es otro .NET, RC4 + LZMA. La stage2 le pasa un objeto de configuración (un bool, un int
y tres strings) y regresa un texto con los otros dos nombres y sus keys:

```
LinPribernex.js|iTmjNaPnLEylOnK|SeigateBrauport.js|VDkHXxEq3VpA
```

Esos también son RC4 + LZMA y ya son los ejecutables finales. El que hace el daño es el segundo.

| archivo | rc4 | |
|---|---|---|
| FianBro.js | r3vWWbc0 | stage3 |
| LinPribernex.js | iTmjNaPnLEylOnK | sin revisar |
| SeigateBrauport.js | VDkHXxEq3VpA | proxy |
| HaullstimCiarquuton.js | 1koMm4y4X5U | stage3 |
| GrifordpiakTheinmiall.js | DdzYH6OU | sin revisar |
| MaurzuxQueinfek.js | zcmdh9gsfeTrmu | clipper |

El stealer va por otro camino: `DassmMQOJ.exe` carga `XLBugHandler.dll`, que lo trae cifrado y lo corre en memoria.

El método se parece al que [describió Malwarebytes en julio](https://www.malwarebytes.com/blog/threat-intel/2026/07/fake-games-spread-stealers-with-renpy-loader-msbuild-and-etherhiding),
aunque los nombres y hashes no son los mismos.

## Stealer

32 bits, se presenta como "Realtek HD Audio Manager". En sus textos salen la versión `4.6.7-alpha1` y la fecha
`Tue Nov  3 19:43:00 2026`. Por el formato de versión, los dominios .cc y que usa Heaven's Gate, casi seguro es Amatera,
el que antes se llamaba ACR Stealer.

Servidores, los dos registrados el mismo día y al mismo minuto:

```
tap.cloudlinkbrh[.]cc
tap.safertunnelnye[.]cc
```

No usa el DNS del equipo, pregunta por DNS cifrado a 1.0.0.1, 8.8.8.8 y dns.google. Bloquear los dominios en el hosts no
lo para.

Lo que busca, según sus propios textos ([strings.txt](strings.txt)):

- Chrome y parecidos: cookies, contraseñas, historial y formularios de todos los perfiles, más la key del `Local State`
- Firefox: `logins.json`, `key4.db`, `cookies.sqlite`, `places.sqlite`, `formhistory.sqlite`
- Extensiones y su almacenamiento (`Local Storage\leveldb`, `storage\default`)
- Steam: `loginusers.vdf`, `local.vdf`
- Cursor: `accessToken` y `refreshToken` de `state.vscdb`
- Captura de pantalla

También trae una lista larga de extensiones de archivo (exe, dll, mp4, iso...). Parece la lista de lo que no le interesa
pero no lo confirmé.

Abre el navegador escondido (`--headless`, `about:blank`, o Firefox con un perfil en `C:\Users\Public\.ff_tmp`).

De Telegram no hay nada en los textos, pero este tipo de stealer puede recibir del servidor qué carpetas copiar, así que
eso no quiere decir que no se lo lleve.

## Proxy

Está en Go y se le quedó la ruta del código: `github.com/acr/proxy-panel`. ACR es también el nombre viejo del stealer,
puede ser casualidad.

Se conecta a `wss://zanakillakill[.]cc/`, se identifica con el `MachineGuid` y deja que otros naveguen por tu internet. Lo
que hagan sale con tu IP, así que si lo tuviste guarda las fechas.

## Clipper

El programa final pesa 73 KB. Se queda mirando el portapapeles y cuando copias una dirección de cripto la cambia por una
suya. Trae para Bitcoin, Ethereum/BNB, Tron, TON, Solana, Litecoin, Bitcoin Cash, Doge, XRP, Dash, Ravencoin, Algorand,
Cosmos y Zcash. Están todas en [iocs.txt](iocs.txt).

Mutex: `update-S-1-5-26-15297236-4840534596-8490206048-3100`

### De dónde saca su servidor

No lo trae escrito. Le pregunta a un contrato de BNB Smart Chain:

```
0xe9D1A9fB1C57a00e8D696FE799cD717c8f311ac9
```

La respuesta de `balanceOf` (0x70a08231), con la dirección que sea, es el dominio en texto. Es lo que llaman EtherHiding:
aunque tumben el dominio escriben otro en el contrato y todos los infectados se enteran solos.

`etherhiding.py` lo lee. Solo consulta un nodo público, no toca el servidor de ellos.

Lo bueno es que en la blockchain queda todo. El contrato se creó el 16/03/2026 y la misma cuenta firmó todos los cambios
(`0x3a35b409af86e79e8945d6a7ffb1dc59b8dbdf46`). Ha tenido 31 dominios, están en iocs.txt con su fecha.

Esa cuenta escribe en otros dos contratos. El 25/11/2026 tenían `pulsefit[.]cc` y `data.nomadhive[.]cc`. No sé qué
programa los usa.

## Qué buscar en el equipo

Tareas programadas: `DeskSessionService` y `SysAgentRuntime`.

Programas instalados: "Audio Service Helper" 6.5 y "Storage Controller Service" 7.0.

Procesos: `MSBuild.exe` corriendo sin que estés compilando nada, sobre todo si no está en la carpeta de .NET de Windows.
Los suyos vienen en su carpeta y la firma no cuadra (HashMismatch).

Archivos: `MonoOptions.wsf`, `FinancialReporting.wsf`, un `Resources.resx` de más de 20 MB, `XLBugHandler.dll`.

Se copia en varias carpetas del usuario, así que borrar una no alcanza. Revisa también las exclusiones y directivas de
Defender.

```
schtasks /query /fo csv /v | findstr /i "wsf MSBuild"
powershell "Get-CimInstance Win32_Process -Filter \"name='MSBuild.exe'\" | select ProcessId,CommandLine"
powershell "Get-MpPreference | select Exclusion*"
```

Para revisar archivos está [rules.yar](rules.yar).
