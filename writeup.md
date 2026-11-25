# Fake GTA 6 -> Amatera + proxy + clipper

```
*.uq8jxr[.]cyou
 └ Grand_Theft_Auto_VI_GTA_6_-_*.zip   (*.192169540[.]com)
    ├ DassmMQOJ.exe + XLBugHandler.dll     stealer
    ├ Storage Controller Service 7.0       proxy    ("Marvell")
    └ Audio Service Helper 6.5             clipper  ("Creative Technology")
```

## MSBuild

Las dos carpetas son iguales por dentro, cambian nombres y keys. Parecen un proyecto de C# cualquiera, hasta traen
README, CHANGELOG y LICENSE.

Persistencia con dos tareas, `DeskSessionService` y `SysAgentRuntime`, que abren un .wsf:

```js
env("MSBUILDENABLEALLPROPERTYFUNCTIONS") = "1";
env("MSBUILDDISABLENODEREUSE") = "1";
...
var cmd = "\"" + msb + "\" \"" + csproj + "\" /nologo /v:q /nodereuse:false";
```

Con esa variable las property functions del csproj pueden llamar casi cualquier método de .NET, no hace falta inline
task ni compilar nada.

El payload está en `Resources.resx` (24 MB), en values numerados `Note0xw4`, `Note0xw5`... Es hex con una letra basura
después de cada byte:

```
6egb9gc6gfag1bg81g2bg66g09g...
```

Quitando eso queda RC4. La key es el csproj completo haciendo XOR en bloques de 32, así que si editas el archivo ya no
descifra. Los primeros 4 bytes son checksum (mismo XOR) y sigue el MZ.

## stage2

.NET con VM. Strings inline: `key(1) pad(3) ?(4) len(4) utf16^key`.

Trae 3 archivos con extensión .js que no son js:

```
magic(4) count(4) [ namelen(2) name offset(4) size(4) ] * count
```

En el proxy es un resource (`d1b56c39`), en el clipper es base64 partido en un montón de strings (`d08b4aea`), unpack.py
saca los dos.

## stage3

Otro .NET, RC4 + LZMA. Le pasan un objeto de config y regresa esto:

```
LinPribernex.js|iTmjNaPnLEylOnK|SeigateBrauport.js|VDkHXxEq3VpA
```

| file | rc4 |
|---|---|
| FianBro.js | r3vWWbc0 |
| LinPribernex.js | iTmjNaPnLEylOnK |
| SeigateBrauport.js | VDkHXxEq3VpA |
| HaullstimCiarquuton.js | 1koMm4y4X5U |
| GrifordpiakTheinmiall.js | DdzYH6OU |
| MaurzuxQueinfek.js | zcmdh9gsfeTrmu |

SeigateBrauport es el proxy y Maurzux el clipper. LinPribernex y Grifordpiak no los revisé.

## proxy

Go. Dejaron el path: `github.com/acr/proxy-panel`. C2 `wss://zanakillakill[.]cc/`, manda el MachineGuid.

## clipper

73 KB, x64. BTC, ETH, TRX, TON, SOL, LTC, BCH, DOGE, XRP, DASH, RVN, ALGO, ATOM, ZEC (wallets en iocs.txt).

Mutex `update-S-1-5-26-15297236-4840534596-8490206048-3100`

El C2 sale de un contrato en BSC, llamando a `balanceOf` (0x70a08231) con cualquier address:

```
0xe9D1A9fB1C57a00e8D696FE799cD717c8f311ac9
```

Creado el 16/03/2026 por `0x3a35b409af86e79e8945d6a7ffb1dc59b8dbdf46`, que firma todos los cambios. Van 31 dominios, están
en iocs.txt. La misma wallet escribe en otros dos contratos, que el 25/11 tenían `pulsefit[.]cc` y
`data.nomadhive[.]cc`, no sé de qué son.

## stealer

x86, en memoria, lo carga XLBugHandler.dll. "Realtek HD Audio Manager". En las strings sale `4.6.7-alpha1` y
`Tue Nov  3 19:43:00 2026`. Heaven's Gate, C2 en .cc y ese formato de versión: Amatera casi seguro.

```
tap.cloudlinkbrh[.]cc
tap.safertunnelnye[.]cc
```

Resuelve por DoH (1.0.0.1, 8.8.8.8, dns.google).

Chromium, Firefox, extensiones, Steam (loginusers.vdf, local.vdf), tokens de Cursor y screenshot. De Telegram no hay
nada en las strings pero puede venir en la config del server.

## refs

- https://www.malwarebytes.com/blog/threat-intel/2026/07/fake-games-spread-stealers-with-renpy-loader-msbuild-and-etherhiding
