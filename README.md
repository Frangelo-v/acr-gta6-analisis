# "GTA 6 gratis": stealer + proxy + clipper

Análisis de un zip que se reparte como si fuera GTA 6 (noviembre de 2026). Adentro no hay juego. Lo que instala son tres
cosas distintas: un ladrón de contraseñas, un proxy y un programa que te cambia las direcciones de cripto al copiar.

Aquí están los indicadores, la explicación de cada parte y los scripts que usé para sacarle las capas.
No subo las muestras, los hashes están en [iocs.txt](iocs.txt).

## Si ya lo abriste

1. Desconecta la PC de internet.
2. Desde **otro** aparato cambia contraseñas y cierra todas las sesiones (Google, Telegram, Discord, Steam, bancos).
   Cambiar la contraseña sin cerrar sesiones no alcanza, porque se llevan las cookies.
3. En Telegram: Ajustes > Dispositivos > Cerrar todas las demás sesiones, y pon verificación en dos pasos.
4. Si tenías cripto en extensiones, muévela a una billetera nueva creada en otro equipo.
5. Busca lo que dice [la parte de limpieza](writeup.md#qué-buscar-en-el-equipo). Lo más seguro es formatear.

## Cómo llega

```
página falsa (*.uq8jxr[.]cyou)
 └ Grand_Theft_Auto_VI_GTA_6_-_*.zip        (se baja de *.192169540[.]com)
    ├ DassmMQOJ.exe + XLBugHandler.dll      stealer, Amatera / ACR 4.6.7-alpha1
    ├ "Storage Controller Service"          proxy, dice ser de Marvell
    └ "Audio Service Helper"                clipper, dice ser de Creative
```

Los dos "servicios" son carpetas que parecen un proyecto normal de C#, con su .csproj, README, CHANGELOG y LICENSE. Se
ejecutan con MSBuild, que es de Microsoft, y por eso no llaman la atención.

Todo el detalle está en [writeup.md](writeup.md).

## Scripts

```
pip install -r scripts/requirements.txt
```

| script | qué hace |
|---|---|
| resx_extract.py | saca el PE de .NET escondido en Resources.resx |
| dotnet_strings.py | strings del código virtualizado de la stage2 |
| unpack.py | separa los 3 archivos que trae la stage2 (siguen cifrados) |
| decrypt.py | RC4 + LZMA |
| get_keys.py | keys de los payloads finales, emulando la stage3 |
| etherhiding.py | lee del contrato el C2 actual del clipper |
| stealer_strings.py | strings del stealer con unicorn |

Por ejemplo, para llegar al proxy:

```
python resx_extract.py -d "Storage Controller Service" -o stage2.bin
python unpack.py -f stage2.bin -o out
python decrypt.py -f out/FianBro.js -k r3vWWbc0 -o stage3.bin
python get_keys.py -f stage3.bin
python decrypt.py -f out/SeigateBrauport.js -k VDkHXxEq3VpA -o proxy.bin
```

Ninguno de esos ejecuta el malware. `get_keys.py` usa un intérprete de CIL hecho a mano (`cil_emu.py`) que solo conoce
las funciones de mentira de `bcl_stubs.py`.

`stealer_strings.py` es aparte. Emula la DLL en un Windows inventado y llama a las propias funciones del stealer para
descifrar sus textos. Tiene direcciones fijas, así que solo sirve con esta muestra, y usa las DLL de SysWOW64 (las lee
como datos), o sea que hay que correrlo en Windows:

```
set SAMPLE=C:\ruta\con\los\.vir
python stealer_strings.py
```

Aunque sea emulación, hazlo en una máquina virtual.

Probado con:

```
Storage Controller Service   9db50ddab4741de2d1cc38a3848deb1f398f76bed50cec6e48259420c588e0fb
Audio Service Helper         9ac4e30bf419acf34eb11ff27924941505a5e8a20986561644ceae794523ac87
```

(son los hashes del MSBuild.exe de cada carpeta)

## Qué no sé

- Quién está detrás. Los tres programas vienen en la misma descarga, pero esto se alquila: el que lo reparte y el que
  lo programó pueden no ser el mismo.
- Qué archivos exactos se lleva el stealer en cada caso, porque puede recibir esa lista del servidor.
- Para qué son LinPribernex.js y GrifordpiakTheinmiall.js. Los descifré pero no los revisé.

Si tienes otra muestra de la misma campaña y los scripts fallan abre un issue con el hash (no con el archivo).
