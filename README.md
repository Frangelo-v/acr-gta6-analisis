# "GTA 6 gratis": ladrón + proxy + clipper

Análisis de un zip que se reparte como si fuera GTA 6 (noviembre de 2026). Adentro no hay juego. Lo que instala son
tres cosas distintas: un ladrón de contraseñas, un proxy y un programa que te cambia las direcciones de cripto al copiar.

Aquí están los indicadores, la explicación de cada parte y los scripts que usé para sacarle las capas.
**No hay muestras en este repo.** Los hashes están en `ioc/hashes.csv`.

## Si ya lo abriste

1. Desconecta la PC de internet.
2. Desde **otro** aparato cambia contraseñas y cierra todas las sesiones (Google, Telegram, Discord, Steam, bancos).
   Cambiar la contraseña sin cerrar sesiones no alcanza: se llevan las cookies.
3. En Telegram: Ajustes > Dispositivos > Cerrar todas las demás sesiones, y pon verificación en dos pasos.
4. Si tenías cripto en extensiones, muévela a una billetera nueva creada en otro equipo.
5. Busca lo que dice `analisis/limpieza.md`. Lo más seguro es formatear.

## Cómo llega

    página falsa (*.uq8jxr[.]cyou)
      -> Grand_Theft_Auto_VI_GTA_6_-_...zip  (bajado de *.192169540[.]com)
        -> DassmMQOJ.exe + XLBugHandler.dll          ladrón (Amatera / ACR, 4.6.7-alpha1)
        -> "Storage Controller Service" (Marvell)    proxy
        -> "Audio Service Helper" (Creative)         clipper

Los dos "servicios" son carpetas que parecen un proyecto normal de C#, con su .csproj, README, CHANGELOG y LICENSE.
Se ejecutan con MSBuild, que es de Microsoft, y por eso no llaman la atención.

- [analisis/cadena.md](analisis/cadena.md): las capas, una por una
- [analisis/ladron.md](analisis/ladron.md)
- [analisis/proxy.md](analisis/proxy.md)
- [analisis/clipper.md](analisis/clipper.md): incluye cómo saca su servidor de la blockchain
- [analisis/limpieza.md](analisis/limpieza.md)

## Desofuscador

    pip install -r desofuscador/requirements.txt

    python desofuscador/etapa2.py CARPETA etapa2.bin          # resx -> PE de .NET
    python desofuscador/textos.py etapa2.bin                  # textos del código virtualizado
    python desofuscador/contenedor.py etapa2.bin partes       # archivos cifrados de adentro
    python desofuscador/etapa3.py partes/FianBro.js r3vWWbc0 etapa3.bin
    python desofuscador/llaves.py etapa3.bin                  # llaves de los programas finales
    python desofuscador/etapa3.py partes/SeigateBrauport.js VDkHXxEq3VpA final.bin

Nada de eso ejecuta el malware. `llaves.py` usa un intérprete de CIL (`cil.py`) que solo conoce las funciones puestas a
mano en `bcl.py`, todas de mentira.

`x86.py` es aparte. Emula la DLL del ladrón con Unicorn y un Windows inventado, y `textos_ladron.py` la aprovecha para
descifrar sus textos con sus propias funciones. Está hecho a la medida de esta muestra (direcciones fijas) y lee las
DLL de `SysWOW64` como datos, así que hay que correrlo en Windows:

    set MUESTRA=C:\ruta\con\los\.vir
    python desofuscador\textos_ladron.py

Aunque sea emulación, hazlo en una máquina virtual.

Llaves de estas muestras:

| archivo | llave RC4 |
|---|---|
| FianBro.js | r3vWWbc0 |
| LinPribernex.js | iTmjNaPnLEylOnK |
| SeigateBrauport.js | VDkHXxEq3VpA |
| HaullstimCiarquuton.js | 1koMm4y4X5U |
| GrifordpiakTheinmiall.js | DdzYH6OU |
| MaurzuxQueinfek.js | zcmdh9gsfeTrmu |

## Qué no sé

- Quién está detrás. Los tres programas vienen en la misma descarga, pero esto se alquila: el que lo reparte y el que
  lo programó pueden no ser el mismo.
- Qué archivos exactos se lleva el ladrón en cada caso. Puede recibir esa lista del servidor.
- Para qué sirven LinPribernex.js y GrifordpiakTheinmiall.js. Los descifré pero no los miré a fondo.

Si tienes otra muestra de la misma campaña y los scripts fallan, abre un issue con el hash (no con el archivo).
