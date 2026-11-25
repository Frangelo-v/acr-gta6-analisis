# Las capas

Las dos carpetas de MSBuild usan el mismo armado, solo cambian nombres y llaves. Tomo de ejemplo la del proxy.

**1. Arranque.** Una tarea programada abre `MonoOptions.wsf` al iniciar sesión. El wsf prende
`MSBUILDENABLEALLPROPERTYFUNCTIONS=1` y llama a MSBuild con `MonoOptions.csproj`. Con esa variable un .csproj puede
llamar a casi cualquier método de .NET desde una propiedad, sin compilar nada.

**2. El proyecto.** El .csproj importa `Build.props`, `Internal.targets` y el `.csproj.user`. La mayoría de lo que
traen es relleno para que parezca un proyecto real (comentarios de NuGet, tickets, versiones).

**3. El resx.** `Resources.resx` pesa 24 MB. Son valores numerados (`Note0xw4`, `Note0xw5`...) con hexadecimal, y
entre byte y byte meten una letra que no es hex para estorbar:

    6egb9gc6gfag1bg81g2bg66g09g...

Se limpia, se junta y va en RC4. La llave no está escrita en ningún lado: es el mismo .csproj doblado a 32 bytes con
XOR. O sea que si le cambias un espacio al proyecto deja de funcionar. Los primeros 4 bytes son la suma de control
(el mismo doblado, sobre lo descifrado) y después viene un PE de .NET.

**4. Etapa 2.** .NET con código virtualizado. Los textos están como `[clave][3][4][largo][utf-16 ^ clave]`. Usa nombres
de clases sacados del propio .NET para despistar.

Trae un contenedor con tres "js" que no son js:

    magia (4)   cantidad (4)
    largo del nombre (2)   nombre   posición (4)   tamaño (4)    <- por cada archivo

En el proxy el contenedor es un recurso (magia `d1b56c39`). En el clipper va en base64 partido en miles de textos
adentro del código (magia `d08b4aea`).

**5. Etapa 3.** El primer archivo es otro .NET, RC4 + LZMA. Devuelve un texto con los otros dos nombres y sus llaves:

    LinPribernex.js|iTmjNaPnLEylOnK|SeigateBrauport.js|VDkHXxEq3VpA

**6. Final.** Los otros dos, también RC4 + LZMA. El programa que hace el daño es el segundo.

El ladrón va por otro camino: `DassmMQOJ.exe` carga `XLBugHandler.dll`, que lo trae cifrado y lo corre en memoria.

El método se parece al que [describió Malwarebytes en julio](https://www.malwarebytes.com/blog/threat-intel/2026/07/fake-games-spread-stealers-with-renpy-loader-msbuild-and-etherhiding),
aunque los nombres y hashes no son los mismos.
