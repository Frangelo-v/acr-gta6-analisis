# acr-gta6-analisis

Zip falso de "GTA 6" que anda circulando desde noviembre 2026. Suelta un stealer (Amatera / ACR 4.6.7-alpha1), un
proxy y un clipper.

- [writeup.md](writeup.md)
- [iocs.txt](iocs.txt)
- [rules.yar](rules.yar)
- [strings.txt](strings.txt) strings del stealer

No subo las muestras.

## scripts

```
pip install -r scripts/requirements.txt
```

| script | |
|---|---|
| resx_extract.py | saca el PE de .NET del Resources.resx |
| dotnet_strings.py | strings de la stage2 |
| unpack.py | separa los 3 archivos que trae la stage2 |
| decrypt.py | RC4 + LZMA |
| get_keys.py | keys de los payloads finales (emula la stage3) |
| etherhiding.py | C2 actual del clipper |
| stealer_strings.py | strings del stealer, con unicorn. Solo esta muestra |

```
python resx_extract.py -d "Storage Controller Service" -o stage2.bin
python unpack.py -f stage2.bin -o out
python decrypt.py -f out/FianBro.js -k r3vWWbc0 -o stage3.bin
python get_keys.py -f stage3.bin
python decrypt.py -f out/SeigateBrauport.js -k VDkHXxEq3VpA -o proxy.bin
```

Probado con:

```
Storage Controller Service   9db50ddab4741de2d1cc38a3848deb1f398f76bed50cec6e48259420c588e0fb
Audio Service Helper         9ac4e30bf419acf34eb11ff27924941505a5e8a20986561644ceae794523ac87
```

(son los hashes del MSBuild.exe de cada carpeta)

## si lo abriste

Cierra todas las sesiones desde otro equipo (google, telegram, discord, steam), cambia contraseñas y formatea. Cambiar
solo la contraseña no sirve porque se llevan las cookies.
