# Ladrón

32 bits, se presenta como "Realtek HD Audio Manager". Versión `4.6.7-alpha1`, con fecha `Tue Nov  3 19:43:00 2026`.
Por el formato de versión, los dominios .cc y el uso de Heaven's Gate, muy probablemente es Amatera, el que antes se
llamaba ACR Stealer.

Servidores: `tap.cloudlinkbrh[.]cc` y `tap.safertunnelnye[.]cc`, los dos registrados el mismo día y al mismo minuto.
No usa el DNS del equipo: pregunta por DNS cifrado a 1.0.0.1, 8.8.8.8 y dns.google, así que bloquear los dominios en
el hosts no lo para.

Lo que busca, según sus propios textos (`ioc/textos_ladron.txt`):

- Chrome y parecidos: cookies, contraseñas, historial y formularios, de todos los perfiles, más la llave del
  `Local State`
- Firefox: `logins.json`, `key4.db`, `cookies.sqlite`, `places.sqlite`, `formhistory.sqlite`
- Extensiones y su almacenamiento (`Local Storage\leveldb`, `storage\default`)
- Steam: `loginusers.vdf`, `local.vdf`
- Cursor: `accessToken` y `refreshToken` de `state.vscdb`
- Captura de pantalla

También trae una lista larga de extensiones de archivo (exe, dll, mp4, iso...). Por lo que contiene parece la lista de
lo que no le interesa, pero no lo confirmé.

Abre el navegador escondido (`--headless`, `about:blank`, o Firefox con un perfil en `C:\Users\Public\.ff_tmp`).

En los textos no aparece Telegram, pero este tipo de ladrón puede recibir del servidor qué carpetas copiar, así que eso
no quiere decir que no se lo lleve.
