# Clipper

"Audio Service Helper", que dice ser de Creative. El programa final pesa 73 KB. Se queda mirando el portapapeles y
cuando copias una dirección de cripto la cambia por una suya. Las que trae están en `ioc/billeteras.csv`.

Mutex: `update-S-1-5-26-15297236-4840534596-8490206048-3100`

## De dónde saca su servidor

No lo trae escrito. Le pregunta a un contrato de BNB Smart Chain:

    0xe9D1A9fB1C57a00e8D696FE799cD717c8f311ac9

La respuesta de `balanceOf` (0x70a08231), con la dirección que sea, es el dominio en texto. Es lo que llaman
EtherHiding: aunque tumben el dominio, escriben otro en el contrato y todos los infectados se enteran solos.

`desofuscador/contrato.py` lo lee. Solo consulta un nodo público, no toca el servidor de ellos.

Lo bueno es que en la blockchain queda todo. El contrato se creó el 16/03/2026 y la misma cuenta firmó todos los
cambios (`0x3a35b409af86e79e8945d6a7ffb1dc59b8dbdf46`). Los 31 dominios que ha tenido están en
`ioc/dominios_contrato.csv`.

Esa cuenta escribe en otros dos contratos. El 25/11/2026 tenían `pulsefit[.]cc` y `data.nomadhive[.]cc`. No sé qué
programa los usa.
