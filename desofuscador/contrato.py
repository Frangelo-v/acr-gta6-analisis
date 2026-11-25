"""Lee el dominio guardado en el contrato del clipper desde un nodo publico de BSC.

    python contrato.py [contrato]
"""
import json
import sys
import urllib.request

CONTRATO = "0xe9D1A9fB1C57a00e8D696FE799cD717c8f311ac9"
NODOS = ("https://bsc-dataseed.bnbchain.org", "https://bsc-rpc.publicnode.com")


def llamar(nodo, metodo, params):
    cuerpo = json.dumps({"id": 1, "jsonrpc": "2.0", "method": metodo, "params": params}).encode()
    req = urllib.request.Request(nodo, cuerpo, {"Content-Type": "application/json", "User-Agent": "python"})
    return json.load(urllib.request.urlopen(req, timeout=20))["result"]


def texto(h):
    b = bytes.fromhex(h[2:])
    ini = int.from_bytes(b[:32], "big")
    n = int.from_bytes(b[ini:ini + 32], "big")
    return b[ini + 32:ini + 32 + n].decode("utf-8", "replace")


c = sys.argv[1] if len(sys.argv) > 1 else CONTRATO
for nodo in NODOS:
    try:
        # balanceOf(address): da igual la direccion
        r = llamar(nodo, "eth_call", [{"to": c, "data": "0x70a08231" + "0" * 63 + "1"}, "latest"])
        print(texto(r).replace(".", "[.]"))
        break
    except Exception as e:
        print(nodo, e, file=sys.stderr)
