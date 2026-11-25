# reads the current clipper c2 from the BSC contract

import json
import sys
import urllib.request

contract = sys.argv[1] if len(sys.argv) > 1 else "0xe9D1A9fB1C57a00e8D696FE799cD717c8f311ac9"
rpc = "https://bsc-dataseed.bnbchain.org"

# balanceOf(), any address works
call = {"to": contract, "data": "0x70a08231" + "1".zfill(64)}
body = json.dumps({"id": 1, "jsonrpc": "2.0", "method": "eth_call", "params": [call, "latest"]})
req = urllib.request.Request(rpc, body.encode(), {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"})
res = json.load(urllib.request.urlopen(req, timeout=20))["result"]

b = bytes.fromhex(res[2:])
off = int.from_bytes(b[:32], "big")
n = int.from_bytes(b[off : off + 32], "big")
print(b[off + 32 : off + 32 + n].decode().replace(".", "[.]"))
