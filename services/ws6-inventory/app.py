"""WS-6 Inventory HTTP API (Contract C).

Implements the OpenAPI paths from contracts/inventory-api.yaml. The handler logic
lives here on a stdlib http.server so it runs with zero dependencies (the contract
test exercises it live). For production, the same `InventoryStore` is trivially
wrapped by FastAPI + uvicorn (see requirements.txt); routing is identical.

Endpoints:
  GET  /assets                 list/search (ip, mac, sector, status, limit)
  GET  /assets/resolve         ?ip=&at=  -> historically-correct asset
  GET  /assets/{mac}           one asset by MAC
  POST /assets/upsert          upsert from an Observation
"""
from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from store import InventoryStore  # noqa: E402

STORE = InventoryStore(os.getenv("INVENTORY_DB", ":memory:"))


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):  # quiet
        pass

    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path == "/assets/resolve":
            if "ip" not in q or "at" not in q:
                return self._send(400, {"error": "ip and at required"})
            asset = STORE.resolve(q["ip"], q["at"])
            return self._send(200, asset) if asset else self._send(404, {"error": "not found"})
        if u.path == "/assets":
            return self._send(200, STORE.list(
                ip=q.get("ip"), mac=q.get("mac"), sector=q.get("sector"),
                status=q.get("status"), limit=int(q.get("limit", 50))))
        if u.path.startswith("/assets/"):
            mac = u.path[len("/assets/"):]
            asset = STORE.get(mac)
            return self._send(200, asset) if asset else self._send(404, {"error": "not found"})
        return self._send(404, {"error": "no such path"})

    def do_POST(self):
        u = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        if u.path == "/assets/upsert":
            asset = STORE.upsert(body)
            return self._send(200, asset) if asset else self._send(400, {"error": "mac required"})
        return self._send(404, {"error": "no such path"})


def serve(host="0.0.0.0", port=8000):
    srv = ThreadingHTTPServer((host, port), Handler)
    sys.path.insert(0, str(HERE.parent))  # for `shared`
    from shared.log import get_logger  # noqa: E402
    get_logger("ws6-inventory").info("listening", url=f"http://{host}:{port}")
    srv.serve_forever()


if __name__ == "__main__":
    serve(port=int(os.getenv("PORT", "8000")))
