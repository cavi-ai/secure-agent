#!/usr/bin/env python3
"""Loopback model fixture for the release smoke test."""

import http.server
import json


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        verdict = {
            "assessment": "benign",
            "confidence": 0.9,
            "rationale": "routine workflow",
            "suggested_action": "none",
        }
        body = json.dumps({"choices": [{"message": {
            "role": "assistant", "content": json.dumps(verdict),
        }}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    with http.server.HTTPServer(("127.0.0.1", 0), Handler) as server:
        print(f"http://127.0.0.1:{server.server_port}", flush=True)
        server.serve_forever()
