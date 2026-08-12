#!/usr/bin/env python3
import json
import os
import subprocess
import time
import urllib.request
import http.client

def query_unix(socket_path, path):
    class UnixHTTPConnection(http.client.HTTPConnection):
        def connect(self):
            import socket
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(socket_path)

    conn = UnixHTTPConnection("localhost")
    conn.request("GET", path)
    res = conn.getresponse()
    body = res.read().decode()
    conn.close()
    return json.loads(body or "[]")

def main():
    home = os.path.expanduser("~")
    sock_path = os.path.join(home, ".config", "secure-agent", "daemon.sock")

    events = query_unix(sock_path, "/events")
    flags = query_unix(sock_path, "/flags")
    status = query_unix(sock_path, "/status")

    print("=== STATUS ===")
    print(json.dumps(status, indent=2))
    print("=== RECENT EVENTS (last 10) ===")
    print(json.dumps(events[:10], indent=2))
    print("=== RECENT FLAGS ===")
    print(json.dumps(flags, indent=2))

if __name__ == "__main__":
    main()
