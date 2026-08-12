#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import time
import http.client
import tempfile

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
    with tempfile.TemporaryDirectory() as tmpdir:
        sock_path = os.path.join(tmpdir, "d.sock")
        db_path = os.path.join(tmpdir, "events.db")
        jsonl_path = os.path.join(tmpdir, "events.jsonl")
        config_path = os.path.join(tmpdir, "config.yaml")

        env_file = os.path.join(tmpdir, ".env")
        with open(env_file, "w") as f:
            f.write("SECRET_KEY=dummy_val_123\n")

        with open(config_path, "w") as f:
            f.write(f"""agents:
  - {{ name: cursor, match: ["fake-cursor", "cursor"] }}
net_sample_interval_ms: 200
socket_path: "{sock_path}"
db_path: "{db_path}"
jsonl_path: "{jsonl_path}"
""")

        # Build secure-agentd
        bin_path = os.path.join(tmpdir, "secure-agentd")
        subprocess.run(["go", "build", "-o", bin_path, "./daemon/cmd/secure-agentd"], check=True)

        proc = subprocess.Popen([bin_path, "-config", config_path])
        time.sleep(1)

        # Build fake-cursor Go binary
        fake_cursor_src = os.path.join(tmpdir, "fake_cursor_main.go")
        fake_cursor_bin = os.path.join(tmpdir, "fake-cursor")
        with open(fake_cursor_src, "w") as f:
            f.write(f"""package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {{
	home, _ := os.UserHomeDir()
	actPath := filepath.Join(home, ".local", "state", "secure-agent", "activity.jsonl")
	os.MkdirAll(filepath.Dir(actPath), 0755)

	targetEnv := os.Args[1] + "/.env"
	rec := map[string]interface{{}}{{
		"tool": "Read",
		"file_path": targetEnv,
		"pid": os.Getpid(),
	}}
	data, _ := json.Marshal(rec)
	f, _ := os.OpenFile(actPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if f != nil {{
		f.Write(append(data, '\\n'))
		f.Close()
	}}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err == nil {{
		defer l.Close()
		done := make(chan struct{{}})
		go func() {{
			conn, err := l.Accept()
			if err == nil {{
				<-done
				conn.Close()
			}}
		}}()

		clientConn, err := net.Dial("tcp", l.Addr().String())
		if err == nil {{
			time.Sleep(2 * time.Second)
			close(done)
			clientConn.Close()
		}}
	}}
}}
""")
        subprocess.run(["go", "build", "-o", fake_cursor_bin, fake_cursor_src], check=True)

        # Run fake-cursor
        print(f"Executing {fake_cursor_bin}...")
        subprocess.run([fake_cursor_bin, tmpdir], check=True)

        time.sleep(1)

        events = query_unix(sock_path, "/events")
        flags = query_unix(sock_path, "/flags")

        print("=== EVENTS RECEIVED ===")
        print(json.dumps(events, indent=2))
        print("\n=== FLAGS RECEIVED ===")
        print(json.dumps(flags, indent=2))

        proc.terminate()

if __name__ == "__main__":
    main()
