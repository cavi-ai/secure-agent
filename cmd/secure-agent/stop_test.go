package main

import (
	"os"
	"path/filepath"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestStopDefaultsMatchDaemonDefaults(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "daemon", "internal", "config", "defaults.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		DBPath     string `yaml:"db_path"`
		SocketPath string `yaml:"socket_path"`
	}
	if err := yaml.Unmarshal(data, &d); err != nil {
		t.Fatal(err)
	}
	if d.DBPath != defaultDBPath || d.SocketPath != defaultSocketPath {
		t.Fatalf("daemon defaults db_path=%q socket_path=%q; stop resolves %q and %q", d.DBPath, d.SocketPath, defaultDBPath, defaultSocketPath)
	}
}

func TestRunRecordPathFollowsConfigOverlay(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SECURE_AGENT_CONFIG", "")
	overlay := filepath.Join(home, ".config", "secure-agent", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(overlay), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, overlay, want string }{
		{"defaults", "", filepath.Join(home, ".local", "state", "secure-agent", "events.db.run-record.json")},
		{"db_path", "db_path: /srv/sa/events.db\n", "/srv/sa/events.db.run-record.json"},
		{"in-memory store", "db_path: \"\"\nsocket_path: ~/sa.sock\n", filepath.Join(home, "sa.sock.run-record.json")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.overlay != "" {
				if err := os.WriteFile(overlay, []byte(tc.overlay), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := runRecordPath()
			if err != nil || got != tc.want {
				t.Fatalf("runRecordPath() = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}
