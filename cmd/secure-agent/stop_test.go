package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestStopCommandProcess(t *testing.T) {
	if os.Getenv("SECURE_AGENT_TEST_STOP_COMMAND") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"secure-agent", "stop"}, os.Args[i+1:]...)
			main()
			os.Exit(0)
		}
	}
	t.Fatal("missing CLI argument separator")
}

func TestStopCommandValidatesArgumentsBeforeConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("db_path: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
		code int
	}{
		{"help", []string{"--help"}, 0},
		{"short help", []string{"-h"}, 0},
		{"unknown flag", []string{"--unexpected"}, 2},
		{"missing run record", []string{"--run-record"}, 2},
		{"empty run record", []string{"--run-record", ""}, 2},
		{"flag instead of run record", []string{"--run-record", "--unexpected"}, 2},
		{"positional argument", []string{"unexpected"}, 2},
		{"trailing flag", []string{"--run-record", "record.json", "--unexpected"}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"-test.run=^TestStopCommandProcess$", "--"}, tc.args...)
			cmd := exec.Command(os.Args[0], args...)
			cmd.Env = append(os.Environ(), "SECURE_AGENT_TEST_STOP_COMMAND=1",
				"SECURE_AGENT_CONFIG="+configPath, "SECURE_AGENT_SOCK="+filepath.Join(dir, "missing.sock"))
			out, err := cmd.CombinedOutput()
			if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != tc.code ||
				!strings.Contains(string(out), "secure-agent stop") || strings.Contains(string(out), "config overlay") {
				t.Fatalf("stop %q: want usage and exit %d, got %v: %s", tc.args, tc.code, err, out)
			}
		})
	}
}

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
	t.Setenv("SECURE_AGENT_TEST_STOP_DB", "")
	overlay := filepath.Join(home, ".config", "secure-agent", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(overlay), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, overlay, want string }{
		{"defaults", "", filepath.Join(home, ".local", "state", "secure-agent", "events.db.run-record.json")},
		{"db_path", "db_path: /srv/sa/events.db\n", "/srv/sa/events.db.run-record.json"},
		{"empty expanded DB path", "db_path: $SECURE_AGENT_TEST_STOP_DB\nsocket_path: ~/sa.sock\n", filepath.Join(home, "sa.sock.run-record.json")},
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
