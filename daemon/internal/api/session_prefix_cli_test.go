package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestSessionPrefixCLIWithRetainedHistory(t *testing.T) {
	dir := t.TempDir()
	database := filepath.Join(dir, "history.db")
	st, err := store.Open(database, "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	put := func(id, status string, age time.Duration) {
		t.Helper()
		at := now.Add(-age)
		if err := st.UpsertSession(model.Session{ID: id, Harness: "codex", Workspace: "/workspace/history", Status: status, StartedAt: at, LastSeenAt: at}); err != nil {
			t.Fatal(err)
		}
	}
	put("olduni-retained", model.SessionEnded, 3*time.Hour)
	put("shared-old", model.SessionEnded, 4*time.Hour)
	for i := range 501 {
		put(fmt.Sprintf("recent-%04d", i), model.SessionEnded, time.Duration(i)*time.Second)
	}
	put("shared-new", model.SessionActive, 0)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = store.Open(database, "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	cli := filepath.Join(dir, "secure-agent")
	buildCtx, cancelBuild := context.WithTimeout(context.Background(), time.Minute)
	defer cancelBuild()
	build := exec.CommandContext(buildCtx, "go", "build", "-o", cli, "./cmd/secure-agent")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, output)
	}

	// Keep the socket path below the platform limit even when the test's
	// storage directory has a long name.
	socketDir, err := os.MkdirTemp("", "session-cli-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(socketDir)
	socket := filepath.Join(socketDir, "api.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	a := New(Deps{Store: st, Peers: PeerDeps{Checker: NewPeerChecker()}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.ServeListener(ctx, listener) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve API: %v", err)
		}
	}()

	for _, tc := range []struct {
		name, id string
		json     bool
		wantID   string
	}{
		{name: "older prefix JSON", id: "olduni", json: true, wantID: "olduni-retained"},
		{name: "older prefix Markdown", id: "olduni", wantID: "olduni-retained"},
		{name: "collision outside recent history", id: "shared", json: true},
		{name: "exact ID despite collision", id: "shared-old", json: true, wantID: "shared-old"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runCtx, cancelRun := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancelRun()
			args := []string{"session", tc.id}
			if tc.json {
				args = append(args, "--json")
			}
			command := exec.CommandContext(runCtx, cli, args...)
			command.Env = append(os.Environ(), "SECURE_AGENT_SOCK="+socket)
			output, err := command.CombinedOutput()
			if tc.wantID == "" {
				if err == nil || !strings.Contains(string(output), "shared-old") || !strings.Contains(string(output), "shared-new") {
					t.Fatalf("ambiguous prefix returned a report instead of both candidates: %v\n%s", err, output)
				}
				return
			}
			if err != nil {
				t.Fatalf("export: %v\n%s", err, output)
			}
			if tc.json {
				var report store.SessionReport
				if err := json.Unmarshal(output, &report); err != nil || report.Session.ID != tc.wantID {
					t.Fatalf("wrong session in JSON export: %v\n%s", err, output)
				}
			} else if !strings.Contains(string(output), tc.wantID) {
				t.Fatalf("Markdown export lacks full identity: %s", output)
			}
		})
	}
}
