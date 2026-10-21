package sysagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/localmodel"
	"github.com/cavi-ai/secure-agent/daemon/internal/redact"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// Explicit opt-in: real keystore and local provider, synthetic evidence only.
func TestPersistentAgentWithLocalModel(t *testing.T) {
	ep, name := os.Getenv("SECURE_AGENT_TEST_SYSTEM_AGENT_ENDPOINT"), os.Getenv("SECURE_AGENT_TEST_SYSTEM_AGENT_MODEL")
	if ep == "" || name == "" || os.Getenv("SECURE_AGENT_TEST_KEYSTORE") != "1" {
		t.Skip("opt-in operating system keystore and local model integration")
	}
	dir := t.TempDir()
	state := filepath.Join(dir, "agent")
	db := filepath.Join(dir, "history.db")
	sum := sha256.Sum256([]byte(state))
	account := hex.EncodeToString(sum[:16])
	defer func() {
		if runtime.GOOS == "darwin" {
			_ = exec.Command("/usr/bin/security", "delete-generic-password", "-s", "com.secure-agent.history", "-a", account).Run()
		}
	}()
	open := func() (*Agent, *store.Store) {
		st, err := store.Open(db, "")
		if err != nil {
			t.Fatal(err)
		}
		a := NewPersistent(st, state, func(v string) (string, bool) { return redact.Scrub(v), true })
		a.SetConfig(config.SystemAgentConfig{Enabled: true, Endpoint: ep, Model: name, TimeoutMinutes: 1})
		return a, st
	}
	a, st := open()
	defer func() { a.Close(); st.Close() }()
	if problem := a.Status(context.Background()).StorageError; problem != "" {
		t.Fatal(problem)
	}
	if _, err := a.Send(ChatInput{Message: "Synthetic check: call inspect_skill with id git, then state which procedure was read. Do not propose a command.", Workdir: dir}); err != nil {
		t.Fatal(err)
	}
	a.Wait()
	rows := a.Messages(10)
	last := rows[len(rows)-1]
	if last.Role != "assistant" || last.Usage == nil || last.Usage.ReadToolCalls < 1 || last.LocalCommand != nil {
		t.Fatalf("native tool exchange did not complete: role=%s", last.Role)
	}
	if err := a.Remember(dir, "local-outcome", "Synthetic recorded check completed", []string{"fixture:one"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Clear(); err != nil {
		t.Fatal(err)
	}
	resident := localmodel.ResidencyAt(context.Background(), a.client, ep, name)
	// MLX reports its dynamic maximum window, not a preallocated num_ctx
	// buffer. GGUF runners report the requested fixed context instead.
	if !resident.Available || !resident.Loaded || (resident.Context > 32768 && resident.Format != "safetensors") {
		t.Fatalf("native context control unavailable: %+v", resident)
	}
	a.Close()
	st.Close()
	a, st = open()
	if len(a.Memory(dir)) != 1 || len(a.Sessions()) != 1 || a.Sessions()[0].ClosedAt == nil {
		t.Fatal("encrypted continuity failed after reopen")
	}
	data, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("Synthetic recorded check completed")) {
		t.Fatal("retained fact appeared in plaintext database")
	}
	t.Logf("native tool exchange completed; provider context=%d; encrypted fact and closed session survived reopen", resident.Context)
}
