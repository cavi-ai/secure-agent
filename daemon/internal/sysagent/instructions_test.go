package sysagent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstructionApplyPreservesContentAndIsIdempotent(t *testing.T) {
	a, _ := testAgent(t, "http://127.0.0.1:11434", nil)
	dir := t.TempDir()
	path := filepath.Join(dir, "AGENTS.md")
	original := "# Project rules\nKeep existing instructions."
	if err := os.WriteFile(path, []byte(original), 0640); err != nil {
		t.Fatal(err)
	}
	p, err := a.PreviewInstruction(dir, "codex", "secret-in-transcript")
	if err != nil || p.Applied || p.Revision == "" {
		t.Fatalf("preview: %+v %v", p, err)
	}
	if p.Path != path || !strings.Contains(p.Instruction, "Never print") {
		t.Fatalf("preview: %+v", p)
	}
	result, err := a.ApplyInstruction(dir, "codex", "secret-in-transcript", p.Revision)
	if err != nil || !result.Applied {
		t.Fatalf("apply: %+v %v", result, err)
	}
	data, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(data), original) || strings.Count(string(data), p.Instruction) != 1 {
		t.Fatalf("existing rules were changed: %q", data)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0640 {
		t.Fatal("permissions changed")
	}
	if _, err := a.ApplyInstruction(dir, "codex", "secret-in-transcript", p.Revision); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(path)
	if string(again) != string(data) {
		t.Fatal("repeat click duplicated instructions")
	}
}

func TestInstructionCreateAndStalePreview(t *testing.T) {
	a, _ := testAgent(t, "http://127.0.0.1:11434", nil)
	dir := t.TempDir()
	p, err := a.PreviewInstruction(dir, "claude", "proxy-prompt-injection")
	if err != nil || filepath.Base(p.Path) != "CLAUDE.md" {
		t.Fatal(p, err)
	}
	if _, err := a.ApplyInstruction(dir, "claude", "proxy-prompt-injection", p.Revision); err != nil {
		t.Fatal(err)
	}
	q, err := a.PreviewInstruction(dir, "claude", "keychain-security-cli")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(q.Path, []byte("Concurrent user edit\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ApplyInstruction(dir, "claude", "keychain-security-cli", q.Revision); err == nil {
		t.Fatal("stale preview wrote a changed file")
	}
	data, _ := os.ReadFile(q.Path)
	if string(data) != "Concurrent user edit\n" {
		t.Fatal("concurrent edit was changed")
	}
}

func TestInstructionRejectsUnsafeTargets(t *testing.T) {
	a, _ := testAgent(t, "http://127.0.0.1:11434", nil)
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.md")
	if err := os.WriteFile(outside, []byte("private content"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "AGENTS.md")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ workspace, agent, rule string }{
		{dir, "codex", "secret-in-transcript"},
		{"/", "codex", "secret-in-transcript"},
		{"relative", "codex", "secret-in-transcript"},
		{dir, "unknown", "secret-in-transcript"},
		{dir, "codex", "unknown"},
	} {
		if _, err := a.PreviewInstruction(tc.workspace, tc.agent, tc.rule); err == nil {
			t.Fatalf("accepted unsafe target: %+v", tc)
		}
		if _, err := a.ApplyInstruction(tc.workspace, tc.agent, tc.rule, "anything"); err == nil {
			t.Fatalf("wrote unsafe target: %+v", tc)
		}
	}
	data, _ := os.ReadFile(outside)
	if string(data) != "private content" {
		t.Fatal("followed symlink")
	}
}
