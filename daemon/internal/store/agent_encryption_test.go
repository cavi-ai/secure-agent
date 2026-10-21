package store

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestAgentEncryptionMigratesAndPreservesClaims(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id := s.PutSysAgentMessage(model.SysAgentMessage{TS: time.Now(), Role: "assistant", Content: "private fixture", LocalCommand: &model.SysAgentLocalCommand{Command: "true"}})
	if err = s.EnableAgentEncryption(bytes.Repeat([]byte{7}, 32)); err != nil {
		t.Fatal(err)
	}
	var raw string
	s.db.QueryRow("SELECT body FROM sysagent_messages WHERE id=?", id).Scan(&raw)
	if strings.Contains(raw, "private fixture") || !strings.HasPrefix(raw, "enc:v1:") {
		t.Fatal("plaintext survived encryption migration")
	}
	old, ok := s.GetSysAgentMessage(id)
	if !ok || old.Content != "private fixture" {
		t.Fatal("encrypted history unavailable")
	}
	if !s.ClaimSysAgentAction(id) {
		t.Fatal("encrypted action could not be claimed")
	}
	s.PutSysAgentMessage(old)
	if s.ClaimSysAgentAction(id) {
		t.Fatal("stale encrypted update reopened action")
	}
}

func TestAgentEncryptionRejectsTamperingAndWrongKey(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.EnableAgentEncryption(bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatal(err)
	}
	id := s.PutSysAgentMessage(model.SysAgentMessage{TS: time.Now(), Role: "user", Content: "private"})
	s.db.Exec("UPDATE sysagent_messages SET body='enc:v1:invalid' WHERE id=?", id)
	if _, ok := s.GetSysAgentMessage(id); ok {
		t.Fatal("tampered ciphertext was readable")
	}
	if err = s.EnableAgentEncryption(bytes.Repeat([]byte{2}, 32)); err == nil {
		t.Fatal("key replacement accepted unreadable history")
	}
	if s.PutSysAgentMessage(model.SysAgentMessage{TS: time.Now(), Role: "user", Content: "must not write"}) != 0 {
		t.Fatal("locked storage fell back to plaintext")
	}
}

func TestRefreshedAgentMemoryRenewsRetention(t *testing.T) {
	s, err := Open("", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.EnableAgentEncryption(bytes.Repeat([]byte{4}, 32)); err != nil {
		t.Fatal(err)
	}
	fact := model.SysAgentMemory{At: time.Now().Add(-89 * 24 * time.Hour), Scope: "/fixture", Kind: "worktree-check", Summary: "Checked repository", References: []string{"fixture:one"}}
	fact.ID = s.PutSysAgentMemory(fact)
	if fact.ID == 0 {
		t.Fatal("fact not stored")
	}
	// Move the retention clock past the original observation's expiry.
	_, err = s.db.Exec("UPDATE sysagent_memory SET ts=? WHERE id=?", time.Now().Add(-91*24*time.Hour).UTC().Format(time.RFC3339Nano), fact.ID)
	if err != nil {
		t.Fatal(err)
	}
	fact.At = time.Now()
	if s.PutSysAgentMemory(fact) == 0 || len(s.FindSysAgentMemory("/fixture")) != 1 {
		t.Fatal("a fresh observation was purged using its original timestamp")
	}
}
