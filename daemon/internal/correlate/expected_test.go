package correlate

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestExpectStorePersistsAndMatchesEveryKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "expected.json")
	s := NewExpectStore(path)
	p, err := s.Add(ExpectedPattern{Agent: "claude", Reader: "gh", Path: "/u/.config/gh/hosts.yml", Dest: "Cloudflare", CreatedAt: time.Unix(1, 0).UTC()})
	if err != nil || p.Key != "claude|gh|/u/.config/gh/hosts.yml|Cloudflare" {
		t.Fatalf("add = %+v, %v", p, err)
	}
	if again, _ := s.Add(ExpectedPattern{Agent: "claude", Reader: "gh", Path: "/u/.config/gh/hosts.yml", Dest: "Cloudflare"}); !again.CreatedAt.Equal(p.CreatedAt) {
		t.Fatal("adding a stored pattern replaced it")
	}
	at := time.Unix(100, 0)
	if s.Match([]string{p.Key, "other"}, at) || s.Match(nil, at) {
		t.Fatal("a partial or empty key set matched")
	}
	if !s.Match([]string{p.Key}, at) {
		t.Fatal("stored key did not match")
	}
	reloaded := NewExpectStore(path)
	got := reloaded.List()
	if len(got) != 1 || got[0].Key != p.Key || got[0].Hits != 0 {
		t.Fatalf("reloaded = %+v, want the pattern without hits", got)
	}
	if l := s.List(); l[0].Hits != 1 || l[0].LastSeen == nil || !l[0].LastSeen.Equal(at) {
		t.Fatalf("hits/last_seen = %d/%v, want 1/%v", l[0].Hits, l[0].LastSeen, at)
	}
	if ok, err := s.Remove(p.Key); !ok || err != nil {
		t.Fatalf("remove = %v, %v", ok, err)
	}
	if ok, _ := s.Remove(p.Key); ok {
		t.Fatal("second remove reported success")
	}
	if len(NewExpectStore(path).List()) != 0 {
		t.Fatal("removal not persisted")
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if NewExpectStore(path).Match([]string{p.Key}, at) {
		t.Fatal("a corrupt file matched")
	}
}

// An expected pattern is counted, not flagged; another reader or another
// destination still flags.
func TestExpectedPatternIsCountedNotFlagged(t *testing.T) {
	c := newFamilyCorrelator(t)
	store := NewExpectStore(filepath.Join(t.TempDir(), "expected.json"))
	c.SetExpected(store.Match)
	hosts := homePath(t, ".config/gh/hosts.yml")
	if _, err := store.Add(ExpectedPattern{Agent: "cursor", Reader: "gh", Path: hosts, Dest: "Cloudflare"}); err != nil {
		t.Fatal(err)
	}
	// The tagger names the family after cursor-agent (pid 200).
	base := time.Unix(1_700_000_000, 0)
	ghReads(c, t, event.KindFileOpen, base)
	if f := connectTo(c, 201, "2606:4700::6812:105d", base.Add(time.Second)); len(f) != 0 {
		t.Fatalf("expected pattern flagged: %+v", f)
	}
	if c.ExpectedCount() != 1 || store.List()[0].Hits != 1 {
		t.Fatalf("expected count/hits = %d/%d, want 1/1", c.ExpectedCount(), store.List()[0].Hits)
	}
	if f := connectTo(c, 201, "evil.example.com", base.Add(2*time.Second)); len(f) != 1 {
		t.Fatalf("new destination: flags = %+v, want 1", f)
	}
	at := base.Add(10 * time.Minute)
	c.Observe(event.Event{Kind: event.KindFileOpen, PID: 201, TS: at, Path: hosts, ExePath: "/usr/bin/curl"})
	if f := connectTo(c, 201, "2606:4700::6812:105d", at.Add(time.Second)); len(f) != 1 {
		t.Fatalf("new reader: flags = %+v, want 1", f)
	}
}
