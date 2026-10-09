package correlate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestExpectStoreRejectsEditsAfterLoadFailure(t *testing.T) {
	p := ExpectedPattern{Agent: "claude", Reader: "gh", Path: "/u/hosts.yml", Dest: "example.com"}
	key := ReadConnectKey(p.Agent, p.Reader, p.Path, p.Dest)
	edits := map[string]func(*ExpectStore) error{
		"add":     func(s *ExpectStore) error { _, err := s.Add(p); return err },
		"add-all": func(s *ExpectStore) error { _, err := s.AddAll([]ExpectedPattern{p}); return err },
		"remove":  func(s *ExpectStore) error { _, err := s.Remove(key); return err },
	}
	for name, content := range map[string]string{"corrupt": `[{"agent":"claude"},`, "null": `null`, "object": `{}`, "wrong-type": `[{"agent":1}]`, "unreadable": ""} {
		for editName, edit := range edits {
			t.Run(name+"/"+editName, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "expected.json")
				if name == "unreadable" {
					if err := os.Mkdir(path, 0o700); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
				s := NewExpectStore(path)
				if len(s.List()) != 0 || s.Has(key) || s.Match([]string{key}, time.Now()) {
					t.Fatal("failed load applied an exception")
				}
				if err := edit(s); err == nil {
					t.Fatal("edit succeeded after a failed load")
				}
				if len(s.List()) != 0 || s.Has(key) {
					t.Fatal("failed edit changed in-memory policy")
				}
				if name == "unreadable" {
					if info, err := os.Stat(path); err != nil || !info.IsDir() {
						t.Fatalf("policy directory changed: %v", err)
					}
				} else if got, err := os.ReadFile(path); err != nil || string(got) != content {
					t.Fatalf("policy changed: %q, %v", got, err)
				}
			})
		}
	}
}

func TestExpectStoreRetriesFailedLoadBeforeEditing(t *testing.T) {
	old := ExpectedPattern{Agent: "claude", Reader: "gh", Path: "/u/hosts.yml", Dest: "old.example.com", CreatedAt: time.Unix(1, 0).UTC()}
	newPattern := old
	newPattern.Dest = "new.example.com"
	oldKey := ReadConnectKey(old.Agent, old.Reader, old.Path, old.Dest)
	for _, operation := range []string{"add", "add-all", "remove"} {
		t.Run(operation, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "expected.json")
			if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
				t.Fatal(err)
			}
			s := NewExpectStore(path)
			if len(s.List()) != 0 {
				t.Fatal("corrupt policy loaded")
			}
			data, err := json.Marshal([]ExpectedPattern{old})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			// Event matching stays in memory even while the file is repaired.
			if s.Has(oldKey) {
				t.Fatal("read path unexpectedly reloaded the policy")
			}
			switch operation {
			case "add":
				_, err = s.Add(newPattern)
			case "add-all":
				_, err = s.AddAll([]ExpectedPattern{newPattern})
			case "remove":
				var removed bool
				removed, err = s.Remove(oldKey)
				if !removed {
					t.Fatal("repaired entry was not removed")
				}
			}
			if err != nil {
				t.Fatalf("edit after repair: %v", err)
			}
			got := NewExpectStore(path).List()
			if operation == "remove" {
				if len(got) != 0 {
					t.Fatalf("removal not persisted: %+v", got)
				}
			} else if len(got) != 2 || !s.Has(oldKey) || !got[0].CreatedAt.Equal(old.CreatedAt) {
				t.Fatalf("repaired policy was overwritten: %+v", got)
			}
		})
	}
}

func TestExpectStorePersistsAndMatchesEveryKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "expected.json")
	s := NewExpectStore(path)
	p, err := s.Add(ExpectedPattern{Agent: "claude", Reader: "gh", Path: "/u/.config/gh/hosts.yml", Dest: "2606:4700::6812:105d", CreatedAt: time.Unix(1, 0).UTC()})
	if err != nil || p.Key != "claude|gh|/u/.config/gh/hosts.yml|2606:4700::6812:105d" {
		t.Fatalf("add = %+v, %v", p, err)
	}
	if again, _ := s.Add(ExpectedPattern{Agent: "claude", Reader: "gh", Path: "/u/.config/gh/hosts.yml", Dest: "2606:4700::6812:105d"}); !again.CreatedAt.Equal(p.CreatedAt) {
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
// AddAll stores the new patterns in one save, skips stored and repeated
// keys, and returns only the ones it added.
func TestExpectStoreAddAll(t *testing.T) {
	path := filepath.Join(t.TempDir(), "expected.json")
	s := NewExpectStore(path)
	old, _ := s.Add(ExpectedPattern{Agent: "claude", Reader: "gh", Path: "/u/h.yml", Dest: "a", CreatedAt: time.Unix(1, 0).UTC()})
	added, err := s.AddAll([]ExpectedPattern{
		{Agent: "claude", Reader: "gh", Path: "/u/h.yml", Dest: "a", CreatedAt: time.Unix(9, 0).UTC()},
		{Agent: "codex", Reader: "gh", Path: "/u/h.yml", Dest: "b"},
		{Agent: "codex", Reader: "gh", Path: "/u/h.yml", Dest: "b"},
		{Agent: "openclaw", Reader: "gh", Path: "/u/h.yml", Dest: "c"},
	})
	if err != nil || len(added) != 2 || added[0].Key != "codex|gh|/u/h.yml|b" || added[1].Key != "openclaw|gh|/u/h.yml|c" {
		t.Fatalf("added = %+v, %v", added, err)
	}
	got := NewExpectStore(path).List()
	kept := false
	for _, p := range got {
		kept = kept || (p.Key == old.Key && p.CreatedAt.Equal(old.CreatedAt))
	}
	if len(got) != 3 || !kept {
		t.Fatalf("reloaded = %+v", got)
	}
	if again, err := s.AddAll(added); err != nil || len(again) != 0 {
		t.Fatalf("re-adding = %+v, %v", again, err)
	}
}

func TestExpectedPatternIsCountedNotFlagged(t *testing.T) {
	c := newFamilyCorrelator(t)
	store := NewExpectStore(filepath.Join(t.TempDir(), "expected.json"))
	c.SetExpected(store.Match)
	hosts := homePath(t, ".config/gh/hosts.yml")
	if _, err := store.Add(ExpectedPattern{Agent: "cursor", Reader: "gh-reader", Path: hosts, Dest: "2606:4700::6812:105d"}); err != nil {
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
