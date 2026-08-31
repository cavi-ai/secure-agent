package firewall

import (
	"path/filepath"
	"testing"
)

func TestSourceStoreAddDedupeRemovePersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "firewall-sources.json")
	s := NewSourceStore(path)

	if len(s.Load()) != 0 {
		t.Fatal("fresh store should be empty")
	}

	if added, err := s.Add("~/.aws/credentials"); err != nil || !added {
		t.Fatalf("first add = (%v, %v), want (true, nil)", added, err)
	}
	if added, err := s.Add("~/.aws/credentials"); err != nil || added {
		t.Fatalf("duplicate add = (%v, %v), want (false, nil)", added, err)
	}

	// A new store reading the same file must see the persisted source.
	if got := NewSourceStore(path).Load(); len(got) != 1 || got[0] != "~/.aws/credentials" {
		t.Fatalf("persisted sources = %v", got)
	}

	if removed, err := s.Remove("~/.nope"); err != nil || removed {
		t.Fatalf("remove of absent = (%v, %v), want (false, nil)", removed, err)
	}
	if removed, err := s.Remove("~/.aws/credentials"); err != nil || !removed {
		t.Fatalf("remove = (%v, %v), want (true, nil)", removed, err)
	}
	if got := NewSourceStore(path).Load(); len(got) != 0 {
		t.Fatalf("sources after remove = %v, want empty", got)
	}
}
