package correlate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The cache reads a policy once per change of the file: not again while it
// is unchanged, again after an atomic rewrite, and once while it is missing
// or failing.
func TestPolicyCacheReadsOncePerChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	var c policyCache[string]
	reads := 0
	read := func() (string, error) {
		reads++
		b, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return string(b), err
	}
	get := func() string {
		v, _, err := c.get(path, read)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if get() != "" || get() != "" || reads != 1 {
		t.Fatalf("missing file read %d times", reads)
	}
	if err := os.WriteFile(path, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if get() != "a" || get() != "a" || reads != 2 {
		t.Fatalf("written file: reads %d", reads)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte("bb"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	if get() != "bb" || reads != 3 {
		t.Fatalf("atomic rewrite not seen: reads %d", reads)
	}
	failing := func() (string, error) { reads++; return "", errors.New("corrupt") }
	if err := os.WriteFile(path, []byte("ccc"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, fresh, err := c.get(path, failing)
	_, again, err2 := c.get(path, failing)
	if err == nil || err2 == nil || !fresh || again || reads != 4 {
		t.Fatalf("failed load: fresh=%v again=%v err=%v reads=%d", fresh, again, err, reads)
	}
}

// An edit through the store is seen by the next match.
func TestMuteStoreMatchSeesEdits(t *testing.T) {
	s := NewMuteStore(filepath.Join(t.TempDir(), "mutes.json"))
	if s.Muted("r", "h.example.com", "") {
		t.Fatal("muted before any mute")
	}
	if err := s.Add("r", "h.example.com", ""); err != nil {
		t.Fatal(err)
	}
	if !s.Muted("r", "h.example.com", "") {
		t.Fatal("added mute not applied")
	}
	if err := s.Remove("r", "h.example.com", ""); err != nil {
		t.Fatal(err)
	}
	if s.Muted("r", "h.example.com", "") {
		t.Fatal("removed mute still applied")
	}
}
