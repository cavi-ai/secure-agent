package sensitive

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

// SharedCase is one row of testdata/paths.json, the fixture the daemon, the
// incident analyzer and the guard hook all assert against.
type SharedCase struct {
	Path          string `json:"path"`
	SSHPrivateKey bool   `json:"ssh_private_key"`
	EnvSecret     bool   `json:"env_secret"`
}

func sharedCases(t *testing.T) []SharedCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "paths.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []SharedCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("no shared cases")
	}
	return f.Cases
}

func TestSharedPathRules(t *testing.T) {
	c := New(config.Config{})
	for _, tc := range sharedCases(t) {
		if got := SSHPrivateKey(tc.Path); got != tc.SSHPrivateKey {
			t.Errorf("SSHPrivateKey(%s) = %v, want %v", tc.Path, got, tc.SSHPrivateKey)
		}
		if got := EnvSecret(filepath.Base(tc.Path)); got != tc.EnvSecret {
			t.Errorf("EnvSecret(%s) = %v, want %v", tc.Path, got, tc.EnvSecret)
		}
		cat, ok := c.Classify(tc.Path)
		want := CatOther
		switch {
		case tc.SSHPrivateKey:
			want = CatSSHKey
		case tc.EnvSecret:
			want = CatEnvFile
		}
		if wantOK := tc.SSHPrivateKey || tc.EnvSecret; ok != wantOK || cat != want {
			t.Errorf("Classify(%s) = %v %v, want %v %v", tc.Path, cat, ok, want, wantOK)
		}
	}
}
