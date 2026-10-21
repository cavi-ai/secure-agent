package platformkey

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxCreationRequiresSuccessfulEmptySearch(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\ncase \"$KEYSTORE_FIXTURE\" in\nabsent) exit 0;;\nlocked) printf '[item]\\nlabel = history\\n'; exit 0;;\nerror) exit 1;;\nesac\nexit 2\n"
	if err := os.WriteFile(filepath.Join(dir, "secret-tool"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	for _, tc := range []struct {
		state  string
		absent bool
	}{{"absent", true}, {"locked", false}, {"error", false}} {
		t.Run(tc.state, func(t *testing.T) {
			t.Setenv("KEYSTORE_FIXTURE", tc.state)
			if got := linuxItemAbsent(context.Background(), "fixture"); got != tc.absent {
				t.Fatalf("creation permitted=%v, want %v", got, tc.absent)
			}
		})
	}
}
