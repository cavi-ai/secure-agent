package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestOwningUIPIDRecognizesOnlySecureAgentApp(t *testing.T) {
	for _, tc := range []struct {
		name, executable string
		owning           bool
	}{
		{"app", "/Applications/Secure Agent.app/Contents/MacOS/SecureAgent", true},
		{"renamed app", "/Applications/Local Protection.app/Contents/MacOS/SecureAgent", true},
		{"bundled interpreter", "/Applications/Editor.app/Contents/Frameworks/Python.framework/Versions/3.12/bin/python3", false},
		{"other app", "/Applications/Editor.app/Contents/MacOS/Editor", false},
		{"helper", "/Applications/Secure Agent.app/Contents/Helpers/secure-agent", false},
		{"unbundled", "/tmp/SecureAgent", false},
		{"shell", "/bin/zsh", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "ps"), []byte(fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' '%s'\n", tc.executable)), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir)
			want := int32(0)
			if tc.owning {
				want = int32(os.Getppid())
			}
			if got := owningUIPID(); got != want {
				t.Fatalf("owner pid=%d, want %d for %q", got, want, tc.executable)
			}
		})
	}
}
