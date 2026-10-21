package collect

import (
	"os"
	"path/filepath"
	"testing"
)

// fakeLoginShell writes a shell that, only when started as a login shell,
// prints startup noise and exports HERMES_HOME before running the command.
func fakeLoginShell(t *testing.T, home string) string {
	t.Helper()
	shell := filepath.Join(t.TempDir(), "login-shell")
	script := "#!/bin/sh\n[ \"$1\" = -l ] || exit 9\nshift\necho 'profile noise'\nHERMES_HOME='" + home + "'\nexport HERMES_HOME\nexec /bin/sh \"$@\"\n"
	if err := os.WriteFile(shell, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return shell
}

func TestLoginShellValuesReadsExportsPastStartupOutput(t *testing.T) {
	t.Setenv("HERMES_HOME", "")
	t.Setenv("HERMES_STATE_DIR", "")
	got := loginShellValues(fakeLoginShell(t, "/from/profile"), []string{"HERMES_STATE_DIR", "HERMES_HOME"})
	if got["HERMES_HOME"] != "/from/profile" || got["HERMES_STATE_DIR"] != "" || len(got) != 2 {
		t.Fatalf("values = %q, want HERMES_HOME from the login shell only", got)
	}
}

func TestLoginShellValuesRefusesUnsafeInput(t *testing.T) {
	shell := fakeLoginShell(t, "/from/profile")
	if got := loginShellValues("login-shell", []string{"HERMES_HOME"}); got != nil {
		t.Fatalf("relative shell = %q, want nil", got)
	}
	if got := loginShellValues(shell, []string{"HERMES_HOME}; touch x; ${HOME"}); got != nil {
		t.Fatalf("non-variable key = %q, want nil", got)
	}
	if got := loginShellValues(filepath.Join(t.TempDir(), "missing"), []string{"HERMES_HOME"}); got != nil {
		t.Fatalf("missing shell = %q, want nil", got)
	}
}
