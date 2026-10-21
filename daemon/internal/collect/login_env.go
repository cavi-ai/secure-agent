package collect

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// loginShellTimeout bounds the login shell a lookup starts.
const loginShellTimeout = 5 * time.Second

// LoginShellEnv looks up keys as the user's login shell ($SHELL -l) exports
// them: a daemon launched by launchd does not inherit what shell profiles
// export. The shell runs once, on the first lookup, and only these keys are
// read back from it.
func LoginShellEnv(keys ...string) func(string) string {
	values := sync.OnceValue(func() map[string]string {
		return loginShellValues(os.Getenv("SHELL"), keys)
	})
	return func(key string) string { return values()[key] }
}

// loginShellValues runs shell as a login shell that prints a NUL before each
// key's value, so output from its startup files cannot shift them. nil when
// shell is not an absolute path, a key is not a variable name, or the shell
// fails or outlives loginShellTimeout.
func loginShellValues(shell string, keys []string) map[string]string {
	if !filepath.IsAbs(shell) || len(keys) == 0 {
		return nil
	}
	script := `printf '\0%s'`
	for _, k := range keys {
		if !isVarName(k) {
			return nil
		}
		script += ` "${` + k + `-}"`
	}
	ctx, cancel := context.WithTimeout(context.Background(), loginShellTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, shell, "-l", "-c", script)
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	fields := strings.Split(string(out), "\x00")
	if len(fields) <= len(keys) {
		return nil
	}
	fields = fields[len(fields)-len(keys):]
	values := make(map[string]string, len(keys))
	for i, k := range keys {
		values[k] = fields[i]
	}
	return values
}

func isVarName(s string) bool {
	for i, r := range s {
		if r != '_' && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (i == 0 || r < '0' || r > '9') {
			return false
		}
	}
	return s != ""
}
