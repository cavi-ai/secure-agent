package taint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fixture struct {
	gate    *Gate
	lookups int
}

// newFixture builds a gate over real record and mode files in a temp dir;
// client 4242 belongs to session "sess-1" in /work/app.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	f := &fixture{}
	f.gate = &Gate{
		Dir:              filepath.Join(dir, "taint"),
		ModesPath:        filepath.Join(dir, "guard-modes.json"),
		CwdOverridesPath: filepath.Join(dir, "guard-cwd-overrides.json"),
		CategoriesPath:   filepath.Join(dir, "guard-categories.json"),
		Exempt:           map[string]bool{"api.anthropic.com": true},
		ClientPID: func(context.Context, string) (int32, error) {
			f.lookups++
			return 4242, nil
		},
		Sessions: func(pid int32) []Session {
			if pid != 4242 {
				return nil
			}
			return []Session{{ID: "sess-1", Workspace: "/work/app"}}
		},
	}
	if err := os.MkdirAll(f.gate.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) taint(t *testing.T, id, body string) {
	t.Helper()
	sum := sha256.Sum256([]byte(id))
	if err := os.WriteFile(filepath.Join(f.gate.Dir, hex.EncodeToString(sum[:])[:32]+".json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDenyModeRefusesTaintedSession(t *testing.T) {
	f := newFixture(t)
	f.taint(t, "sess-1", `{"ts":"2026-10-28T10:00:00Z","source":"web: https://evil.example/page","sources":[]}`)
	write(t, f.gate.ModesPath, `{"untrusted-egress":"deny"}`)

	v := f.gate.Check(context.Background(), "127.0.0.1:50000", "paste.example.net:443")
	if !v.Blocked || v.PID != 4242 || v.SessionID != "sess-1" {
		t.Fatalf("verdict = %+v, want blocked for pid 4242 in sess-1", v)
	}
	if !strings.HasPrefix(v.Detail, "proxy-untrusted-egress: paste.example.net after untrusted content (web: https://evil.example/page)") {
		t.Fatalf("detail = %q", v.Detail)
	}
}

func TestOnlyDenyRefuses(t *testing.T) {
	for _, tc := range []struct {
		name, modes, cwd string
		blocked          bool
	}{
		{"shipped monitor", "", "", false},
		{"prompt", `{"untrusted-egress":"prompt"}`, "", false},
		{"session", `{"untrusted-egress":"session"}`, "", false},
		{"unknown mode denies", `{"untrusted-egress":"block"}`, "", true},
		{"workspace overlay monitors", `{"untrusted-egress":"deny"}`, `[{"cwd_prefix":"/work","rules":{"untrusted-egress":"monitor"}}]`, false},
		{"workspace overlay denies", "", `[{"cwd_prefix":"/work/app","rules":{"untrusted-egress":"deny"}}]`, true},
		{"other workspace overlay", "", `[{"cwd_prefix":"/work/other","rules":{"untrusted-egress":"deny"}}]`, false},
		{"corrupt modes file", `{not json`, "", true},
		{"corrupt overlay file", "", `{"cwd_prefix":"/"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.taint(t, "sess-1", `{"source":"image: /tmp/x.png"}`)
			if tc.modes != "" {
				write(t, f.gate.ModesPath, tc.modes)
			}
			if tc.cwd != "" {
				write(t, f.gate.CwdOverridesPath, tc.cwd)
			}
			if v := f.gate.Check(context.Background(), "127.0.0.1:50000", "paste.example.net"); v.Blocked != tc.blocked {
				t.Fatalf("blocked = %v, want %v (%+v)", v.Blocked, tc.blocked, v)
			}
		})
	}
}

func TestUntaintedOrUnattributedClientPasses(t *testing.T) {
	f := newFixture(t)
	f.taint(t, "sess-other", `{"source":"web: https://evil.example"}`)
	write(t, f.gate.ModesPath, `{"untrusted-egress":"deny"}`)
	if v := f.gate.Check(context.Background(), "127.0.0.1:50000", "paste.example.net"); v.Blocked {
		t.Fatalf("session without a record refused: %+v", v)
	}

	f.taint(t, "sess-1", `{"source":"web: https://evil.example"}`)
	f.gate.ClientPID = func(context.Context, string) (int32, error) { return 0, errors.New("2 candidate processes") }
	if v := f.gate.Check(context.Background(), "127.0.0.1:50000", "paste.example.net"); v.Blocked {
		t.Fatalf("unattributed client refused: %+v", v)
	}
}

func TestUnreadableRecordCountsAsTaint(t *testing.T) {
	f := newFixture(t)
	f.taint(t, "sess-1", `{truncated`)
	write(t, f.gate.ModesPath, `{"untrusted-egress":"deny"}`)
	v := f.gate.Check(context.Background(), "127.0.0.1:50000", "paste.example.net")
	if !v.Blocked || !strings.Contains(v.Detail, "(unreadable)") {
		t.Fatalf("verdict = %+v, want blocked as unreadable", v)
	}
}

// The client lookup runs netstat: it is skipped for exempt hosts, while no
// session is tainted, and while no workspace resolves the rule to deny.
func TestClientLookupOnlyWhenARefusalIsPossible(t *testing.T) {
	f := newFixture(t)
	write(t, f.gate.ModesPath, `{"untrusted-egress":"deny"}`)
	f.gate.Check(context.Background(), "127.0.0.1:50000", "paste.example.net")
	if f.lookups != 0 {
		t.Fatalf("lookups without any taint record = %d", f.lookups)
	}

	f.taint(t, "sess-1", `{"source":"web: https://evil.example"}`)
	if v := f.gate.Check(context.Background(), "127.0.0.1:50000", "api.anthropic.com:443"); v.Blocked || f.lookups != 0 {
		t.Fatalf("exempt host: verdict %+v after %d lookups", v, f.lookups)
	}

	write(t, f.gate.ModesPath, `{"untrusted-egress":"monitor"}`)
	f.gate.Check(context.Background(), "127.0.0.1:50000", "paste.example.net")
	if f.lookups != 0 {
		t.Fatalf("lookups with the rule in monitor = %d", f.lookups)
	}
}

func TestInjectedRuleRaisesTheMode(t *testing.T) {
	for _, tc := range []struct {
		name, record string
		blocked      bool
	}{
		{"plain taint", `{"source":"web: https://evil.example"}`, false},
		{"injection match", `{"source":"web: https://evil.example","injection":{"match":"ignore previous"}}`, true},
		{"null injection", `{"source":"web: https://evil.example","injection":null}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.taint(t, "sess-1", tc.record)
			write(t, f.gate.ModesPath, `{"untrusted-egress":"monitor","untrusted-egress-injected":"deny"}`)
			if v := f.gate.Check(context.Background(), "127.0.0.1:50000", "paste.example.net"); v.Blocked != tc.blocked {
				t.Fatalf("blocked = %v, want %v (%+v)", v.Blocked, tc.blocked, v)
			}
		})
	}
}

func TestNetworkSendKindMode(t *testing.T) {
	for _, tc := range []struct {
		name, modes, categories string
		blocked                 bool
	}{
		{"kind denies", `{"untrusted-egress":"monitor"}`, `{"untrusted-egress":{"network-send":"deny"}}`, true},
		{"kind monitors under a deny rule", `{"untrusted-egress":"deny"}`, `{"untrusted-egress":{"network-send":"monitor"}}`, false},
		{"other kind ignored", `{"untrusted-egress":"monitor"}`, `{"untrusted-egress":{"git-push":"deny"}}`, false},
		{"unknown kind mode denies", "", `{"untrusted-egress":{"network-send":"block"}}`, true},
		{"corrupt file denies", "", `{not json`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.taint(t, "sess-1", `{"source":"web: https://evil.example"}`)
			if tc.modes != "" {
				write(t, f.gate.ModesPath, tc.modes)
			}
			write(t, f.gate.CategoriesPath, tc.categories)
			if v := f.gate.Check(context.Background(), "127.0.0.1:50000", "paste.example.net"); v.Blocked != tc.blocked {
				t.Fatalf("blocked = %v, want %v (%+v)", v.Blocked, tc.blocked, v)
			}
		})
	}
}

func TestAnyTaintedSessionOnTheRootRefuses(t *testing.T) {
	f := newFixture(t)
	f.gate.Sessions = func(int32) []Session {
		return []Session{{ID: "thread-a", Workspace: "/work/a"}, {ID: "thread-b", Workspace: "/work/b"}}
	}
	f.taint(t, "thread-b", `{"source":"web: https://evil.example"}`)
	write(t, f.gate.CwdOverridesPath, `[{"cwd_prefix":"/work/b","rules":{"untrusted-egress":"deny"}}]`)
	if v := f.gate.Check(context.Background(), "127.0.0.1:50000", "paste.example.net"); !v.Blocked || v.SessionID != "thread-b" {
		t.Fatalf("verdict = %+v, want blocked for thread-b", v)
	}
}

func TestSessionIDClipsByCharacter(t *testing.T) {
	f := newFixture(t)
	long := strings.Repeat("é", 70)
	f.gate.Sessions = func(int32) []Session { return []Session{{ID: long, Workspace: "/work/app"}} }
	f.taint(t, strings.Repeat("é", 64), `{"source":"web: https://evil.example"}`)
	write(t, f.gate.ModesPath, `{"untrusted-egress":"deny"}`)
	if v := f.gate.Check(context.Background(), "127.0.0.1:50000", "paste.example.net"); !v.Blocked {
		t.Fatalf("record under the hook's 64-character id missed: %+v", v)
	}
}
