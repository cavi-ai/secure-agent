package proxy

import (
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadTokenPersistsHexAnd0600(t *testing.T) {
	t.Cleanup(clearProxyToken)
	p := filepath.Join(t.TempDir(), "proxy-token")
	a := LoadToken(p)
	if !isHexToken(a) {
		t.Fatalf("generated token %q", a)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("perms = %o, want 0600", fi.Mode().Perm())
	}
	if b := LoadToken(p); a != b {
		t.Fatalf("token not stable: %q vs %q", a, b)
	}
}

func TestLoadTokenMalformedRegenerates(t *testing.T) {
	t.Cleanup(clearProxyToken)
	p := filepath.Join(t.TempDir(), "proxy-token")
	if err := os.WriteFile(p, []byte("not-a-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := LoadToken(p)
	if !isHexToken(got) {
		t.Fatalf("malformed file not regenerated: %q", got)
	}
}

func TestProxyAuthFailClosedWithoutToken(t *testing.T) {
	t.Cleanup(clearProxyToken)
	clearProxyToken()
	req, err := http.NewRequest("GET", "http://127.0.0.1/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if authorizeOK(req) {
		t.Fatal("empty proxy token must fail closed — a security product never becomes an open relay")
	}
}

func TestProxyAuthRejectsWrongToken(t *testing.T) {
	t.Cleanup(clearProxyToken)
	tok := LoadToken(filepath.Join(t.TempDir(), "proxy-token"))
	req, err := http.NewRequest("GET", "http://127.0.0.1/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if authorizeOK(req) {
		t.Fatal("missing token must be rejected")
	}
	req.Header.Set("X-SecureAgent-Proxy-Token", "00000000000000000000000000000000")
	if authorizeOK(req) {
		t.Fatal("wrong token must be rejected")
	}
	req.Header.Set("X-SecureAgent-Proxy-Token", tok)
	if !authorizeOK(req) {
		t.Fatal("correct custom header must pass")
	}
	req2, err := http.NewRequest("GET", "http://127.0.0.1/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req2.Header.Set("Proxy-Authorization", "Basic "+tok)
	if !authorizeOK(req2) {
		t.Fatal("Proxy-Authorization Basic must pass")
	}
}

func TestConsoleAuthFailClosedWithoutToken(t *testing.T) {
	t.Cleanup(clearConsoleToken)
	clearConsoleToken()
	req, err := http.NewRequest("GET", "http://127.0.0.1/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	if consoleAuthorized(req) {
		t.Fatal("empty console token must fail closed")
	}
}

func TestConsoleAuthRejectsProxyToken(t *testing.T) {
	t.Cleanup(clearProxyToken)
	t.Cleanup(clearConsoleToken)
	dir := t.TempDir()
	ct := LoadConsoleToken(filepath.Join(dir, "console-token"))
	pt := LoadToken(filepath.Join(dir, "proxy-token"))
	if ct == pt {
		t.Fatal("console and proxy tokens must be independent credentials")
	}
	req, err := http.NewRequest("GET", "http://127.0.0.1/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-SecureAgent-Proxy-Token", pt)
	if consoleAuthorized(req) {
		t.Fatal("proxy token must not authorize the console API")
	}
	req.Header.Set("X-SecureAgent-Console-Token", ct)
	if !consoleAuthorized(req) {
		t.Fatal("console token header must pass")
	}
	req2, err := http.NewRequest("GET", "http://127.0.0.1/status?ct="+ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !consoleAuthorized(req2) {
		t.Fatal("ct query must pass")
	}
}

func TestLoadConsoleTokenPersists0600(t *testing.T) {
	t.Cleanup(clearConsoleToken)
	p := filepath.Join(t.TempDir(), "console-token")
	if !isHexToken(LoadConsoleToken(p)) {
		t.Fatal("console token generation failed")
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("perms = %o, want 0600", fi.Mode().Perm())
	}
}

func authorizeOK(r *http.Request) bool {
	_, ok := authorize(r)
	return ok
}

// Credentials in the proxy URL arrive base64-encoded; the user name picks the
// mode, the password must be the token.
func TestProxyAuthModesFromProxyURLCredentials(t *testing.T) {
	t.Cleanup(clearProxyToken)
	tok := LoadToken(filepath.Join(t.TempDir(), "proxy-token"))
	basic := func(userpass string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(userpass))
	}
	for _, tc := range []struct {
		header string
		mode   Mode
		ok     bool
	}{
		{basic("tunnel:" + tok), ModeTunnel, true},
		{basic("inspect:" + tok), ModeInspect, true},
		{basic("anyone:" + tok), ModeInspect, true},
		{basic("tunnel:00000000000000000000000000000000"), ModeInspect, false},
		{basic("tunnel"), ModeInspect, false},
		{"Basic " + tok, ModeInspect, true},
		{"Basic not-base64!", ModeInspect, false},
	} {
		req, _ := http.NewRequest("CONNECT", "http://api.example.com:443", nil)
		req.Header.Set("Proxy-Authorization", tc.header)
		mode, ok := authorize(req)
		if ok != tc.ok || (ok && mode != tc.mode) {
			t.Errorf("%q: mode %v ok %v, want mode %v ok %v", tc.header, mode, ok, tc.mode, tc.ok)
		}
	}
}
