package agentenv

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const tok = "abcdef0123456789abcdef0123456789"

// Tunnel mode: credentials in the proxy URL (the form clients turn into
// Proxy-Authorization), loopback kept off the proxy, and no CA variable — a
// tunneled client verifies the real upstream itself.
func TestVarsTunnelEveryClient(t *testing.T) {
	v := Vars(8443, tok)
	want := "http://tunnel:" + tok + "@127.0.0.1:8443"
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if v[k] != want {
			t.Errorf("%s = %q, want %q", k, v[k], want)
		}
	}
	if v["NO_PROXY"] != NoProxy || v["no_proxy"] != NoProxy {
		t.Errorf("NO_PROXY = %q / %q, want %q", v["NO_PROXY"], v["no_proxy"], NoProxy)
	}
	for _, k := range []string{"NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "PROXY_AUTHORIZATION"} {
		if _, ok := v[k]; ok {
			t.Errorf("tunnel mode sets %s; it must not replace or extend any client's trust", k)
		}
	}
}

// Inspect mode is for a client that trusts the proxy CA: the inspect user and
// NODE_EXTRA_CA_CERTS, which adds to Node's roots instead of replacing them.
func TestInspectVarsAddTheCA(t *testing.T) {
	v := InspectVars(8443, "/Users/x/.config/secure-agent/ca.crt", tok)
	if want := "http://inspect:" + tok + "@127.0.0.1:8443"; v["HTTPS_PROXY"] != want || v["https_proxy"] != want {
		t.Fatalf("HTTPS_PROXY = %q, want %q", v["HTTPS_PROXY"], want)
	}
	if v["NODE_EXTRA_CA_CERTS"] != "/Users/x/.config/secure-agent/ca.crt" || v["NO_PROXY"] != NoProxy {
		t.Fatalf("vars = %v", v)
	}
	if _, ok := v["SSL_CERT_FILE"]; ok {
		t.Fatal("SSL_CERT_FILE replaces a client's whole trust store; inspect mode must not set it")
	}
}

func TestSnippetIsSourceableAndScoped(t *testing.T) {
	s := Snippet(8443, tok)
	if !strings.Contains(s, "export HTTPS_PROXY='http://tunnel:"+tok+"@127.0.0.1:8443'") {
		t.Fatalf("snippet missing tunnel HTTPS_PROXY:\n%s", s)
	}
	if strings.Contains(s, ".zshrc") || strings.Contains(s, ".bashrc") {
		t.Fatal("snippet must not reference or modify shell rc files")
	}
	out, err := exec.Command("sh", "-c", s+"\nprintf %s \"$HTTPS_PROXY|$NO_PROXY\"").Output()
	if err != nil {
		t.Fatalf("snippet is not sourceable: %v", err)
	}
	if got, want := string(out), "http://tunnel:"+tok+"@127.0.0.1:8443|"+NoProxy; got != want {
		t.Fatalf("sourced HTTPS_PROXY|NO_PROXY = %q, want %q", got, want)
	}
}

// A config-controlled value is never interpreted by the shell that sources
// the snippet.
func TestSnippetQuotesValues(t *testing.T) {
	evil := Snippet(8443, "$(touch /tmp/pwned)")
	if !strings.Contains(evil, "'http://tunnel:$(touch /tmp/pwned)@127.0.0.1:8443'") {
		t.Fatalf("value not single-quoted:\n%s", evil)
	}
}

func TestWriteSnippetPerms(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secure-agent")
	path, err := WriteSnippet(dir, 8443, tok)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(dir, SnippetName) {
		t.Fatalf("path = %q", path)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("snippet carries the proxy token; mode = %v, want 0600", st.Mode().Perm())
	}
}
