package agentenv

import (
	"strings"
	"testing"
)

func TestVarsPointAtProxyAndCA(t *testing.T) {
	v := Vars(8443, "/home/u/.config/secure-agent/ca.crt")
	if v["HTTPS_PROXY"] != "http://127.0.0.1:8443" {
		t.Fatalf("HTTPS_PROXY = %q", v["HTTPS_PROXY"])
	}
	if v["NODE_EXTRA_CA_CERTS"] != "/home/u/.config/secure-agent/ca.crt" {
		t.Fatalf("NODE_EXTRA_CA_CERTS = %q", v["NODE_EXTRA_CA_CERTS"])
	}
	// Lowercase variants matter for many CLIs.
	if v["https_proxy"] != v["HTTPS_PROXY"] {
		t.Fatal("lowercase https_proxy must match uppercase")
	}
}

func TestSnippetIsSourceableAndScoped(t *testing.T) {
	s := Snippet(8443, "/home/u/.config/secure-agent/ca.crt")
	for _, want := range []string{
		"export HTTPS_PROXY=http://127.0.0.1:8443",
		"export NODE_EXTRA_CA_CERTS=/home/u/.config/secure-agent/ca.crt",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("snippet missing %q\n---\n%s", want, s)
		}
	}
}
