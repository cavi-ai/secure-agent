package agentenv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVarsPointAtProxyAndCA(t *testing.T) {
	v := Vars(8443, "/home/u/.config/secure-agent/ca.crt", "")
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
	s := Snippet(8443, "/home/u/.config/secure-agent/ca.crt", "")
	for _, want := range []string{
		"export HTTPS_PROXY=http://127.0.0.1:8443",
		"export NODE_EXTRA_CA_CERTS=/home/u/.config/secure-agent/ca.crt",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("snippet missing %q\n---\n%s", want, s)
		}
	}
}

func TestWriteSnippetCreatesFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cfg")
	path, err := WriteSnippet(dir, 8443, "/ca.crt", "")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != SnippetName {
		t.Fatalf("path base = %q, want %q", filepath.Base(path), SnippetName)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "export HTTPS_PROXY=http://127.0.0.1:8443") {
		t.Fatalf("written snippet missing proxy export:\n%s", data)
	}
}

func TestVarsCarryProxyToken(t *testing.T) {
	v := Vars(8443, "/ca.crt", "abcdef0123456789abcdef0123456789")
	if v["PROXY_AUTHORIZATION"] != "Basic abcdef0123456789abcdef0123456789" {
		t.Fatalf("PROXY_AUTHORIZATION = %q", v["PROXY_AUTHORIZATION"])
	}
	if v["X_SECURE_AGENT_PROXY_TOKEN"] != "abcdef0123456789abcdef0123456789" {
		t.Fatalf("X_SECURE_AGENT_PROXY_TOKEN = %q", v["X_SECURE_AGENT_PROXY_TOKEN"])
	}
	// No token: the vars must stay clean of auth lines.
	if v2 := Vars(8443, "/ca.crt", ""); v2["PROXY_AUTHORIZATION"] != "" {
		t.Fatalf("empty token leaked: %q", v2["PROXY_AUTHORIZATION"])
	}
}

func TestWriteSnippetPermsWithToken(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cfg")
	path, err := WriteSnippet(dir, 8443, "/ca.crt", "abcdef0123456789abcdef0123456789")
	if err != nil {
		t.Fatal(err)
	}
	// The snippet carries the proxy token now: 0600, not 0644.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("snippet perms = %v, want 0600", fi.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "PROXY_AUTHORIZATION=Basic abcdef0123456789abcdef0123456789") {
		t.Fatalf("snippet missing token auth line:\n%s", data)
	}
}
