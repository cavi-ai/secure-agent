package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// chunkReader returns one chunk per Read call, then io.EOF.
type chunkReader struct {
	chunks []string
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[0])
	r.chunks = r.chunks[1:]
	return n, nil
}

func TestPumpToSpoolWritesEachRecordIntact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spool.jsonl")
	r := &chunkReader{chunks: []string{`{"a":1}` + "\n" + `{"b":2}` + "\n" + `{"c":`, "3}\n"}}

	if err := pumpToSpoolAt(r, path); err != nil {
		t.Fatalf("pumpToSpoolAt: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read spool: %v", err)
	}
	want := `{"a":1}` + "\n" + `{"b":2}` + "\n" + `{"c":3}` + "\n"
	if string(got) != want {
		t.Fatalf("spool = %q, want %q", got, want)
	}
	for i, line := range bytes.Split(bytes.TrimSuffix(got, []byte("\n")), []byte("\n")) {
		var v map[string]any
		if err := json.Unmarshal(line, &v); err != nil {
			t.Fatalf("line %d %q is not a JSON object: %v", i, line, err)
		}
	}
}

func TestIsESCollectorInvocation(t *testing.T) {
	cases := []struct {
		argv0 string
		flag  bool
		want  bool
	}{
		{"/Applications/Secure Agent.app/Contents/MacOS/secure-agent-esd", false, true},
		{"secure-agent-esd", false, true},
		{"/Applications/Secure Agent.app/Contents/Helpers/secure-agentd", false, false},
		{"/Library/PrivilegedHelperTools/com.cavi-ai.secure-agent-esd", true, true},
		{"/usr/local/bin/secure-agent-esd-old", false, false},
		{"", false, false},
	}
	for _, c := range cases {
		if got := isESCollectorInvocation(c.argv0, c.flag); got != c.want {
			t.Errorf("isESCollectorInvocation(%q, %v) = %v, want %v", c.argv0, c.flag, got, c.want)
		}
	}
}

// stubCodesign replaces the signature check for one test and records the
// path it was asked about.
func stubCodesign(t *testing.T, result error) *string {
	t.Helper()
	var asked string
	prev := codesignVerify
	codesignVerify = func(path string) error {
		asked = path
		return result
	}
	t.Cleanup(func() { codesignVerify = prev })
	return &asked
}

func TestVerifyExecutableAcceptsSignedNonWritableBinary(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "secure-agent-esd")
	if err := os.WriteFile(exe, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	asked := stubCodesign(t, nil)
	if err := verifyExecutable(exe); err != nil {
		t.Fatalf("verifyExecutable: %v", err)
	}
	if *asked != exe {
		t.Fatalf("codesign verified %q, want %q", *asked, exe)
	}
}

func TestVerifyExecutableRefusesFailedSignature(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "secure-agent-esd")
	if err := os.WriteFile(exe, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	stubCodesign(t, errors.New("invalid signature (code or signature have been modified)"))
	err := verifyExecutable(exe)
	if err == nil || !strings.Contains(err.Error(), "code signature") {
		t.Fatalf("verifyExecutable = %v, want a code signature refusal", err)
	}
	if !IsESPermanentFailure(permanent(err)) {
		t.Fatal("a signature refusal must be permanent so launchd leaves the service stopped")
	}
}

func TestVerifyExecutableRefusesWritableBinary(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "secure-agent-esd")
	if err := os.WriteFile(exe, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(exe, 0o775); err != nil {
		t.Fatal(err)
	}
	asked := stubCodesign(t, nil)
	err := verifyExecutable(exe)
	if err == nil || !strings.Contains(err.Error(), "group/world-writable") {
		t.Fatalf("verifyExecutable = %v, want a writable-binary refusal", err)
	}
	if *asked != "" {
		t.Fatal("a writable binary must be refused before the signature check")
	}
}

func TestCodesignVerifyRealSignatures(t *testing.T) {
	if _, err := os.Stat("/usr/bin/codesign"); err != nil {
		t.Skip("codesign not available")
	}
	if err := codesignVerify("/bin/ls"); err != nil {
		t.Fatalf("codesign --verify rejected a signed system binary: %v", err)
	}
	f := filepath.Join(t.TempDir(), "unsigned")
	if err := os.WriteFile(f, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := codesignVerify(f); err == nil {
		t.Fatal("codesign --verify accepted an unsigned file")
	}
}
