package main

import (
	"os/exec"
	"strings"
	"testing"
)

// The rotate subcommand POSTed to /rotate, an endpoint deleted in the security
// remediation. It must be gone from both dispatch and help text.
func TestUsageHasNoRotate(t *testing.T) {
	out, err := exec.Command("go", "run", ".", "help").CombinedOutput()
	if err != nil {
		t.Fatalf("run help: %v\n%s", err, out)
	}
	if strings.Contains(strings.ToLower(string(out)), "rotate") {
		t.Fatalf("usage still mentions rotate:\n%s", out)
	}
}
