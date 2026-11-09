package modelruntime

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCapabilitiesRejectLegacyMalformedAndExcessOutput(t *testing.T) {
	for name, script := range map[string]string{
		"compatible": `case "$2" in private-worker) echo '{"protocol":"inherited-unix-v1"}';; protected-service) echo '{"protocol":"protected-service-v1"}';; esac`,
		"legacy":     `echo '{"protocol":"tcp"}'`,
		"malformed":  `echo invalid`,
		"excess":     `head -c 5000 /dev/zero`,
	} {
		t.Run(name, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "engine")
			if err := os.WriteFile(binary, []byte("#!/bin/sh\n"+script+"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			err := Check(context.Background(), binary)
			if (err == nil) != (name == "compatible") {
				t.Fatalf("Check: %v", err)
			}
		})
	}
}

func TestOwnedRuntimeRequiresPrivateUnlinkedMarkers(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	os.Mkdir(filepath.Join(root, "bin"), 0700)
	binary := filepath.Join(root, "bin", "mlx-agent")
	os.WriteFile(binary, []byte("#!/bin/sh\n"), 0700)
	ready := filepath.Join(root, ".ready")
	os.WriteFile(ready, []byte(Revision), 0600)
	if ownedAt(root) != binary {
		t.Fatal("owned runtime refused")
	}
	os.Chmod(ready, 0644)
	if ownedAt(root) != "" {
		t.Fatal("public marker admitted")
	}
	os.Chmod(ready, 0600)
	os.Link(ready, filepath.Join(root, "linked"))
	if ownedAt(root) != "" {
		t.Fatal("linked marker admitted")
	}
	os.Remove(ready)
	os.Symlink(filepath.Join(root, "linked"), ready)
	if ownedAt(root) != "" {
		t.Fatal("symlink marker admitted")
	}
}

func TestMarkerReadIsBoundedAndRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "marker")
	os.WriteFile(path, []byte(strings.Repeat("x", 4097)), 0600)
	if _, err := readMarker(path); err == nil {
		t.Fatal("large marker admitted")
	}
	os.Remove(path)
	os.Symlink("missing", path)
	if _, err := readMarker(path); err == nil {
		t.Fatal("symlink admitted")
	}
}

func TestNativePinnedInstall(t *testing.T) {
	root := os.Getenv("SECURE_AGENT_TEST_INSTALL_ROOT")
	if root == "" {
		t.Skip("opt-in private pinned runtime installation")
	}
	if !filepath.IsAbs(root) {
		t.Fatal("absolute private test root required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	source := "git+https://github.com/cavi-ai/mlx-agent.git@" + Revision
	binary, err := install(ctx, root, source, os.Stdout)
	if err != nil {
		t.Fatal(err)
	}
	if ownedAt(filepath.Dir(filepath.Dir(binary))) != binary {
		t.Fatal("installed runtime is not privately owned")
	}
	again, err := install(ctx, root, source, io.Discard)
	if err != nil || again != binary {
		t.Fatalf("idempotent install: %s %v", again, err)
	}
	t.Logf("installed and checked pinned runtime %s", binary)
}
