package localservice

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestModelKeyFileNeverOverwritesAndRejectsUnsafeFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "model.key")
	if err := CreateKeyFile(path); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(path)
	if err := CreateKeyFile(path); err == nil {
		t.Fatal("key overwritten")
	}
	req, _ := http.NewRequest("GET", "http://localhost:8000/v1/models", nil)
	if err := Authorize(req, path); err != nil || req.Header.Get("Authorization") != "Bearer "+strings.TrimSpace(string(first)) || req.URL.Host != "localhost:8000" {
		t.Fatalf("local client authentication: %v", err)
	}
	rotated := strings.Repeat("R", 43)
	if err := os.WriteFile(path, []byte(rotated), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Authorize(req, path); err != nil || req.Header.Get("Authorization") != "Bearer "+rotated {
		t.Fatal("rotated credential was not reopened")
	}
	for _, mode := range []os.FileMode{0644, 0620} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if err := Authorize(req, path); err == nil || strings.Contains(err.Error(), path) || strings.Contains(err.Error(), string(first)) {
			t.Fatalf("unsafe file or sensitive error: %v", err)
		}
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := Authorize(req, link); err == nil {
		t.Fatal("symlink key accepted")
	}
	remote, _ := http.NewRequest("GET", "http://example.com/v1/models", nil)
	if err := Authorize(remote, path); err == nil || remote.Header.Get("Authorization") != "" {
		t.Fatal("credential sent to non-loopback target")
	}
	if err := os.WriteFile(path, []byte("invalid\r\nheader"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Authorize(req, path); err == nil {
		t.Fatal("invalid key accepted")
	}
}
