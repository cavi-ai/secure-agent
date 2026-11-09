package modelservice

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRollbackChecksEveryInputBeforeRestoring(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "config.yaml")
	source := filepath.Join(root, "model.plist")
	m := New(config, nil)
	label := "com.example.model"
	if err := os.MkdirAll(m.jobDir(label), 0700); err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string]string{config: "operator changed this", source: "patched service", filepath.Join(m.jobDir(label), "original.plist"): "original service", filepath.Join(m.jobDir(label), "original.yaml"): "original config"} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r := Receipt{Preview: Preview{Label: label, Source: source}, OriginalSHA: digest([]byte("original service")), SourceSHA: digest([]byte("patched service")), ClientOldSHA: digest([]byte("original config")), ClientSHA: digest([]byte("patched config")), OriginalMode: 0600, ClientMode: 0600}
	if err := m.restore(&r); err == nil {
		t.Fatal("rollback overwrote operator changes")
	}
	current, _ := os.ReadFile(source)
	if string(current) != "patched service" {
		t.Fatal("rollback changed one file before discovering drift in another")
	}
}
