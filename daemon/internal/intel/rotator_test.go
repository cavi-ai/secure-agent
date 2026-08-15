package intel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestRotateEnvFile(t *testing.T) {
	tmpDir := t.TempDir()
	envPath := filepath.Join(tmpDir, ".env")

	initialContent := "API_KEY=dummy_secret_key_123\nDB_HOST=localhost\nAWS_SECRET=my_aws_secret_val\n"
	if err := os.WriteFile(envPath, []byte(initialContent), 0600); err != nil {
		t.Fatalf("failed to write test env file: %v", err)
	}

	rotator := NewRotator()
	item := model.RotateItem{
		ID:       "rot-1",
		Category: model.CategoryEnvSecrets,
		Name:     ".env",
		Path:     envPath,
		Risk:     model.RiskCritical,
	}

	res, err := rotator.Execute(item)
	if err != nil {
		t.Fatalf("rotator.Execute failed: %v", err)
	}

	if !strings.Contains(res, "Successfully auto-rotated") {
		t.Fatalf("unexpected rotation response: %s", res)
	}

	newContentBytes, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("failed to read rotated env file: %v", err)
	}
	newContent := string(newContentBytes)

	if strings.Contains(newContent, "dummy_secret_key_123") {
		t.Fatal("old secret key still present in rotated env file!")
	}
	if strings.Contains(newContent, "my_aws_secret_val") {
		t.Fatal("old aws secret still present in rotated env file!")
	}
	if !strings.Contains(newContent, "rotated_") {
		t.Fatal("new rotated secret prefix 'rotated_' missing from env file!")
	}
}

func TestRotateSSHKeyPair(t *testing.T) {
	tmpDir := t.TempDir()
	sshKeyPath := filepath.Join(tmpDir, "id_ed25519")

	rotator := NewRotator()
	item := model.RotateItem{
		ID:       "rot-2",
		Category: model.CategorySSHKeys,
		Name:     "SSH Key",
		Path:     sshKeyPath,
		Risk:     model.RiskHigh,
	}

	res, err := rotator.Execute(item)
	if err != nil {
		t.Fatalf("rotator.Execute failed: %v", err)
	}

	if !strings.Contains(res, "Generated new rotated ED25519 SSH keypair") {
		t.Fatalf("unexpected ssh rotation response: %s", res)
	}

	rotatedPath := sshKeyPath + "_rotated"
	if _, err := os.Stat(rotatedPath); err != nil {
		t.Fatalf("rotated SSH private key file not found: %v", err)
	}
	if _, err := os.Stat(rotatedPath + ".pub"); err != nil {
		t.Fatalf("rotated SSH public key file not found: %v", err)
	}
}
