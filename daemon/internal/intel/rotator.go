package intel

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

type Rotator struct{}

func NewRotator() *Rotator {
	return &Rotator{}
}

// Execute performs the appropriate automated secret rotation for a given RotateItem.
func (r *Rotator) Execute(item model.RotateItem) (string, error) {
	switch item.Category {
	case model.CategoryEnvSecrets:
		return r.rotateEnvFile(item.Path)
	case model.CategorySSHKeys:
		return r.rotateSSHKeyPair(item.Path)
	case model.CategoryCloudCreds:
		return r.rotateCloudCredentials(item)
	default:
		if strings.Contains(strings.ToLower(item.Name), "env") {
			return r.rotateEnvFile(item.Path)
		}
		return fmt.Sprintf("Manual rotation required for %s: %s", item.Name, item.Action), nil
	}
}

func (r *Rotator) rotateEnvFile(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("env file path is empty")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read env file %s: %w", path, err)
	}

	lines := strings.Split(string(data), "\n")
	reSecret := regexp.MustCompile(`^(?i)(.*SECRET.*|.*KEY.*|.*TOKEN.*|.*PASSWORD.*|.*API.*)=(.*)$`)
	updatedCount := 0

	for i, line := range lines {
		lineTrim := strings.TrimSpace(line)
		if strings.HasPrefix(lineTrim, "#") {
			continue
		}
		if matches := reSecret.FindStringSubmatch(lineTrim); len(matches) == 3 {
			key := matches[1]
			newValBytes := make([]byte, 16)
			_, _ = rand.Read(newValBytes)
			newVal := "rotated_" + hex.EncodeToString(newValBytes)
			lines[i] = fmt.Sprintf("%s=%s", key, newVal)
			updatedCount++
		}
	}

	if updatedCount == 0 {
		return fmt.Sprintf("No secret key-value pairs matched for rotation in %s", path), nil
	}

	outputData := strings.Join(lines, "\n")
	if err := os.WriteFile(path, []byte(outputData), 0600); err != nil {
		return "", fmt.Errorf("failed to write rotated env file: %w", err)
	}

	return fmt.Sprintf("Successfully auto-rotated %d secret(s) in %s", updatedCount, path), nil
}

func (r *Rotator) rotateSSHKeyPair(keyPath string) (string, error) {
	home, _ := os.UserHomeDir()
	targetPath := keyPath
	if targetPath == "" {
		targetPath = filepath.Join(home, ".ssh", "id_ed25519_rotated")
	} else {
		targetPath = targetPath + "_rotated"
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to generate ed25519 key: %w", err)
	}

	pkcs8Bytes, err := ed25519MarshalPKCS8(priv)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	}

	if err := os.MkdirAll(filepath.Dir(targetPath), 0700); err != nil {
		return "", err
	}

	privPem := pem.EncodeToMemory(pemBlock)
	if err := os.WriteFile(targetPath, privPem, 0600); err != nil {
		return "", fmt.Errorf("failed to write rotated SSH private key: %w", err)
	}

	pubPath := targetPath + ".pub"
	pubStr := fmt.Sprintf("ssh-ed25519 %s secure-agent-rotated@local\n", hex.EncodeToString(pub))
	_ = os.WriteFile(pubPath, []byte(pubStr), 0644)

	return fmt.Sprintf("Generated new rotated ED25519 SSH keypair at %s", targetPath), nil
}

func (r *Rotator) rotateCloudCredentials(item model.RotateItem) (string, error) {
	if strings.Contains(strings.ToLower(item.Name), "aws") {
		if _, err := exec.LookPath("aws"); err == nil {
			cmd := exec.Command("aws", "iam", "create-access-key")
			output, err := cmd.CombinedOutput()
			if err == nil {
				return fmt.Sprintf("AWS CLI access key created successfully:\n%s", string(output)), nil
			}
		}
	}
	return fmt.Sprintf("Cloud rotation checklist initialized for %s. Execute action: %s", item.Name, item.Action), nil
}

func ed25519MarshalPKCS8(priv ed25519.PrivateKey) ([]byte, error) {
	// PKCS#8 DER header for ED25519 private key
	header := []byte{0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20}
	seed := priv.Seed()
	return append(header, seed...), nil
}
