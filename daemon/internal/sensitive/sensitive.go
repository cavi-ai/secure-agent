package sensitive

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

type Category int

const (
	CatOther Category = iota
	CatEnvFile
	CatSSHKey
	CatAWS
	CatKeychain
)

func (c Category) String() string {
	switch c {
	case CatEnvFile:
		return "env_file"
	case CatSSHKey:
		return "ssh_key"
	case CatAWS:
		return "aws_credentials"
	case CatKeychain:
		return "keychain"
	default:
		return "other_sensitive"
	}
}

type Classifier interface {
	Classify(path string) (Category, bool)
}

type classifierImpl struct {
	cfg      config.Config
	sshKeyRe *regexp.Regexp
}

func New(cfg config.Config) Classifier {
	return &classifierImpl{
		cfg:      cfg,
		sshKeyRe: regexp.MustCompile(`/\.ssh/(id_[a-z0-9_-]+|.*_(rsa|dsa|ecdsa|ed25519))$`),
	}
}

func (c *classifierImpl) Classify(path string) (Category, bool) {
	if path == "" {
		return CatOther, false
	}
	clean := filepath.Clean(path)
	lower := strings.ToLower(clean)

	// 1. Keychain markers
	for _, marker := range c.cfg.KeychainMarkers {
		if strings.Contains(lower, strings.ToLower(marker)) {
			return CatKeychain, true
		}
	}

	// 2. SSH key paths
	if strings.Contains(lower, "/.ssh/") || strings.HasSuffix(lower, "/.ssh") {
		if c.sshKeyRe.MatchString(clean) || strings.Contains(lower, "/.ssh/id_") {
			return CatSSHKey, true
		}
	}

	// 3. AWS credentials
	if strings.Contains(lower, "/.aws/") || strings.HasSuffix(lower, "/.aws") {
		return CatAWS, true
	}

	// 4. .env files
	base := filepath.Base(clean)
	if base == ".env" || strings.HasPrefix(base, ".env.") {
		return CatEnvFile, true
	}

	// 5. Check configured sensitive paths (prefix)
	for _, sp := range c.cfg.SensitivePaths {
		spClean := filepath.Clean(sp)
		if strings.HasPrefix(clean, spClean) {
			return CatOther, true
		}
	}

	// 6. Check configured globs
	for _, glob := range c.cfg.SensitiveGlobs {
		globClean := filepath.Clean(glob)
		globBase := filepath.Base(globClean)
		if matched, _ := filepath.Match(globBase, base); matched {
			return CatOther, true
		}
		if matched, _ := filepath.Match(globClean, clean); matched {
			return CatOther, true
		}
	}

	return CatOther, false
}
