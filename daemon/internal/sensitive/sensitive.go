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
	CatKeychainSystem
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
	case CatKeychainSystem:
		return "keychain_system_trust"
	default:
		return "other_sensitive"
	}
}

// Match is a classification with the rule that produced it, so a flag's
// evidence can say why a path counted as sensitive.
type Match struct {
	Category Category
	Rule     string // system-trust | keychain:<marker> | ssh-key | aws | env-file | path:<prefix> | glob:<pattern>
}

// CategoryForRule maps a Match.Rule string (as stamped on flag evidence) back
// to the category the classifier assigned with it. Configured path and glob
// rules, and unknown or empty rules, are CatOther.
func CategoryForRule(rule string) Category {
	switch {
	case rule == "system-trust":
		return CatKeychainSystem
	case strings.HasPrefix(rule, "keychain:"):
		return CatKeychain
	case rule == "ssh-key":
		return CatSSHKey
	case rule == "aws":
		return CatAWS
	case rule == "env-file":
		return CatEnvFile
	default:
		return CatOther
	}
}

type Classifier interface {
	Classify(path string) (Category, bool)
	Match(path string) (Match, bool)
}

type classifierImpl struct {
	cfg config.Config
}

func New(cfg config.Config) Classifier {
	return &classifierImpl{cfg: cfg}
}

// sshPrivateKeyRe is the one SSH private key rule: id_* or *_rsa|_dsa|_ecdsa|
// _ed25519 under a .ssh directory. A name ending in a dotted suffix
// (id_ed25519.pub) is not a key. plugin/hooks/secret_guard.py mirrors it,
// and testdata/paths.json pins both.
var sshPrivateKeyRe = regexp.MustCompile(`(?i)/\.ssh/(?:[^/]+/)*(id_[a-z0-9_-]+|[^/]*_(rsa|dsa|ecdsa|ed25519))$`)

// SSHPrivateKey reports whether path is a private SSH key.
func SSHPrivateKey(path string) bool {
	return sshPrivateKeyRe.MatchString(filepath.Clean(path))
}

// EnvSecret reports whether a file name is an environment file holding
// values: .env or .env.<name>, but not a committed template (.env.example,
// .env.sample, .env.template, .env.dist).
func EnvSecret(base string) bool {
	lower := strings.ToLower(base)
	if envTemplates[lower] {
		return false
	}
	return lower == ".env" || strings.HasPrefix(lower, ".env.")
}

func (c *classifierImpl) Classify(path string) (Category, bool) {
	m, ok := c.Match(path)
	return m.Category, ok
}

func (c *classifierImpl) Match(path string) (Match, bool) {
	if path == "" {
		return Match{Category: CatOther}, false
	}
	clean := filepath.Clean(path)
	lower := strings.ToLower(clean)

	// 1a. System trust store: reading these files is what macOS does when
	// ANY app evaluates a certificate chain (code signing, TLS, package
	// verification). Agents read them constantly for ordinary work — this
	// is not a secret and not exfiltratable identity material. Classify
	// separately so the keychain rule doesn't fire CRITICAL on it.
	if strings.Contains(lower, "systemtrustsettings.plist") ||
		strings.Contains(lower, "/system/library/keychains/") {
		return Match{CatKeychainSystem, "system-trust"}, true
	}

	// 1b. Keychain markers (user keychains — the actual secrets).
	for _, marker := range c.cfg.KeychainMarkers {
		if strings.Contains(lower, strings.ToLower(marker)) {
			return Match{CatKeychain, "keychain:" + marker}, true
		}
	}

	// 2. SSH private keys (public keys and ~/.ssh/config are not secrets)
	if SSHPrivateKey(clean) {
		return Match{CatSSHKey, "ssh-key"}, true
	}

	// 3. AWS credentials
	if strings.Contains(lower, "/.aws/") || strings.HasSuffix(lower, "/.aws") {
		return Match{CatAWS, "aws"}, true
	}

	// 5. Configured non-secret directories, then sensitive paths (prefix)
	for _, np := range c.cfg.NotSecretPaths {
		npClean := filepath.Clean(np)
		if clean == npClean || strings.HasPrefix(clean, npClean+"/") {
			return Match{Category: CatOther}, false
		}
	}

	// 4. .env files. A template (.env.example, .env.sample, .env.template,
	// .env.dist) is a committed placeholder, not a secret, under any rule.
	base := filepath.Base(clean)
	if envTemplates[strings.ToLower(base)] {
		return Match{Category: CatOther}, false
	}
	if EnvSecret(base) {
		return Match{CatEnvFile, "env-file"}, true
	}

	for _, sp := range c.cfg.SensitivePaths {
		spClean := filepath.Clean(sp)
		if strings.HasPrefix(clean, spClean) {
			return Match{CatOther, "path:" + sp}, true
		}
	}

	// 6. Check configured globs
	for _, glob := range c.cfg.SensitiveGlobs {
		if globMatches(filepath.Clean(glob), clean) {
			return Match{CatOther, "glob:" + glob}, true
		}
	}

	return Match{Category: CatOther}, false
}

var envTemplates = map[string]bool{".env.example": true, ".env.sample": true, ".env.template": true, ".env.dist": true}

// globMatches: a bare-name glob (".env", "*.keychain-db") or one anchored
// with "**/" matches the file name anywhere; a glob with a directory
// component matches the whole path only.
func globMatches(glob, path string) bool {
	if rest, ok := strings.CutPrefix(glob, "**/"); ok {
		glob = rest
	}
	if !strings.Contains(glob, "/") {
		ok, _ := filepath.Match(glob, filepath.Base(path))
		return ok
	}
	ok, _ := filepath.Match(glob, path)
	return ok
}
