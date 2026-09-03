package config

import (
	_ "embed"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed defaults.yaml
var defaultBytes []byte

type AgentDef struct {
	Name  string   `yaml:"name"`
	Match []string `yaml:"match"`
}

// FirewallConfig configures the egress secret-leak firewall (see the
// egress-secret-leak-firewall design doc).
type FirewallConfig struct {
	Mode     string                  `yaml:"mode"` // monitor | block (global default)
	Registry RegistryConfig          `yaml:"registry"`
	Patterns []PatternConfig         `yaml:"patterns"`
	Entropy  EntropyConfig           `yaml:"entropy"`
	Vendors  map[string]VendorConfig `yaml:"vendors"`
	Context  ContextConfig           `yaml:"context"`
}

type RegistryConfig struct {
	SaltRef       string        `yaml:"salt_ref"`
	IngestSources []string      `yaml:"ingest_sources"`
	Fingerprints  []Fingerprint `yaml:"fingerprints"`
}

type Fingerprint struct {
	ID    string `yaml:"id"`
	Type  string `yaml:"type"`
	Len   int    `yaml:"len"`
	Label string `yaml:"label"`
	HMAC  string `yaml:"hmac"`
}

type PatternConfig struct {
	ID   string `yaml:"id"`
	Type string `yaml:"type"`
	Re   string `yaml:"re"`
	Mode string `yaml:"mode"`
}

type EntropyConfig struct {
	Enabled bool    `yaml:"enabled"`
	MinLen  int     `yaml:"min_len"`
	MinBits float64 `yaml:"min_bits"`
	Mode    string  `yaml:"mode"`
}

type VendorConfig struct {
	Hosts      []string `yaml:"hosts"`
	AuthHeader string   `yaml:"auth_header"`
}

type ContextConfig struct {
	AllowOwnVendorAuth    bool `yaml:"allow_own_vendor_auth"`
	TreatBodySecretAsLeak bool `yaml:"treat_body_secret_as_leak"`
}

// WebhookConfig is one HMAC-signed fleet sink.
type WebhookConfig struct {
	URL    string   `yaml:"url"`
	Secret string   `yaml:"secret"`
	Events []string `yaml:"events"` // flag | incident | guard; empty = all
}

// FleetConfig configures downstream fleet-oversight delivery.
type FleetConfig struct {
	Webhooks []WebhookConfig `yaml:"webhooks"`
}

// CwdOverride pins one directory subtree to specific guard-rule modes — the
// per-project policy layer (deny .env in the production repo, monitor
// everywhere else). Written to guard-cwd-overrides.json for the hook to read.
type CwdOverride struct {
	CwdPrefix string            `yaml:"cwd_prefix"`
	Rules     map[string]string `yaml:"rules"` // rule_id -> monitor|prompt|deny
}

// DirectoryGuardConfig configures the interactive filesystem guard (pillar 2).
// The hook owns the rule set — it is a stdlib-only Python process and cannot
// parse YAML — via its own embedded copy plus the user's guard-modes.json
// override file. The daemon config carries only the hook's fail-safe prompt
// deadline.
type DirectoryGuardConfig struct {
	PromptDeadlineMS int           `yaml:"prompt_deadline_ms"`
	CwdOverrides     []CwdOverride `yaml:"cwd_overrides"`
}

type rawConfig struct {
	SensitiveGlobs      []string             `yaml:"sensitive_globs"`
	SensitivePaths      []string             `yaml:"sensitive_paths"`
	KeychainMarkers     []string             `yaml:"keychain_markers"`
	Agents              []AgentDef           `yaml:"agents"`
	VendorAllowlist     map[string][]string  `yaml:"vendor_allowlist"`
	NetSampleIntervalMS int64                `yaml:"net_sample_interval_ms"`
	SocketPath          string               `yaml:"socket_path"`
	DBPath              string               `yaml:"db_path"`
	JSONLPath           string               `yaml:"jsonl_path"`
	ProxyEnabled        bool                 `yaml:"proxy_enabled"`
	ProxyPort           int                  `yaml:"proxy_port"`
	ProxyCACertPath     string               `yaml:"proxy_ca_cert_path"`
	ProxyCAKeyPath      string               `yaml:"proxy_ca_key_path"`
	Firewall            FirewallConfig       `yaml:"firewall"`
	DirectoryGuard      DirectoryGuardConfig `yaml:"directory_guard"`
	Fleet               FleetConfig          `yaml:"fleet"`
}

type Config struct {
	SensitiveGlobs    []string
	SensitivePaths    []string
	KeychainMarkers   []string
	Agents            []AgentDef
	VendorAllowlist   map[string][]string
	NetSampleInterval time.Duration
	SocketPath        string
	DBPath            string
	JSONLPath         string
	ProxyEnabled      bool
	ProxyPort         int
	ProxyCACertPath   string
	ProxyCAKeyPath    string
	Firewall          FirewallConfig
	DirectoryGuard    DirectoryGuardConfig
	Fleet             FleetConfig
}

func Load(explicitPath string) (Config, error) {
	var raw rawConfig
	if err := yaml.Unmarshal(defaultBytes, &raw); err != nil {
		return Config{}, err
	}

	targetPath := explicitPath
	if targetPath == "" || targetPath == "/nonexistent" {
		home, _ := os.UserHomeDir()
		if home != "" {
			defaultOverlay := filepath.Join(home, ".config", "secure-agent", "config.yaml")
			if _, err := os.Stat(defaultOverlay); err == nil {
				targetPath = defaultOverlay
			}
		}
	}

	if targetPath != "" && targetPath != "/nonexistent" {
		if data, err := os.ReadFile(expandPath(targetPath)); err == nil {
			// Unmarshal overlay over raw config struct
			_ = yaml.Unmarshal(data, &raw)
		}
	}

	cfg := Config{
		SensitiveGlobs:    expandPaths(raw.SensitiveGlobs),
		SensitivePaths:    expandPaths(raw.SensitivePaths),
		KeychainMarkers:   raw.KeychainMarkers,
		Agents:            raw.Agents,
		VendorAllowlist:   raw.VendorAllowlist,
		NetSampleInterval: time.Duration(raw.NetSampleIntervalMS) * time.Millisecond,
		SocketPath:        expandPath(raw.SocketPath),
		DBPath:            expandPath(raw.DBPath),
		JSONLPath:         expandPath(raw.JSONLPath),
		ProxyEnabled:      raw.ProxyEnabled,
		ProxyPort:         raw.ProxyPort,
		ProxyCACertPath:   expandPath(raw.ProxyCACertPath),
		ProxyCAKeyPath:    expandPath(raw.ProxyCAKeyPath),
		Firewall:          raw.Firewall,
		DirectoryGuard:    raw.DirectoryGuard,
		Fleet:             raw.Fleet,
	}
	cfg.Firewall.Registry.SaltRef = expandPath(cfg.Firewall.Registry.SaltRef)
	cfg.Firewall.Registry.IngestSources = expandPaths(cfg.Firewall.Registry.IngestSources)

	return cfg, nil
}

// ExpandPath expands a leading ~ and $ENV references in p, matching how config
// sources are normalized at load. Exported for runtime-added ingest sources,
// which are stored raw and expanded at use.
func ExpandPath(p string) string { return expandPath(p) }

func expandPath(p string) string {
	if strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return os.ExpandEnv(p)
}

func expandPaths(paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = expandPath(p)
	}
	return out
}
