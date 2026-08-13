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

type rawConfig struct {
	SensitiveGlobs       []string            `yaml:"sensitive_globs"`
	SensitivePaths       []string            `yaml:"sensitive_paths"`
	KeychainMarkers      []string            `yaml:"keychain_markers"`
	Agents               []AgentDef          `yaml:"agents"`
	VendorAllowlist      map[string][]string `yaml:"vendor_allowlist"`
	NetSampleIntervalMS int64               `yaml:"net_sample_interval_ms"`
	SocketPath           string              `yaml:"socket_path"`
	DBPath               string              `yaml:"db_path"`
	JSONLPath            string              `yaml:"jsonl_path"`
	ProxyEnabled         bool                `yaml:"proxy_enabled"`
	ProxyPort            int                 `yaml:"proxy_port"`
	ProxyCACertPath      string              `yaml:"proxy_ca_cert_path"`
	ProxyCAKeyPath       string              `yaml:"proxy_ca_key_path"`
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
	}

	return cfg, nil
}

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
