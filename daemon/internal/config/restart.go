package config

import "reflect"

// startOnly lists the settings the daemon reads only at start, by their
// config.yaml key. The config watcher applies every other setting live:
// agents and disabled_agents, advisor, fleet, pricing, resource_control,
// system_agent and worktrees.
var startOnly = []struct {
	key string
	get func(Config) any
}{
	{"sensitive_globs", func(c Config) any { return c.SensitiveGlobs }},
	{"sensitive_paths", func(c Config) any { return c.SensitivePaths }},
	{"not_secret_paths", func(c Config) any { return c.NotSecretPaths }},
	{"keychain_markers", func(c Config) any { return c.KeychainMarkers }},
	{"vendor_allowlist", func(c Config) any { return c.VendorAllowlist }},
	{"credential_owners", func(c Config) any { return c.CredentialOwners }},
	{"net_sample_interval_ms", func(c Config) any { return c.NetSampleInterval }},
	{"socket_path", func(c Config) any { return c.SocketPath }},
	{"db_path", func(c Config) any { return c.DBPath }},
	{"jsonl_path", func(c Config) any { return c.JSONLPath }},
	{"openclaw_home", func(c Config) any { return c.OpenclawHome }},
	{"hermes_home", func(c Config) any { return c.HermesHome }},
	{"proxy_enabled", func(c Config) any { return c.ProxyEnabled }},
	{"proxy_port", func(c Config) any { return c.ProxyPort }},
	{"proxy_ca_cert_path", func(c Config) any { return c.ProxyCACertPath }},
	{"proxy_ca_key_path", func(c Config) any { return c.ProxyCAKeyPath }},
	{"proxy_inspect_hosts", func(c Config) any { return c.ProxyInspectHosts }},
	{"firewall", func(c Config) any { return c.Firewall }},
	{"directory_guard", func(c Config) any { return c.DirectoryGuard }},
	{"retention", func(c Config) any { return c.Retention }},
	{"otlp", func(c Config) any { return c.OTLP }},
}

// RestartSettings returns the config.yaml keys of start-only settings that
// differ between running and loaded, in a fixed order; empty when a restart
// would change nothing.
func RestartSettings(running, loaded Config) []string {
	var keys []string
	for _, s := range startOnly {
		if !reflect.DeepEqual(s.get(running), s.get(loaded)) {
			keys = append(keys, s.key)
		}
	}
	return keys
}
