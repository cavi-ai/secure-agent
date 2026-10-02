// Package agentenv generates the scoped environment that routes an agent
// process through the local inspection proxy. It sets per-process variables
// only; it never modifies the system trust store or the user's shell
// configuration. Applying it is the user's own opt-in.
package agentenv

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SnippetName is the file the routing snippet is written as.
const SnippetName = "agent-env.sh"

// NoProxy keeps loopback traffic (dev servers, local model servers, the
// daemon itself) off the proxy.
const NoProxy = "localhost,127.0.0.1,::1"

// Proxy URL user names select the proxy's mode for the connection (see
// proxy.authorize): inspect decrypts the proxy's inspect hosts, tunnel passes
// every connection through unopened.
const (
	InspectUser = "inspect"
	TunnelUser  = "tunnel"
)

// WriteSnippet writes the tunnel-mode routing snippet to dir/agent-env.sh
// (0600 — it carries the proxy token) and returns its path. It only writes
// into the app's own config dir; it never touches the user's shell rc or the
// system trust store.
func WriteSnippet(dir string, proxyPort int, proxyToken string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, SnippetName)
	if err := os.WriteFile(path, []byte(Snippet(proxyPort, proxyToken)), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// ProxyURL is the proxy at 127.0.0.1:proxyPort with the token as the basic
// auth password and user selecting the mode, the form HTTP clients read from
// HTTPS_PROXY and turn into a Proxy-Authorization header.
func ProxyURL(proxyPort int, proxyToken, user string) string {
	return fmt.Sprintf("http://%s:%s@127.0.0.1:%d", user, proxyToken, proxyPort)
}

// Vars returns the tunnel-mode environment: every HTTP(S) connection goes
// through the proxy unopened, so the destination is recorded and no client
// needs the proxy CA. Both upper- and lower-case proxy variables are set
// because CLIs disagree on which they read.
func Vars(proxyPort int, proxyToken string) map[string]string {
	return proxyVars(ProxyURL(proxyPort, proxyToken, TunnelUser))
}

// InspectVars returns the environment for a client that trusts the proxy CA
// (Claude Code reads NODE_EXTRA_CA_CERTS): its connections to the proxy's
// inspect hosts are decrypted and scanned, the rest are tunneled.
func InspectVars(proxyPort int, caCertPath, proxyToken string) map[string]string {
	v := proxyVars(ProxyURL(proxyPort, proxyToken, InspectUser))
	v["NODE_EXTRA_CA_CERTS"] = caCertPath
	return v
}

func proxyVars(proxy string) map[string]string {
	return map[string]string{
		"HTTP_PROXY":  proxy,
		"HTTPS_PROXY": proxy,
		"http_proxy":  proxy,
		"https_proxy": proxy,
		"NO_PROXY":    NoProxy,
		"no_proxy":    NoProxy,
	}
}

// shellQuote single-quotes a value for POSIX sh, so a config-controlled value
// containing shell metacharacters is never interpreted by the shell that
// sources the snippet.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Snippet renders Vars as a POSIX-sh sourceable script. It is written to the
// app's own config dir and sourced by the user in a shell where they run
// agents, or appended to a routed Claude Code session's Bash environment by
// its SessionStart hook — never appended to a shell rc by the daemon.
func Snippet(proxyPort int, proxyToken string) string {
	v := Vars(proxyPort, proxyToken)
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString("# Secure Agent — route this shell's agents through the local proxy.\n")
	b.WriteString("# Source this file (e.g. `source ~/.config/secure-agent/agent-env.sh`).\n")
	b.WriteString("# Remove it, or unset these variables, to stop routing.\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "export %s=%s\n", k, shellQuote(v[k]))
	}
	return b.String()
}
