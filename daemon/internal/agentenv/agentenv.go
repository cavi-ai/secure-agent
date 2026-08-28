// Package agentenv generates the scoped environment that routes an agent
// process through the local inspection proxy while trusting its CA. It sets
// per-process variables only; it never modifies the system trust store or the
// user's shell configuration. Applying the snippet is the user's own opt-in.
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

// WriteSnippet writes the routing snippet to dir/agent-env.sh (0644) and returns
// its path. It only writes into the app's own config dir; it never touches the
// user's shell rc or the system trust store.
func WriteSnippet(dir string, proxyPort int, caCertPath string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, SnippetName)
	if err := os.WriteFile(path, []byte(Snippet(proxyPort, caCertPath)), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// Vars returns the environment variables that route an agent through the proxy
// at 127.0.0.1:proxyPort and make it trust the proxy CA at caCertPath. Both
// upper- and lower-case proxy variables are set because CLIs disagree on which
// they read; the CA variables cover Node, OpenSSL, and Python-requests clients.
func Vars(proxyPort int, caCertPath string) map[string]string {
	proxy := fmt.Sprintf("http://127.0.0.1:%d", proxyPort)
	return map[string]string{
		"HTTP_PROXY":          proxy,
		"HTTPS_PROXY":         proxy,
		"http_proxy":          proxy,
		"https_proxy":         proxy,
		"NODE_EXTRA_CA_CERTS": caCertPath,
		"SSL_CERT_FILE":       caCertPath,
		"REQUESTS_CA_BUNDLE":  caCertPath,
	}
}

// Snippet renders Vars as a POSIX-sh sourceable script. Intended to be written
// to the app's own config dir and sourced by the user in the shell where they
// run agents — not appended to a shell rc by the daemon.
func Snippet(proxyPort int, caCertPath string) string {
	v := Vars(proxyPort, caCertPath)
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	b.WriteString("# Secure Agent — route this shell's agents through the local inspection proxy.\n")
	b.WriteString("# Source this file (e.g. `source ~/.config/secure-agent/agent-env.sh`).\n")
	b.WriteString("# Remove it, or unset these variables, to stop routing.\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "export %s=%s\n", k, v[k])
	}
	return b.String()
}
