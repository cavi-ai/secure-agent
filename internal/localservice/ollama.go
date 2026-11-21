package localservice

import (
	"errors"
	"net"
	"strconv"
	"strings"
)

const (
	ScopeBrowserHardening       = "browser_hardening"
	ScopeAuthenticatedInference = "authenticated_inference"
	SupportBrowserHardeningOnly = "browser_hardening_only"
)

const defaultOllamaHost = "127.0.0.1:11434"

// OllamaLoopback returns the loopback host and port applied to an Ollama serve job.
// An empty host uses 127.0.0.1:11434. Any other host keeps its explicit port.
func OllamaLoopback(existingHost string) (host string, port int, err error) {
	host = defaultOllamaHost
	if existingHost != "" {
		host = strings.TrimPrefix(strings.TrimPrefix(existingHost, "http://"), "https://")
	}
	_, portText, splitErr := net.SplitHostPort(host)
	if splitErr != nil {
		return "", 0, errors.New("Ollama requires an explicit TCP host and port")
	}
	port, err = strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, errors.New("invalid service port")
	}
	host = "127.0.0.1:" + portText
	return host, port, nil
}

// OllamaSettings formats the loopback environment block with an empty OLLAMA_ORIGINS value.
func OllamaSettings(host string) string {
	return "OLLAMA_HOST=" + host + "\nOLLAMA_ORIGINS="
}
