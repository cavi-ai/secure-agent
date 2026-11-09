// Package modelservice applies reviewed hardening to identified owner launchd jobs.
package modelservice

import (
	"errors"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

type Change struct {
	Runtime string `json:"runtime"`
	Scope   string `json:"scope"`
	Port    int    `json:"port"`
}

func arguments(job map[string]any) ([]string, error) {
	raw, ok := job["ProgramArguments"].([]any)
	if !ok || len(raw) < 1 || len(raw) > 128 {
		return nil, errors.New("service must have a direct ProgramArguments launcher")
	}
	args := make([]string, len(raw))
	for i, value := range raw {
		arg, ok := value.(string)
		if !ok || len(arg) > 4096 || strings.ContainsAny(arg, "\x00\r\n") {
			return nil, errors.New("unsupported service arguments")
		}
		args[i] = arg
	}
	if !filepath.IsAbs(args[0]) {
		return nil, errors.New("service executable must be absolute")
	}
	if program, ok := job["Program"]; ok && program != args[0] {
		return nil, errors.New("separate Program override is unsupported")
	}
	for _, key := range []string{"Sockets", "inetdCompatibility", "UserName", "GroupName", "RootDirectory"} {
		if _, ok := job[key]; ok {
			return nil, errors.New("socket activation and alternate service identities are unsupported")
		}
	}
	if job["AbandonProcessGroup"] == true {
		return nil, errors.New("services abandoning their process group are unsupported")
	}
	return args, nil
}

func options(args []string) (map[string]string, error) {
	values := map[string]string{}
	for i := 1; i < len(args); i++ {
		key, value, inline := strings.Cut(args[i], "=")
		if !strings.HasPrefix(key, "-") {
			continue
		}
		if !inline && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			i++
			value = args[i]
		}
		if _, exists := values[key]; exists {
			return nil, errors.New("duplicate service options require manual review")
		}
		values[key] = value
	}
	return values, nil
}

func adapt(job map[string]any, keyPath, engine string) (Change, error) {
	change := Change{}
	args, err := arguments(job)
	if err != nil {
		return change, err
	}
	env, ok := job["EnvironmentVariables"].(map[string]any)
	if !ok {
		if job["EnvironmentVariables"] != nil {
			return change, errors.New("unsupported service environment")
		}
		env = map[string]any{}
	}
	for _, value := range env {
		if _, ok := value.(string); !ok {
			return change, errors.New("unsupported service environment")
		}
	}
	if filepath.Base(args[0]) == "ollama" && len(args) == 2 && args[1] == "serve" {
		host := "127.0.0.1:11434"
		if value, ok := env["OLLAMA_HOST"].(string); ok && value != "" {
			host = strings.TrimPrefix(strings.TrimPrefix(value, "http://"), "https://")
		}
		_, port, err := net.SplitHostPort(host)
		if err != nil {
			return change, errors.New("Ollama requires an explicit TCP host and port")
		}
		change.Port, err = strconv.Atoi(port)
		if err != nil || change.Port < 1 || change.Port > 65535 {
			return change, errors.New("invalid service port")
		}
		env["OLLAMA_HOST"], env["OLLAMA_ORIGINS"] = "127.0.0.1:"+port, ""
		job["EnvironmentVariables"] = env
		change.Runtime, change.Scope = "ollama", "browser_hardening"
		return change, nil
	}
	values, err := options(args)
	if err != nil {
		return change, err
	}
	port := values["--port"]
	if port == "" {
		return change, errors.New("an explicit service --port is required")
	}
	change.Port, err = strconv.Atoi(port)
	if err != nil || change.Port < 1 || change.Port > 65535 {
		return change, errors.New("invalid service port")
	}
	switch filepath.Base(args[0]) {
	case "llama-server":
		if values["--ssl-key-file"] != "" || values["--ssl-cert-file"] != "" || env["LLAMA_ARG_SSL_KEY_FILE"] != nil || env["LLAMA_ARG_SSL_CERT_FILE"] != nil {
			return change, errors.New("TLS service migration requires manual review; this adapter verifies local HTTP")
		}
		remove := map[string]bool{"--host": true, "--api-key": true, "--api-key-file": true, "--cors-origins": true, "--cors-credentials": true, "--no-cors-credentials": true}
		updated := []string{args[0]}
		for i := 1; i < len(args); i++ {
			flag, _, inline := strings.Cut(args[i], "=")
			if remove[flag] {
				if !inline && flag != "--cors-credentials" && flag != "--no-cors-credentials" && i+1 < len(args) {
					i++
				}
				continue
			}
			updated = append(updated, args[i])
		}
		updated = append(updated, "--host", "127.0.0.1", "--api-key-file", keyPath, "--cors-origins", "https://secure-agent-browser.invalid", "--no-cors-credentials")
		setArgs(job, updated)
		for _, key := range []string{"LLAMA_API_KEY", "LLAMA_ARG_API_KEY_FILE", "LLAMA_ARG_HOST", "LLAMA_ARG_CORS_ORIGINS", "LLAMA_ARG_CORS_CREDENTIALS"} {
			delete(env, key)
		}
		change.Runtime, change.Scope = "llama.cpp", "authenticated_inference"
	case "mlx_lm.server":
		if engine == "" {
			return change, errors.New("install the compatible Secure Agent model runtime before MLX remediation")
		}
		for flag := range values {
			if flag != "--model" && flag != "--host" && flag != "--port" && flag != "--max-tokens" && flag != "--log-level" {
				return change, errors.New("MLX service options require manual migration")
			}
		}
		model := values["--model"]
		if !filepath.IsAbs(model) {
			return change, errors.New("MLX remediation requires an existing absolute local model path")
		}
		for _, key := range []string{"PYTHONPATH", "PYTHONHOME", "PYTHONINSPECT"} {
			if env[key] != nil {
				return change, errors.New("custom Python environments require manual migration")
			}
		}
		updated := []string{engine, "serve", "protected-service", "--model", model, "--port", port, "--api-key-file", keyPath, "--runtime-executable", args[0]}
		if tokens := values["--max-tokens"]; tokens != "" {
			updated = append(updated, "--max-tokens", tokens)
		}
		setArgs(job, updated)
		if job["Program"] != nil {
			job["Program"] = engine
		}
		change.Runtime, change.Scope = "mlx", "authenticated_inference"
	default:
		return change, errors.New("unsupported launcher; select a direct Ollama, llama-server or plain MLX-LM launchd job")
	}
	job["EnvironmentVariables"] = env
	return change, nil
}

func setArgs(job map[string]any, args []string) {
	values := make([]any, len(args))
	for i, arg := range args {
		values[i] = arg
	}
	job["ProgramArguments"] = values
}

func sameEndpoint(endpoint string, port int) bool {
	u, err := url.Parse(endpoint)
	return err == nil && u.Port() == strconv.Itoa(port) && (u.Hostname() == "localhost" || net.ParseIP(u.Hostname()) != nil && net.ParseIP(u.Hostname()).IsLoopback())
}
