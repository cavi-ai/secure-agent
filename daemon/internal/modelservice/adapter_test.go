package modelservice

import (
	"strings"
	"testing"
)

func TestAdaptersKeepPortAndRequireRecognizableOwner(t *testing.T) {
	job := map[string]any{"Label": "com.example.model", "ProgramArguments": []any{"/usr/local/bin/ollama", "serve"}, "EnvironmentVariables": map[string]any{"OLLAMA_HOST": "0.0.0.0:19001", "OLLAMA_ORIGINS": "*", "KEEP": "value"}}
	change, err := adapt(job, "/private/model.key", "")
	if err != nil || change.Runtime != "ollama" || change.Port != 19001 || change.Scope != "browser_hardening" {
		t.Fatalf("adapter: %+v %v", change, err)
	}
	env := job["EnvironmentVariables"].(map[string]any)
	if env["OLLAMA_HOST"] != "127.0.0.1:19001" || env["OLLAMA_ORIGINS"] != "" || env["KEEP"] != "value" {
		t.Fatal("adapter lost unrelated configuration or retained broad origins")
	}
	job["ProgramArguments"] = []any{"/bin/sh", "-c", "ollama serve"}
	if _, err := adapt(job, "/private/model.key", ""); err == nil {
		t.Fatal("shell wrapper accepted as a supported runtime")
	}
}

func TestLlamaRemovesInlineCredentialsWithoutExposingThem(t *testing.T) {
	job := map[string]any{"ProgramArguments": []any{"/opt/bin/llama-server", "--model", "/models/model.gguf", "--port=19002", "--host", "0.0.0.0", "--api-key", "private-old-key"}}
	change, err := adapt(job, "/private/model.key", "")
	if err != nil || change.Port != 19002 || change.Scope != "authenticated_inference" {
		t.Fatalf("adapter: %+v %v", change, err)
	}
	args, _ := arguments(job)
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "private-old-key") || strings.Contains(joined, "0.0.0.0") || !strings.Contains(joined, "--api-key-file /private/model.key") || !strings.Contains(joined, "/models/model.gguf") {
		t.Fatal("native protection settings not applied")
	}
}
