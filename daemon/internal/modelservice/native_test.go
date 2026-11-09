package modelservice

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func TestNativeMLXRemediation(t *testing.T) {
	if runtime.GOOS != "darwin" || os.Getenv("SECURE_AGENT_TEST_MODEL_REMEDIATION") != "1" {
		t.Skip("opt-in real launchd/model acceptance")
	}
	model, program, engine := os.Getenv("SECURE_AGENT_TEST_MANAGED_MODEL"), os.Getenv("SECURE_AGENT_TEST_MLX_SERVER"), os.Getenv("SECURE_AGENT_TEST_MLX_AGENT_BIN")
	if model == "" || program == "" || engine == "" {
		t.Fatal("native acceptance requires local model, MLX executable and engine")
	}
	testNativeRemediation(t, []string{program, "--model", model, "--host", "127.0.0.1"}, map[string]any{"PATH": filepath.Dir(program) + ":/usr/bin:/bin:/usr/local/bin"}, engine, "authenticated_inference", false)
}

func TestNativeLlamaRemediation(t *testing.T) {
	if runtime.GOOS != "darwin" || os.Getenv("SECURE_AGENT_TEST_LLAMA_REMEDIATION") != "1" {
		t.Skip("opt-in real llama-server acceptance")
	}
	model, program := os.Getenv("SECURE_AGENT_TEST_GGUF"), os.Getenv("SECURE_AGENT_TEST_LLAMA_SERVER")
	if model == "" || program == "" {
		t.Fatal("native acceptance requires an existing GGUF and llama-server")
	}
	testNativeRemediation(t, []string{program, "--model", model, "--host", "127.0.0.1", "--ctx-size", "512", "--threads", "2", "--n-gpu-layers", "0"}, nil, "", "authenticated_inference", false)
}

func TestNativeOllamaRemediation(t *testing.T) {
	if runtime.GOOS != "darwin" || os.Getenv("SECURE_AGENT_TEST_OLLAMA_REMEDIATION") != "1" {
		t.Skip("opt-in real Ollama browser-hardening acceptance")
	}
	program := os.Getenv("SECURE_AGENT_TEST_OLLAMA_SERVER")
	if program == "" {
		t.Fatal("Ollama executable required")
	}
	testNativeRemediation(t, []string{program, "serve"}, map[string]any{"OLLAMA_ORIGINS": "*", "OLLAMA_NO_CLOUD": "true"}, "", "browser_hardening", false)
}

func testNativeRemediation(t *testing.T, args []string, env map[string]any, engine, scope string, cancelAfterWrite bool) {
	testNativeRemediationProbe(t, args, env, engine, scope, cancelAfterWrite, nil)
}

func testNativeRemediationProbe(t *testing.T, args []string, env map[string]any, engine, scope string, cancelAfterWrite bool, probe func(*testing.T, string, *Manager, string)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	if filepath.Base(args[0]) == "ollama" {
		env["OLLAMA_HOST"] = "127.0.0.1:" + strconv.Itoa(port)
		env["OLLAMA_MODELS"] = filepath.Join(root, "models")
	} else {
		args = append(args, "--port", strconv.Itoa(port))
	}
	values := make([]any, len(args))
	for i, value := range args {
		values[i] = value
	}
	label := "com.cavi.secure-agent.model-test." + strconv.Itoa(os.Getpid()) + "." + strconv.Itoa(port)
	source := filepath.Join(root, "model.plist")
	job := map[string]any{"Label": label, "ProgramArguments": values, "RunAtLoad": true, "StandardOutPath": filepath.Join(root, "service.log"), "StandardErrorPath": filepath.Join(root, "service.log")}
	if env != nil {
		job["EnvironmentVariables"] = env
	}
	raw, err := encodeDefinition(job)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, raw, 0600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "config.yaml")
	config := []byte(fmt.Sprintf("advisor:\n  enabled: true\n  endpoint: http://127.0.0.1:%d\n  model: fixture\n# preserve this operator comment\n", port))
	if err := os.WriteFile(configPath, config, 0600); err != nil {
		t.Fatal(err)
	}
	if err := startJob(ctx, source); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = stopJob(cleanup, label)
	})
	endpoint := "http://127.0.0.1:" + strconv.Itoa(port)
	for {
		response, err := (&http.Client{Timeout: time.Second}).Get(endpoint + "/v1/models")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == 200 {
				break
			}
		}
		select {
		case <-ctx.Done():
			data, _ := os.ReadFile(filepath.Join(root, "service.log"))
			t.Fatalf("original service not ready: %s", data)
		case <-time.After(250 * time.Millisecond):
		}
	}
	m := New(configPath, func() string { return engine })
	preview, err := m.Preview(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	expectedClients := 1
	if scope == "browser_hardening" {
		expectedClients = 0
	}
	if preview.Change.Scope != scope || preview.Change.Port != port || len(preview.ClientFields) != expectedClients {
		t.Fatalf("preview: %+v", preview)
	}
	if current, _ := os.ReadFile(source); digest(current) != digest(raw) {
		t.Fatal("preview changed service")
	}
	if err := os.WriteFile(configPath, append(append([]byte{}, config...), []byte("# changed after preview\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply(ctx, preview.ID, preview.Hash); err == nil {
		t.Fatal("stale preview applied")
	}
	if current, _ := os.ReadFile(source); digest(current) != digest(raw) {
		t.Fatal("stale preview changed service")
	}
	if err := os.WriteFile(configPath, config, 0600); err != nil {
		t.Fatal(err)
	}
	preview, err = m.Preview(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	if cancelAfterWrite {
		go func() {
			ticker := time.NewTicker(time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					current, err := os.ReadFile(source)
					if err == nil && digest(current) != digest(raw) {
						cancel()
						return
					}
				}
			}
		}()
	}
	result, err := m.Apply(ctx, preview.ID, preview.Hash)
	if cancelAfterWrite {
		if err == nil || result.State != "failed_restored_stopped" {
			t.Fatalf("cancelled apply: state=%s err=%v", result.State, err)
		}
		for path, expected := range map[string][]byte{source: raw, configPath: config} {
			current, readErr := os.ReadFile(path)
			if readErr != nil || digest(current) != digest(expected) {
				t.Fatal("cancellation did not restore original files")
			}
		}
		check, cancelCheck := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelCheck()
		if _, err := inspectJob(check, label); !errors.Is(err, errJobAbsent) {
			t.Fatalf("cancellation left job loaded: %v", err)
		}
		t.Log("cancelled restart restored original service and client bytes and left the job unloaded")
		return
	}
	if err != nil {
		data, _ := os.ReadFile(filepath.Join(root, "service.log"))
		t.Fatalf("native apply: %v state=%s log=%s", err, result.State, data)
	}
	expectedChecks := 5
	if scope == "browser_hardening" {
		expectedChecks = 3
	}
	if result.State != "verified" || result.VerifiedAt.IsZero() || len(result.Checks) < expectedChecks {
		t.Fatalf("receipt: %+v", result)
	}
	if _, err := m.Apply(ctx, preview.ID, preview.Hash); err == nil {
		t.Fatal("consumed preview replay accepted")
	}
	if probe != nil {
		probe(t, endpoint, m, label)
	}
	result, err = m.Rollback(ctx, label)
	if err != nil || result.State != "restored_stopped" {
		t.Fatalf("rollback: %+v %v", result, err)
	}
	if current, _ := os.ReadFile(source); digest(current) != digest(raw) {
		t.Fatal("original service bytes not restored")
	}
	if current, _ := os.ReadFile(configPath); digest(current) != digest(config) {
		t.Fatal("original client bytes not restored")
	}
	if _, err := inspectJob(ctx, label); err == nil {
		t.Fatal("rollback left original service running")
	}
	if scope == "browser_hardening" {
		t.Log("production preview/apply, native restart, foreign Origin/Host refusal and stopped rollback passed; authenticated isolation is not claimed")
	} else {
		t.Log("production preview/apply, native restart, credential/browser/admin refusals, authorized inference, backend isolation and stopped rollback passed")
	}
}

func TestNativeStopLoadedIdleJob(t *testing.T) {
	if runtime.GOOS != "darwin" || os.Getenv("SECURE_AGENT_TEST_OLLAMA_REMEDIATION") != "1" {
		t.Skip("opt-in native job lifecycle acceptance")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	root, _ := filepath.EvalSymlinks(t.TempDir())
	source := filepath.Join(root, "idle.plist")
	label := "com.cavi.secure-agent.idle-test." + strconv.Itoa(os.Getpid())
	raw, err := encodeDefinition(map[string]any{"Label": label, "ProgramArguments": []any{"/usr/bin/true"}, "RunAtLoad": true})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := startJob(ctx, source); err != nil {
		t.Fatal(err)
	}
	defer stopJob(context.Background(), label)
	for {
		state, err := inspectJob(ctx, label)
		if err == nil && state.PID == 0 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("idle job did not settle")
		case <-time.After(50 * time.Millisecond):
		}
	}
	if err := stopSelectedJob(ctx, label, source); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectJob(ctx, label); !errors.Is(err, errJobAbsent) {
		t.Fatalf("loaded idle job was not unloaded: %v", err)
	}
}

func TestNativeCancellationRestoresStopped(t *testing.T) {
	if runtime.GOOS != "darwin" || os.Getenv("SECURE_AGENT_TEST_OLLAMA_REMEDIATION") != "1" {
		t.Skip("opt-in native cancellation acceptance")
	}
	program := os.Getenv("SECURE_AGENT_TEST_OLLAMA_SERVER")
	if program == "" {
		t.Fatal("Ollama executable required")
	}
	testNativeRemediation(t, []string{program, "serve"}, map[string]any{"OLLAMA_ORIGINS": "*", "OLLAMA_NO_CLOUD": "true"}, "", "browser_hardening", true)
}
