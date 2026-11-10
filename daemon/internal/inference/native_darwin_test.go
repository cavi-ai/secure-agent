//go:build darwin

package inference_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/api"
	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/connpeer"
	"github.com/cavi-ai/secure-agent/daemon/internal/inference"
	"github.com/cavi-ai/secure-agent/internal/localservice"
)

func freeAddress(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := ln.Addr().String()
	ln.Close()
	return address
}

// This opt-in acceptance uses cached models and its own Ollama process. It
// never reconfigures or stops an existing server and performs no model pulls.
func TestNativeOllamaGatewayAndPassiveClients(t *testing.T) {
	if os.Getenv("SECURE_AGENT_TEST_OLLAMA_INFERENCE") != "1" {
		t.Skip("set SECURE_AGENT_TEST_OLLAMA_INFERENCE=1 with existing model inputs")
	}
	executable := os.Getenv("SECURE_AGENT_TEST_OLLAMA_SERVER")
	model := os.Getenv("SECURE_AGENT_TEST_OLLAMA_MODEL")
	embedding := os.Getenv("SECURE_AGENT_TEST_OLLAMA_EMBEDDING")
	models := os.Getenv("SECURE_AGENT_TEST_OLLAMA_MODELS")
	if !filepath.IsAbs(executable) || !filepath.IsAbs(models) || model == "" || embedding == "" {
		t.Fatal("existing Ollama executable, cache directory, chat and embedding models required")
	}
	address := freeAddress(t)
	command := exec.Command(executable, "serve")
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "OLLAMA_") {
			command.Env = append(command.Env, entry)
		}
	}
	command.Env = append(command.Env, "OLLAMA_HOST="+address, "OLLAMA_MODELS="+models, "OLLAMA_NO_CLOUD=1", "OLLAMA_CONTEXT_LENGTH=512", "OLLAMA_NUM_PARALLEL=2", "OLLAMA_KEEP_ALIVE=0", "OLLAMA_ORIGINS=")
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	log, err := os.Create(filepath.Join(t.TempDir(), "ollama.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	t.Cleanup(func() {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
		select {
		case <-waited:
		case <-time.After(3 * time.Second):
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			<-waited
		}
	})
	client := &http.Client{Timeout: 2 * time.Second}
	target := "http://" + address
	deadline := time.Now().Add(20 * time.Second)
	for {
		response, err := client.Get(target + "/api/version")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("isolated Ollama did not start")
		}
		time.Sleep(50 * time.Millisecond)
	}

	monitor := inference.New()
	monitor.Refresh(context.Background(), []string{target}, localservice.DiscoverListeners(context.Background()))
	found := false
	for _, s := range monitor.Snapshot().Servers {
		if s.Endpoint == target && s.Runtime == "ollama" && s.PID == command.Process.Pid {
			found = true
		}
	}
	if !found {
		t.Fatal("native listener inventory did not identify the isolated Ollama")
	}
	hold := exec.Command("python3", "-c", "import socket,sys,time;s=socket.create_connection(('127.0.0.1',int(sys.argv[1])));print('connected',flush=True);time.sleep(15)", strings.Split(address, ":")[1])
	output, err := hold.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := hold.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hold.Process.Kill(); _ = hold.Wait() })
	ready := make([]byte, len("connected\n"))
	if _, err := io.ReadFull(output, ready); err != nil {
		t.Fatal(err)
	}
	source := collect.NewSocketLister()
	snapshot := source.(interface{ Snapshot() collect.SocketSnapshot }).Snapshot()
	connections := []inference.Connection{}
	for _, c := range snapshot.Connections {
		connections = append(connections, inference.Connection{PID: c.PID, LocalAddress: net.JoinHostPort(c.LocalHost, strconv.Itoa(c.LocalPort)), RemoteAddress: net.JoinHostPort(c.Host, strconv.Itoa(c.Port))})
	}
	monitor.ObserveConnections(connections, snapshot.State)
	found = false
	for _, c := range monitor.Snapshot().Connections {
		if c.PID == int32(hold.Process.Pid) && c.Endpoint == target {
			found = true
		}
	}
	if !found || len(monitor.Snapshot().Requests) != 0 {
		t.Fatal("untagged native connection was missed or fabricated inference")
	}

	key := filepath.Join(t.TempDir(), "gateway.key")
	if err := localservice.CreateKeyFile(key); err != nil {
		t.Fatal(err)
	}
	gatewayAddress := freeAddress(t)
	gateway, err := inference.NewGateway(inference.GatewayConfig{Listen: gatewayAddress, Upstream: target, APIKeyFile: key}, monitor)
	if err != nil {
		t.Fatal(err)
	}
	gateway.Identify = func(ctx context.Context, remote string) (int32, string) {
		pid, _ := connpeer.PID(ctx, remote, api.TCPClientPID)
		return pid, ""
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gatewayDone := make(chan error, 1)
	go func() { gatewayDone <- gateway.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-gatewayDone:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(7 * time.Second):
			t.Error("gateway failed to stop")
		}
	})
	endpoint := "http://" + gatewayAddress
	deadline = time.Now().Add(3 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", gatewayAddress, 100*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("gateway did not bind")
		}
		time.Sleep(10 * time.Millisecond)
	}
	var clientsMu sync.Mutex
	clientPIDs := map[int32]bool{}
	send := func(path string, body map[string]any) error {
		data, _ := json.Marshal(body)
		requestCtx, stop := context.WithTimeout(context.Background(), 90*time.Second)
		defer stop()
		program := "import pathlib,sys,urllib.request\nkey=pathlib.Path(sys.argv[2]).read_text().strip()\nr=urllib.request.Request(sys.argv[1],data=sys.argv[3].encode(),headers={'Content-Type':'application/json','Authorization':'Bearer '+key})\nwith urllib.request.urlopen(r,timeout=80) as response:\n while response.read(16384): pass\n"
		child := exec.CommandContext(requestCtx, "python3", "-c", program, endpoint+path, key, string(data))
		if err := child.Start(); err != nil {
			return err
		}
		clientsMu.Lock()
		clientPIDs[int32(child.Process.Pid)] = true
		clientsMu.Unlock()
		if err := child.Wait(); err != nil {
			return fmt.Errorf("native Python request %s: %w", path, err)
		}
		return nil
	}
	if err := send("/api/embed", map[string]any{"model": embedding, "input": "local inference check", "keep_alive": 0}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	failures := make(chan error, 2)
	for _, stream := range []bool{true, false} {
		wg.Go(func() {
			failures <- send("/api/chat", map[string]any{"model": model, "messages": []any{map[string]string{"role": "user", "content": "Reply OK."}}, "stream": stream, "think": false, "keep_alive": 0, "options": map[string]int{"num_ctx": 512, "num_predict": 4}})
		})
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	deadline = time.Now().Add(time.Second)
	for {
		finished := 0
		for _, r := range monitor.Snapshot().Requests {
			if r.EndedAt != nil {
				finished++
			}
		}
		if finished == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("native requests remained active")
		}
		time.Sleep(time.Millisecond)
	}
	for _, r := range monitor.Snapshot().Requests {
		if r.State != "completed" || !clientPIDs[r.PID] || r.InputTokens == nil {
			t.Fatalf("native request metadata: %+v", r)
		}
	}
	request, _ := http.NewRequest("POST", endpoint+"/api/chat", strings.NewReader(`{"model":"invalid"}`))
	request.Header.Set("Origin", "https://example.invalid")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("foreign browser origin reached gateway")
	}
	if len(monitor.Snapshot().Requests) != 3 {
		t.Fatal("browser refusal became inference activity")
	}
	t.Log("real Ollama: native listener ownership, untagged Python client, authenticated embeddings, parallel streaming/non-streaming chat, OS peer attribution and browser-origin refusal passed")
}
