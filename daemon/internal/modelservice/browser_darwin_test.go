package modelservice

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/loopback"
	"github.com/cavi-ai/secure-agent/internal/localservice"
)

// Opt-in acceptance uses a disposable launchd job and a fresh headless profile.
// Browser network records distinguish server refusal from a CORS preflight.
func TestNativeMLXBrowserRemediation(t *testing.T) {
	if os.Getenv("SECURE_AGENT_TEST_MODEL_BROWSER") != "1" {
		t.Skip("opt-in real browser and cached-model remediation acceptance")
	}
	model, program, engine := os.Getenv("SECURE_AGENT_TEST_MANAGED_MODEL"), os.Getenv("SECURE_AGENT_TEST_MLX_SERVER"), os.Getenv("SECURE_AGENT_TEST_MLX_AGENT_BIN")
	if model == "" || program == "" || engine == "" {
		t.Fatal("native browser acceptance requires local model, MLX executable and engine")
	}
	testNativeRemediationProbe(t, []string{program, "--model", model, "--host", "127.0.0.1"},
		map[string]any{"PATH": filepath.Dir(program) + ":/usr/bin:/bin:/usr/local/bin", "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1"}, engine,
		"authenticated_inference", false, browserModelProbe)
}

func browserModelProbe(t *testing.T, endpoint string, manager *Manager, label string) {
	t.Helper()
	chrome := os.Getenv("SECURE_AGENT_TEST_CHROME")
	if chrome == "" {
		chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
	}
	if _, err := os.Stat(chrome); err != nil {
		t.Fatal("headless Chrome is required for browser acceptance")
	}
	target, _ := json.Marshal(endpoint)
	page := `<!doctype html><body>Waiting<script src="/probe.js"></script>`
	script := `const target=` + string(target) + `;
const body=JSON.stringify({messages:[{role:'user',content:'Reply OK'}],max_tokens:1});
const pending=[];
pending.push(fetch(target+'/v1/chat/completions',{method:'POST',mode:'no-cors',headers:{'Content-Type':'text/plain'},body}));
pending.push(new Promise(resolve=>{
  const frame=document.createElement('iframe');frame.name='form-result';document.body.append(frame);
  const form=document.createElement('form');form.method='POST';form.action=target+'/v1/responses';form.target=frame.name;
  const input=document.createElement('input');input.name='prompt';input.value='Reply OK';form.append(input);document.body.append(form);
  frame.onload=resolve;form.submit();
}));
pending.push(new Promise(resolve=>{
  addEventListener('message',event=>{if(event.data==='null-origin-done')resolve();});
  const frame=document.createElement('iframe');frame.sandbox='allow-scripts';
  frame.srcdoc='<script>fetch('+JSON.stringify(target+'/_mlx/unload')+',{method:"POST",mode:"no-cors",headers:{"Content-Type":"text/plain"},body:"{}"}).catch(()=>{}).finally(()=>parent.postMessage("null-origin-done","*"))</script>';
  document.body.append(frame);
}));
pending.push(fetch(target+'/v1/responses?preflight',{method:'POST',headers:{'Content-Type':'application/json'},body}));
pending.push(fetch(target.replace('127.0.0.1','model-browser.invalid')+'/v1/messages',{method:'POST',mode:'no-cors',headers:{'Content-Type':'text/plain'},body}));
Promise.allSettled(pending).then(()=>document.body.dataset.complete='true');`
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/probe.js" {
			w.Header().Set("Content-Type", "application/javascript")
			io.WriteString(w, script)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, page)
	}))
	defer attacker.Close()
	root := t.TempDir()
	netlog := filepath.Join(root, "network.json")
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, chrome, "--headless=new", "--disable-gpu", "--no-first-run",
		"--disable-background-networking", "--disable-component-update", "--disable-sync", "--no-proxy-server", "--user-data-dir="+filepath.Join(root, "profile"),
		"--host-resolver-rules=MAP model-browser.invalid 127.0.0.1", "--log-net-log="+netlog,
		"--virtual-time-budget=8000", "--dump-dom", attacker.URL)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("headless browser failed: %v", err)
	}
	if !strings.Contains(string(output), `data-complete="true"`) {
		t.Fatal("browser probes did not finish")
	}
	requests := readBrowserRequests(t, netlog)
	for _, path := range []string{"/v1/chat/completions", "/v1/responses", "/_mlx/unload"} {
		record := requireBrowserResponse(t, requests, endpoint+path, "POST", 403)
		origin := attacker.URL
		if path == "/_mlx/unload" {
			origin = "null"
		}
		if record.Origin != origin {
			t.Fatalf("browser %s Origin=%q, want %q", path, record.Origin, origin)
		}
		if path == "/v1/responses" && !strings.HasPrefix(record.ContentType, "application/x-www-form-urlencoded") {
			t.Fatal("HTML form did not use a form-compatible content type")
		}
	}
	// An unsupported JSON preflight is a browser-enforced refusal. It must
	// not be mistaken for an authenticated POST handled by the service.
	requireBrowserResponse(t, requests, endpoint+"/v1/responses?preflight", "OPTIONS", 501)
	for _, request := range requests {
		if request.URL == endpoint+"/v1/responses?preflight" && request.Method == "POST" {
			t.Fatal("browser sent JSON POST after rejected preflight")
		}
	}
	foreign := strings.Replace(endpoint, "127.0.0.1", "model-browser.invalid", 1) + "/v1/messages"
	record := requireBrowserResponse(t, requests, foreign, "POST", 403)
	if record.Host != strings.Split(strings.TrimPrefix(foreign, "http://"), "/")[0] {
		t.Fatal("foreign Host did not reach the service")
	}
	// The key remains in the native client and never enters the browser.
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/v1/chat/completions",
		strings.NewReader(`{"messages":[{"role":"user","content":"Reply OK"}],"max_tokens":1,"stream":false}`))
	request.Header.Set("Content-Type", "application/json")
	if err := localservice.Authorize(request, manager.keyPath(label)); err != nil {
		t.Fatal(err)
	}
	response, err := loopback.Client(20 * time.Second).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("authorized native inference after browser probes: HTTP %d", response.StatusCode)
	}
	if _, err := io.Copy(io.Discard, io.LimitReader(response.Body, 65536)); err != nil {
		t.Fatal(err)
	}
	t.Log("real browser: simple POST, HTML form, null Origin and foreign Host reached the service and received 403; JSON preflight received 501 without a POST; authorized native inference still succeeded")
}

type browserRequest struct {
	URL, Method, Origin, Host, ContentType string
	Status                                 int
}

func readBrowserRequests(t *testing.T, path string) []browserRequest {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var log struct {
		Constants struct {
			Types map[string]int `json:"logEventTypes"`
		}
		Events []struct {
			Type   int
			Source struct{ ID int }
			Params struct {
				URL     string
				Line    string
				Headers []string
			}
		}
	}
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatal(err)
	}
	bySource := map[int]*browserRequest{}
	for _, event := range log.Events {
		request := bySource[event.Source.ID]
		if request == nil {
			request = &browserRequest{}
			bySource[event.Source.ID] = request
		}
		switch event.Type {
		case log.Constants.Types["URL_REQUEST_START_JOB"]:
			if event.Params.URL != "" {
				request.URL = event.Params.URL
			}
		case log.Constants.Types["HTTP_TRANSACTION_SEND_REQUEST_HEADERS"]:
			if fields := strings.Fields(event.Params.Line); len(fields) > 0 {
				request.Method = fields[0]
			}
			for _, header := range event.Params.Headers {
				name, value, found := strings.Cut(header, ":")
				if !found {
					continue
				}
				switch strings.ToLower(name) {
				case "origin":
					request.Origin = strings.TrimSpace(value)
				case "host":
					request.Host = strings.TrimSpace(value)
				case "content-type":
					request.ContentType = strings.TrimSpace(value)
				}
			}
		case log.Constants.Types["HTTP_TRANSACTION_READ_RESPONSE_HEADERS"]:
			if len(event.Params.Headers) > 0 {
				fields := strings.Fields(event.Params.Headers[0])
				if len(fields) > 1 {
					request.Status, _ = strconv.Atoi(fields[1])
				}
			}
		}
	}
	var requests []browserRequest
	for _, request := range bySource {
		if request.URL != "" && request.Method != "" {
			requests = append(requests, *request)
		}
	}
	return requests
}

func requireBrowserResponse(t *testing.T, requests []browserRequest, url, method string, status int) browserRequest {
	t.Helper()
	for _, request := range requests {
		if request.URL == url && request.Method == method && request.Status == status {
			return request
		}
	}
	t.Fatalf("browser network record missing %s %s => %d; records=%+v", method, url, status, requests)
	return browserRequest{}
}

func TestBrowserNetLogPreservesCompletedRequest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "network.json")
	// NetLog emits a matching end event without repeating begin parameters.
	raw := `{"constants":{"logEventTypes":{"URL_REQUEST_START_JOB":1,"HTTP_TRANSACTION_SEND_REQUEST_HEADERS":2,"HTTP_TRANSACTION_READ_RESPONSE_HEADERS":3}},"events":[
{"type":1,"phase":1,"source":{"id":10},"params":{"url":"http://127.0.0.1:8080/v1/chat/completions"}},
{"type":2,"phase":0,"source":{"id":10},"params":{"line":"POST /v1/chat/completions HTTP/1.1"}},
{"type":3,"phase":0,"source":{"id":10},"params":{"headers":["HTTP/1.1 403 Forbidden"]}},
{"type":1,"phase":2,"source":{"id":10},"params":{}}]}`
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	requireBrowserResponse(t, readBrowserRequests(t, path), "http://127.0.0.1:8080/v1/chat/completions", "POST", 403)
}
