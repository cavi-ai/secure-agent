package daemon

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
	"github.com/cavi-ai/secure-agent/daemon/internal/inference"
	"github.com/cavi-ai/secure-agent/daemon/internal/taint"
	"github.com/cavi-ai/secure-agent/internal/localservice"
)

func inferencePolicyFixture(t *testing.T, engine *firewall.Engine, gate *taint.Gate, ask func(context.Context, taint.Verdict) bool) (*httptest.Server, string, *inference.Monitor, <-chan event.Event, *atomic.Int32) {
	t.Helper()
	reached := new(atomic.Int32)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Api-Key") != "" {
			t.Error("gateway credential reached backend")
		}
		hash := sha256.New()
		if _, err := io.Copy(hash, r.Body); err != nil {
			t.Error(err)
		}
		reached.Add(1)
		w.Header().Set("X-Fixture-Body-Sha256", hex.EncodeToString(hash.Sum(nil)))
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"done":true}`)
	}))
	t.Cleanup(backend.Close)
	b := bus.New(64)
	events := b.Subscribe()
	policy, err := inferenceRequestPolicy(engine, gate, ask, b.Publish, func(context.Context, string) (int32, string) { return 123, "fixture-session" })
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(t.TempDir(), "gateway.key")
	if err := localservice.CreateKeyFile(key); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)
	m := inference.New()
	g, err := inference.NewGateway(inference.GatewayConfig{Listen: server.Listener.Addr().String(), Upstream: backend.URL, APIKeyFile: key}, m, policy)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = g
	server.Start()
	return server, key, m, events, reached
}

func inferenceEngine(t *testing.T, mode string) *firewall.Engine {
	t.Helper()
	e, err := firewall.NewEngine(config.FirewallConfig{Mode: mode, Patterns: []config.PatternConfig{{ID: "fixture-key", Re: `fixture_[A-Z]{16}`, Mode: mode}}}, []byte("fixture-salt"))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func inferencePolicyRequest(t *testing.T, server *httptest.Server, key, path string, body io.Reader, encoding string) int {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, server.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := localservice.Authorize(r, key); err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	if encoding != "" {
		r.Header.Set("Content-Encoding", encoding)
	}
	wantHash := ""
	if r.GetBody != nil {
		original, err := r.GetBody()
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.New()
		_, err = io.Copy(hash, original)
		original.Close()
		if err != nil {
			t.Fatal(err)
		}
		wantHash = hex.EncodeToString(hash.Sum(nil))
	}
	response, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode == 200 && wantHash != "" && response.Header.Get("X-Fixture-Body-Sha256") != wantHash {
		t.Fatal("inspected request bytes changed before reaching backend")
	}
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	return response.StatusCode
}

func TestInferenceFirewallBeforeForwarding(t *testing.T) {
	secret := "fixture_ABCDEFGHIJKLMNOP"
	for _, tc := range []struct {
		name, mode, encoding, body string
		want                       int
	}{
		{"blocked body", "block", "", `{"model":"test","prompt":"` + secret + `"}`, 403},
		{"past metadata prefix", "block", "", `{"model":"test","prompt":"` + strings.Repeat(" ", 70<<10) + secret + `"}`, 403},
		{"monitored body", "monitor", "", `{"model":"test","prompt":"` + secret + `"}`, 200},
		{"clean body", "block", "", `{"model":"test","prompt":"hello"}`, 200},
		{"spooled clean body", "block", "", `{"model":"test","prompt":"` + strings.Repeat(" ", 1<<20) + `hello"}`, 200},
		{"gzip body", "block", "gzip", `{"model":"test","prompt":"` + secret + `"}`, 403},
		{"unsupported encoding", "block", "br", `{"model":"test","prompt":"hello"}`, 403},
		{"broken gzip", "block", "gzip", "invalid compressed body", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := inferenceEngine(t, tc.mode)
			server, key, monitor, events, reached := inferencePolicyFixture(t, engine, &taint.Gate{}, nil)
			data := []byte(tc.body)
			if tc.name == "gzip body" {
				var zipped bytes.Buffer
				writer := gzip.NewWriter(&zipped)
				if _, err := writer.Write(data); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				data = zipped.Bytes()
			}
			if got := inferencePolicyRequest(t, server, key, "/api/chat", bytes.NewReader(data), tc.encoding); got != tc.want {
				t.Fatalf("status=%d, want %d", got, tc.want)
			}
			wantReached := int32(0)
			if tc.want == 200 {
				wantReached = 1
			}
			if reached.Load() != wantReached {
				t.Fatalf("backend received %d requests, want %d", reached.Load(), wantReached)
			}
			if tc.name == "monitored body" || tc.name == "blocked body" {
				select {
				case e := <-events:
					if e.Kind != event.KindProxyHit || e.PID != 123 || e.SessionID != "fixture-session" || e.Payload == nil || e.Payload.Field != "body" {
						t.Fatalf("missing attributed firewall evidence: %+v", e)
					}
				default:
					t.Fatal("no firewall evidence")
				}
			}
			metadata, err := json.Marshal(monitor.Snapshot())
			if err != nil || bytes.Contains(metadata, []byte(secret)) {
				t.Fatal("secret retained in inference metadata")
			}
		})
	}
}

func TestInferenceTaintModesAndMetadata(t *testing.T) {
	dir := t.TempDir()
	sum := sha256.Sum256([]byte("fixture-session"))
	if err := os.WriteFile(filepath.Join(dir, hex.EncodeToString(sum[:])[:32]+".json"), []byte(`{"source":"web: https://example.invalid"}`), 0600); err != nil {
		t.Fatal(err)
	}
	modes := filepath.Join(t.TempDir(), "modes.json")
	gate := &taint.Gate{Dir: dir, ModesPath: modes, Exempt: map[string]bool{"127.0.0.1": true}, ClientPID: func(context.Context, string) (int32, error) { return 123, nil }, Sessions: func(int32) []taint.Session { return []taint.Session{{ID: "fixture-session", Workspace: "/fixture"}} }}
	var answer atomic.Bool
	var asks atomic.Int32
	var delayed atomic.Bool
	server, key, _, _, reached := inferencePolicyFixture(t, inferenceEngine(t, "block"), gate, func(ctx context.Context, _ taint.Verdict) bool {
		asks.Add(1)
		if delayed.Load() {
			select {
			case <-time.After(16 * time.Second):
			case <-ctx.Done():
				return false
			}
		}
		return answer.Load()
	})
	for _, tc := range []struct {
		mode          string
		allow         bool
		path          string
		want, prompts int
		delay         bool
	}{
		{"deny", false, "/api/chat", 403, 0, false},
		{"monitor", false, "/api/chat", 200, 0, false},
		{"prompt", false, "/api/chat", 403, 1, false},
		{"prompt", true, "/api/chat", 200, 1, false},
		{"session", true, "/api/chat", 200, 1, false},
		{"deny", false, "/api/show", 200, 0, false},
		{"prompt", true, "/api/chat", 200, 1, true},
	} {
		if err := os.WriteFile(modes, []byte(`{"untrusted-egress":"`+tc.mode+`"}`), 0600); err != nil {
			t.Fatal(err)
		}
		answer.Store(tc.allow)
		delayed.Store(tc.delay)
		before, asked := reached.Load(), asks.Load()
		if got := inferencePolicyRequest(t, server, key, tc.path, strings.NewReader(`{"model":"test","prompt":"hello"}`), ""); got != tc.want {
			t.Fatalf("%s %s: status=%d, want %d", tc.mode, tc.path, got, tc.want)
		}
		wantReached := before
		if tc.want == 200 {
			wantReached++
		}
		if reached.Load() != wantReached || int(asks.Load()-asked) != tc.prompts {
			t.Fatalf("%s: backend=%d, prompts=%d", tc.mode, reached.Load()-before, asks.Load()-asked)
		}
	}
}

func TestInferencePolicyRequiresFirewallAndGate(t *testing.T) {
	if _, err := inferenceRequestPolicy(nil, &taint.Gate{}, nil, nil, nil); err == nil {
		t.Fatal("policy accepted an unavailable firewall")
	}
	if _, err := inferenceRequestPolicy(inferenceEngine(t, "block"), nil, nil, nil, nil); err == nil {
		t.Fatal("policy accepted an unavailable taint gate")
	}
}

func TestInferenceLiveFirewallPolicyAndSizeLimit(t *testing.T) {
	engine := inferenceEngine(t, "monitor")
	server, key, _, _, reached := inferencePolicyFixture(t, engine, &taint.Gate{}, nil)
	request := func(body string, want int) {
		t.Helper()
		if got := inferencePolicyRequest(t, server, key, "/api/chat", strings.NewReader(body), ""); got != want {
			t.Fatalf("status=%d, want %d", got, want)
		}
	}
	body := `{"model":"test","prompt":"fixture_ABCDEFGHIJKLMNOP"}`
	request(body, 200)
	engine.SetRuleMode("fixture-key", firewall.ModeBlock)
	request(body, 403)
	secret := "registered-value-for-inference-fixture"
	request(`{"model":"test","prompt":"`+secret+`"}`, 200)
	r, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := localservice.Authorize(r, key); err != nil {
		t.Fatal(err)
	}
	credential := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	engine.SetFingerprints([]config.Fingerprint{
		{ID: "registered-fixture", Len: len(secret), HMAC: firewall.Fingerprint([]byte("fixture-salt"), secret)},
		{ID: "gateway-fixture", Len: len(credential), HMAC: firewall.Fingerprint([]byte("fixture-salt"), credential)},
	})
	engine.SetRuleMode("registered-fixture", firewall.ModeBlock)
	engine.SetRuleMode("gateway-fixture", firewall.ModeBlock)
	request(`{"model":"test","prompt":"`+secret+`"}`, 403)
	request(`{"model":"test","prompt":"hello"}`, 200)
	before := reached.Load()
	oversized := io.LimitReader(strings.NewReader(strings.Repeat("x", 16<<20+1)), 16<<20+1)
	if got := inferencePolicyRequest(t, server, key, "/api/chat", oversized, ""); got != 413 {
		t.Fatalf("chunked oversized upload: status=%d, want 413", got)
	}
	if reached.Load() != before {
		t.Fatal("oversized upload reached backend")
	}
}
