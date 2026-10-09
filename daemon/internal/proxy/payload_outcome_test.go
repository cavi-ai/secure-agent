package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
)

func TestPayloadOutcomeMatchesActualForwardingGate(t *testing.T) {
	for _, tc := range []struct {
		name, mode, body, layer, finding, request string
		status, forwarded                         int
	}{
		{"fingerprint blocked", "block", bodyFixture, "fingerprint", "block", "block", 403, 0},
		{"pattern observed", "monitor", "Bearer fixture-token-abcdefghijklmnop", "pattern", "would-block", "would-block", 204, 1},
		{"mixed rules blocked", "monitor", bodyFixture + " Bearer fixture-token-abcdefghijklmnop", "fingerprint", "would-block", "block", 403, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var forwarded atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { forwarded.Add(1); w.WriteHeader(204) }))
			defer upstream.Close()
			b := bus.New(32)
			defer b.Close()
			sub := b.Subscribe()
			e := bodyEngine(t, tc.mode)
			if tc.name == "mixed rules blocked" {
				e.SetRuleMode("bearer-token", firewall.ModeBlock)
			}
			ps := NewProxyServer(0, b, nil, e)
			r := httptest.NewRequest("POST", upstream.URL+"/upload", strings.NewReader(tc.body))
			w := httptest.NewRecorder()
			ps.inspectAndForwardHTTP(w, r)
			if w.Code != tc.status || int(forwarded.Load()) != tc.forwarded {
				t.Fatalf("status %d; forwarded %d", w.Code, forwarded.Load())
			}
			found := false
			for {
				select {
				case ev := <-sub:
					if ev.Kind != event.KindProxyHit {
						continue
					}
					raw, err := json.Marshal(ev)
					if err != nil {
						t.Fatal(err)
					}
					if strings.Contains(string(raw), tc.body) || strings.Contains(string(raw), bodyFixture) {
						t.Fatal("matched bytes entered the event")
					}
					var decoded struct {
						Payload struct {
							Layer, Field, Verdict string
							Finding               string `json:"finding_action"`
							Request               string `json:"request_action"`
						} `json:"payload"`
					}
					if err := json.Unmarshal(raw, &decoded); err != nil {
						t.Fatal(err)
					}
					p := decoded.Payload
					if p.Layer == tc.layer {
						found = true
						if p.Field != "body" || p.Verdict != "leak" || p.Finding != tc.finding || p.Request != tc.request {
							t.Fatalf("incorrect gate evidence: %s", raw)
						}
					}
				default:
					if !found {
						t.Fatal("proxy omitted typed payload outcome")
					}
					return
				}
			}
		})
	}
}

func TestExpectedVendorAuthenticationCreatesNoLeakFinding(t *testing.T) {
	b := bus.New(16)
	defer b.Close()
	sub := b.Subscribe()
	ps := NewProxyServer(0, b, nil, testProxyEngine(t, "block"))
	r := httptest.NewRequest("POST", "https://api.anthropic.com/messages", nil)
	r.Header.Set("Authorization", "Bearer fixture-token-abcdefghijklmnop")
	if blocked, _ := ps.inspectRequest(r, "api.anthropic.com"); blocked {
		t.Fatal("expected vendor authentication blocked")
	}
	select {
	case ev := <-sub:
		t.Fatalf("legitimate auth raised a finding: %+v", ev)
	default:
	}
}
