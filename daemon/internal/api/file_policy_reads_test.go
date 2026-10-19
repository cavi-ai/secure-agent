package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
)

func TestFilePolicyReadsReportFailureAndRecover(t *testing.T) {
	for _, route := range []string{"/mute", "/expected"} {
		for _, fault := range []string{"missing", "empty", "corrupt", "null", "wrong-root", "wrong-row", "unreadable"} {
			t.Run(route+"/"+fault, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "policy.json")
				broken := "{broken"
				switch fault {
				case "empty":
					broken = "{}"
					if route == "/expected" {
						broken = "[]"
					}
				case "null":
					broken = "null"
				case "wrong-root":
					broken = "[]"
					if route == "/expected" {
						broken = "{}"
					}
				case "wrong-row":
					broken = `{"rule":["valid.example.com",true]}`
					if route == "/expected" {
						broken = `[{"agent":"claude"},{"agent":true}]`
					}
				}
				if fault == "unreadable" {
					if err := os.Mkdir(path, 0o700); err != nil {
						t.Fatal(err)
					}
				} else if fault != "missing" {
					if err := os.WriteFile(path, []byte(broken), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				st := testStore(t)
				t.Cleanup(func() { _ = st.Close() })
				a := newTestAPI(Deps{Store: st, Policy: PolicyDeps{Mutes: correlate.NewMuteStore(path), Expected: correlate.NewExpectStore(path)}})
				w := call(t, a, http.MethodGet, route, "")
				if fault == "missing" || fault == "empty" {
					if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "[]" {
						t.Fatalf("empty policy: %d %s", w.Code, w.Body)
					}
					return
				}
				if w.Code != http.StatusServiceUnavailable {
					t.Fatalf("failed policy read: %d %s", w.Code, w.Body)
				}
				if strings.Contains(w.Body.String(), path) || strings.Contains(w.Body.String(), "decode") {
					t.Fatalf("policy diagnostic exposed: %s", w.Body)
				}
				if fault == "unreadable" {
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				} else if data, err := os.ReadFile(path); err != nil || string(data) != broken {
					t.Fatalf("failed read changed policy: %q %v", data, err)
				}
				repaired := `{"rule":["api.example.com"]}`
				if route == "/expected" {
					repaired = `[{"agent":"claude","reader":"tool","path":"/synthetic/config","dest":"api.example.com","created_at":"2026-10-01T00:00:00Z"}]`
				}
				if err := os.WriteFile(path, []byte(repaired), 0o600); err != nil {
					t.Fatal(err)
				}
				w = call(t, a, http.MethodGet, route, "")
				var rows []json.RawMessage
				if err := json.Unmarshal(w.Body.Bytes(), &rows); w.Code != http.StatusOK || err != nil || len(rows) != 1 {
					t.Fatalf("read after repair: %d %s (%v)", w.Code, w.Body, err)
				}
				if route == "/mute" {
					var got MutePair
					if err := json.Unmarshal(rows[0], &got); err != nil || got.Rule != "rule" || got.Host != "api.example.com" {
						t.Fatalf("repaired mute: %+v %v", got, err)
					}
				} else {
					key := correlate.ReadConnectKey("claude", "tool", "/synthetic/config", "api.example.com")
					if !a.expected.Has(key) {
						t.Fatal("repaired list does not match active policy")
					}
				}
			})
		}
	}
}
