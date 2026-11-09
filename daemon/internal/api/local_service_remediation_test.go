package api

import (
	"github.com/cavi-ai/secure-agent/daemon/internal/apiroutes"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemediationBoundaryRejectsAmbiguousAndOversizedRequests(t *testing.T) {
	a := newTestAPI(Deps{Store: testStore(t), ConfigPath: filepath.Join(t.TempDir(), "config.yaml")})
	for _, body := range []string{`{}`, `{"action":"preview","source":"/model.plist","label":"extra"}`, `{"action":"apply","id":"id"}`, `{"action":"rollback","label":"model","source":"extra"}`, `{"action":"apply","id":"id","preview_hash":"hash","unknown":true}`, `{} {}`, strings.Repeat(" ", 8193) + `{}`} {
		w := httptest.NewRecorder()
		a.handleLocalServiceRemediation(w, httptest.NewRequest("POST", "/local-services/remediation", strings.NewReader(body)))
		if w.Code != 400 {
			t.Fatalf("ambiguous input admitted: %d %s", w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	a.handleLocalServiceRemediation(w, httptest.NewRequest("POST", "/local-services/remediation", strings.NewReader(`{"action":"apply","id":"missing","preview_hash":"hash"}`)))
	if w.Code != 409 || !strings.Contains(w.Body.String(), "expired or changed") {
		t.Fatalf("unreviewed apply: %d %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Content-Type") != "application/json" {
		t.Fatal("mutation failure must retain its JSON response contract")
	}
	for _, path := range []string{"/local-services/remediation", "/local-services/receipt"} {
		if !apiroutes.IsNoAgent(path) {
			t.Fatal("service operation lacks owner peer boundary")
		}
	}
	if !apiroutes.IsMutation("POST", "/local-services/remediation") {
		t.Fatal("service mutations bypass mutation boundary")
	}
}

func TestReceiptRequiresOneLabelAndSavedConfiguration(t *testing.T) {
	a := newTestAPI(Deps{Store: testStore(t), ConfigPath: filepath.Join(t.TempDir(), "config.yaml")})
	for _, query := range []string{"", "?label=a&label=b", "?label=a&extra=b"} {
		w := httptest.NewRecorder()
		a.handleLocalServiceReceipt(w, httptest.NewRequest("GET", "/local-services/receipt"+query, nil))
		if w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
	a.modelServices = nil
	w := httptest.NewRecorder()
	a.handleLocalServiceRemediation(w, httptest.NewRequest("POST", "/local-services/remediation", strings.NewReader(`{}`)))
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
}
