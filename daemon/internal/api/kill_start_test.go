package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestKillEndpointRejectsStartMismatch(t *testing.T) {
	fk := &fakeKiller{}
	a := New("", testStore(t), fk, func() Status {
		return Status{Running: true, Agents: []AgentSummary{
			{PID: 7, Name: "claude", StartedAt: "2026-09-09T16:00:00Z"},
		}}
	})
	req := httptest.NewRequest(http.MethodPost, "/kill", strings.NewReader(`{"pid":7,"started_at":"2026-01-01T00:00:00Z"}`))
	rec := httptest.NewRecorder()
	a.handleKill(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d, want 409", rec.Code)
	}
	if fk.killed != 0 {
		t.Fatalf("killed %d, want none", fk.killed)
	}
}

func TestKillEndpointAllowsMatchingStart(t *testing.T) {
	fk := &fakeKiller{}
	a := New("", testStore(t), fk, func() Status {
		return Status{Running: true, Agents: []AgentSummary{
			{PID: 7, Name: "claude", StartedAt: "2026-09-09T16:00:00Z"},
		}}
	})
	req := httptest.NewRequest(http.MethodPost, "/kill", strings.NewReader(`{"pid":7,"started_at":"2026-09-09T16:00:00Z"}`))
	rec := httptest.NewRecorder()
	a.handleKill(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	if fk.killed != 7 {
		t.Fatalf("killed %d, want 7", fk.killed)
	}
}
