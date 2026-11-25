package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type errKiller struct{ err error }

func (k *errKiller) Kill(int32) error { return k.err }

func TestKillEndpointStatusByError(t *testing.T) {
	const started = "2026-09-09T16:00:00Z"
	tests := []struct {
		name       string
		body       string
		agentPIDs  func() func() map[int32]struct{}
		killErr    error
		wantStatus int
		wantBody   string
	}{
		{
			name: "not a recognized agent",
			body: `{"pid":7}`,
			agentPIDs: func() func() map[int32]struct{} {
				return func() map[int32]struct{} { return map[int32]struct{}{} }
			},
			wantStatus: http.StatusForbidden,
			wantBody:   "pid is not a recognized agent process tree\n",
		},
		{
			name: "agent gone before signal",
			body: `{"pid":7}`,
			agentPIDs: func() func() map[int32]struct{} {
				calls := 0
				return func() map[int32]struct{} {
					calls++
					if calls == 1 {
						return map[int32]struct{}{7: {}}
					}
					return map[int32]struct{}{}
				}
			},
			wantStatus: http.StatusConflict,
			wantBody:   "pid is no longer a recognized agent process\n",
		},
		{
			name:       "start time mismatch",
			body:       `{"pid":7,"started_at":"2026-01-01T00:00:00Z"}`,
			wantStatus: http.StatusConflict,
			wantBody:   "pid 7 start time mismatch (process recycled?)\n",
		},
		{
			name:       "killer failure",
			body:       `{"pid":7}`,
			killErr:    errors.New("permission denied"),
			wantStatus: http.StatusInternalServerError,
			wantBody:   "Kill failed: permission denied\n",
		},
		{
			name:       "killer failure containing start",
			body:       `{"pid":7}`,
			killErr:    errors.New("restart pending"),
			wantStatus: http.StatusInternalServerError,
			wantBody:   "Kill failed: restart pending\n",
		},
		{
			name:       "killer failure containing no longer",
			body:       `{"pid":7}`,
			killErr:    errors.New("process no longer exists"),
			wantStatus: http.StatusInternalServerError,
			wantBody:   "Kill failed: process no longer exists\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newTestAPI(Deps{SocketPath: "", Store: testStore(t), Killer: &errKiller{err: tt.killErr}, Status: func() Status {
				return Status{Running: true, Agents: []AgentSummary{
					{PID: 7, Name: "claude", StartedAt: started},
				}}
			}})
			if tt.agentPIDs != nil {
				a.agentPIDs = tt.agentPIDs()
			}
			req := httptest.NewRequest(http.MethodPost, "/kill", strings.NewReader(tt.body))
			rec := httptest.NewRecorder()
			a.handleKill(rec, req)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status=%d, want %d (body %q)", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if rec.Body.String() != tt.wantBody {
				t.Fatalf("body=%q, want %q", rec.Body.String(), tt.wantBody)
			}
		})
	}
}
