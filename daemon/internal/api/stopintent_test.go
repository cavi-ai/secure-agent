package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// POST /daemon/stop-intent records an intent for the pinned UI and the owner
// uid; an agent-family peer gets the gate's 403 and records nothing.
func TestStopIntentRoutePeerRoles(t *testing.T) {
	const gateRefusal = "requires a more privileged client"
	self := int32(os.Getpid())
	recordedAt := time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC)
	validUntil := recordedAt.Add(30 * time.Second)
	// One parent directory keeps each socket path under the unix path limit.
	dir := t.TempDir()
	for i, tc := range []struct {
		name  string
		uiPID int32
		agent bool
		want  int
	}{
		{"pinned UI", self, false, http.StatusOK},
		{"owner beside a pinned UI", self + 9999, false, http.StatusOK},
		{"owner headless", 0, false, http.StatusOK},
		{"agent beside a pinned UI", self + 9999, true, http.StatusForbidden},
		{"agent headless", 0, true, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock := filepath.Join(dir, fmt.Sprintf("%d.sock", i))
			recorded := 0
			deps := Deps{SocketPath: sock, Store: testStore(t), Status: func() Status { return Status{Running: true} }}
			deps.Peers.Checker = loopbackChecker{NewPeerChecker()}
			deps.Peers.AgentPIDs = func() map[int32]struct{} { return nil }
			deps.Peers.IsAgentPID = func(pid int32) (bool, bool) { return tc.agent && pid == self, true }
			deps.StopIntent = func() (time.Time, time.Time, error) {
				recorded++
				return recordedAt, validUntil, nil
			}
			a := newTestAPI(deps)
			a.peerRole.UIPID = tc.uiPID
			ctx, cancel := contextWithCancel()
			defer cancel()
			go a.Serve(ctx)
			waitForSocket(t, sock)

			req, _ := http.NewRequest(http.MethodPost, "http://unix/daemon/stop-intent", nil)
			resp, err := unixClient(sock).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != tc.want {
				t.Fatalf("status %d %q, want %d", resp.StatusCode, strings.TrimSpace(string(body)), tc.want)
			}
			if tc.want == http.StatusForbidden {
				if !strings.Contains(string(body), gateRefusal) {
					t.Fatalf("body %q, want the gate's refusal", body)
				}
				if recorded != 0 {
					t.Fatalf("agent peer recorded %d stop intents", recorded)
				}
				return
			}
			var got struct {
				RecordedAt string `json:"recorded_at"`
				ValidUntil string `json:"valid_until"`
			}
			if err := json.Unmarshal(body, &got); err != nil {
				t.Fatalf("body %q: %v", body, err)
			}
			if got.RecordedAt != recordedAt.Format(time.RFC3339Nano) || got.ValidUntil != validUntil.Format(time.RFC3339Nano) {
				t.Fatalf("receipt %+v, want recorded_at %s valid_until %s", got, recordedAt.Format(time.RFC3339Nano), validUntil.Format(time.RFC3339Nano))
			}
			if recorded != 1 {
				t.Fatalf("recorded %d stop intents, want 1", recorded)
			}
		})
	}
}
