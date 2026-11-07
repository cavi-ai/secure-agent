package collect

import (
	"testing"
	"time"
)

func TestOpenclawSessionUsesRecordedWorkspace(t *testing.T) {
	dir, _ := openclawFixture(t)
	db := openclawAgentFixture(t, dir)
	if _, err := db.Exec(`INSERT INTO transcript_events (session_id,seq,event_json,created_at) VALUES
		('s-sig',0,'{"type":"session","cwd":"/workspace/marketing"}',1)`); err != nil {
		t.Fatal(err)
	}
	c, _, seen, _ := newTestOpenclaw(t, dir)
	c.pollOnce()
	if len(*seen) == 0 || (*seen)[0].workspace != "/workspace/marketing" {
		t.Fatalf("session identity = %+v, want the recorded workspace", *seen)
	}
}

func TestOpenclawLCMSightingKeepsAgentAndRecordedTime(t *testing.T) {
	dir, _ := openclawFixture(t)
	db := openclawAgentFixture(t, dir)
	if _, err := db.Exec(`DELETE FROM transcript_events;
		INSERT INTO transcript_events (session_id,seq,event_json,created_at) VALUES
		('s-sig',0,'{"type":"session","cwd":"/workspace/marketing"}',1)`); err != nil {
		t.Fatal(err)
	}
	c, _, _, _ := newTestOpenclaw(t, dir)
	var seen []TraceSession
	c.OnSessionSeen = func(s TraceSession) { seen = append(seen, s) }
	c.pollOnce()
	wantTime := time.Date(2026, 9, 23, 7, 0, 0, 0, time.UTC)
	if len(seen) != 2 || seen[0].Workspace != "/workspace/marketing" || seen[0].Origin != "ember (openclaw)" || !seen[0].At.Equal(wantTime) {
		t.Fatalf("LCM identity lost: %+v", seen)
	}
	if seen[1].Workspace != "openclaw:juniper" || seen[1].Origin != "juniper (openclaw)" {
		t.Fatalf("missing metadata fabricated a workspace: %+v", seen[1])
	}
}

func TestOpenclawIdentityRejectsAgentPaths(t *testing.T) {
	for _, agent := range []string{"..", "../outside", "/outside", `..\outside`} {
		c := NewOpenclawCollector(nil, "/state/lcm.db", 0)
		var got TraceSession
		c.OnSessionSeen = func(s TraceSession) { got = s }
		c.noteSession("s", agent, time.Unix(1, 0), nil)
		if got.Workspace != "openclaw" || got.Origin != "" {
			t.Fatalf("agent path %q became identity: %+v", agent, got)
		}
	}
}

func TestOpenclawIdentityRetriesMissingHeaderOnLaterActivity(t *testing.T) {
	dir, lcm := openclawFixture(t)
	db := openclawAgentFixture(t, dir)
	c, _, seen, _ := newTestOpenclaw(t, dir)
	c.pollOnce()
	before := len(*seen)
	if _, err := db.Exec(`INSERT INTO transcript_events (session_id,seq,event_json,created_at) VALUES
		('s-sig',0,'{"type":"session","cwd":"/workspace/marketing"}',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := lcm.Exec(`INSERT INTO messages (conversation_id,seq,role,content,token_count,created_at)
		VALUES (1,99,'user','',0,'2026-09-23 07:02:00')`); err != nil {
		t.Fatal(err)
	}
	now := c.now().Add(openclawPollInterval)
	c.now = func() time.Time { return now }
	c.pollOnce()
	if len(*seen) != before+1 || (*seen)[len(*seen)-1].workspace != "/workspace/marketing" {
		t.Fatalf("later metadata was not adopted: %+v", *seen)
	}
	c.pollOnce()
	if len(*seen) != before+1 {
		t.Fatal("unchanged identity produced duplicate sightings")
	}
}
