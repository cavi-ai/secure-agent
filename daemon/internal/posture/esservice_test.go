package posture

import (
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
)

// A running root service whose helper binary is newer than the last spool
// write lost its privacy grant: the item must name the re-grant. An older
// helper keeps the generic not-writing detail.
func TestESServiceItemsNamesRegrantAfterHelperReplaced(t *testing.T) {
	now := time.Now()
	replaced := ESServiceItems(time.Now(), collect.ESServiceSnapshot{
		State: "running", SpoolSize: 10, SpoolMtime: now.Add(-2 * time.Hour), HelperMtime: now.Add(-time.Hour),
	})
	if len(replaced) != 1 || replaced[0].Kind != "collector_silent" {
		t.Fatalf("replaced helper: items = %+v, want one collector_silent", replaced)
	}
	d := replaced[0].Detail
	if !strings.Contains(d, "helper binary was replaced after the last write") ||
		!strings.Contains(d, "grant Full Disk Access again for Secure Agent") {
		t.Fatalf("replaced helper detail must name the re-grant, got %q", d)
	}
	if strings.Contains(d, collect.ESServiceLabel) {
		t.Fatalf("user-facing detail must name the app, not the launchd label: %q", d)
	}

	unchanged := ESServiceItems(time.Now(), collect.ESServiceSnapshot{
		State: "running", SpoolSize: 10, SpoolMtime: now.Add(-2 * time.Hour), HelperMtime: now.Add(-3 * time.Hour),
	})
	if len(unchanged) != 1 {
		t.Fatalf("unchanged helper: items = %+v, want one", unchanged)
	}
	if strings.Contains(unchanged[0].Detail, "replaced") || !strings.Contains(unchanged[0].Detail, "file telemetry may be blind") {
		t.Fatalf("unchanged helper must keep the generic detail, got %q", unchanged[0].Detail)
	}

	// launchd keeps an earlier exit code after a restart: still running.
	restarted := ESServiceItems(time.Now(), collect.ESServiceSnapshot{
		State: "running (last exit 1)", SpoolSize: 10, SpoolMtime: now.Add(-2 * time.Hour), HelperMtime: now.Add(-time.Hour),
	})
	if len(restarted) != 1 || !strings.Contains(restarted[0].Detail, "helper binary was replaced after the last write") {
		t.Fatalf("restarted helper: items = %+v, want the re-grant item, not a failing service", restarted)
	}
	if fresh := ESServiceItems(time.Now(), collect.ESServiceSnapshot{State: "running (last exit 1)", SpoolSize: 10, SpoolMtime: now}); len(fresh) != 0 {
		t.Fatalf("restarted helper writing now: items = %+v, want none", fresh)
	}
}

// launchd refusing every spawn (78: EX_CONFIG, e.g. a registration bound to
// a replaced build) or a spawn-scheduled service that last exited nonzero
// needs Re-register; the posture detail names it.
func TestESServiceRefusedNamesReregister(t *testing.T) {
	for state, want := range map[string]bool{
		"spawn scheduled (last exit 78: EX_CONFIG)": true,
		"not running (last exit 78: EX_CONFIG)":     true,
		"spawn scheduled (last exit 1)":             true,
		"spawn scheduled":                           false,
		"not running (last exit 1)":                 false,
		"running (last exit 78: EX_CONFIG)":         false,
		"not-loaded":                                false,
	} {
		if got := ESServiceRefused(state); got != want {
			t.Errorf("ESServiceRefused(%q) = %v, want %v", state, got, want)
		}
	}

	stale := time.Now().Add(-8 * time.Minute)
	items := ESServiceItems(time.Now(), collect.ESServiceSnapshot{State: "spawn scheduled (last exit 78: EX_CONFIG)", SpoolSize: 10, SpoolMtime: stale})
	if len(items) != 1 || !strings.Contains(items[0].Detail, "78: EX_CONFIG") || !strings.Contains(items[0].Detail, "Re-register") ||
		!strings.Contains(items[0].Detail, "/var/log/secure-agent-esd.log") {
		t.Fatalf("refused service: items = %+v, want one failing item naming the exit code, Re-register and the log", items)
	}
	plain := ESServiceItems(time.Now(), collect.ESServiceSnapshot{State: "spawn scheduled", SpoolSize: 10, SpoolMtime: stale})
	if len(plain) != 1 || strings.Contains(plain[0].Detail, "Re-register") {
		t.Fatalf("spawn scheduled without an exit: items = %+v, want one failing item without Re-register", plain)
	}
}

// A writer producing mostly-unparseable lines (UnparsedShare over half) is
// real garbage and supersedes the ordinary not-writing/crash-loop items.
// Flooding (the tailer skipping past its per-tick budget) alone is a burst,
// not garbage: a short one is invisible, a sustained one reads as "falling
// behind", never as "flooding".
// timeAt returns a pointer to t, for optional time fields.
func timeAt(t time.Time) *time.Time { return &t }

func TestESServiceItemsFlooding(t *testing.T) {
	shortBurst := ESServiceItems(time.Now(), collect.ESServiceSnapshot{
		State: "running", SpoolMtime: time.Now(), Flooding: true, UnparsedShare: 0, FloodingSince: timeAt(time.Now().Add(-5 * time.Second)),
	})
	if len(shortBurst) != 0 {
		t.Fatalf("Flooding=true, FloodingSince=5s ago: items = %+v, want none — a short burst is normal load", shortBurst)
	}
	sustained := ESServiceItems(time.Now(), collect.ESServiceSnapshot{
		State: "running", SpoolMtime: time.Now(), Flooding: true, UnparsedShare: 0, FloodingSince: timeAt(time.Now().Add(-2 * time.Minute)),
	})
	if len(sustained) != 1 || sustained[0].Title != "File monitoring is falling behind" {
		t.Fatalf("Flooding=true, FloodingSince=2m ago: items = %+v, want one falling-behind item", sustained)
	}
	unparsed := ESServiceItems(time.Now(), collect.ESServiceSnapshot{State: "running", SpoolMtime: time.Now(), UnparsedShare: 0.9})
	if len(unparsed) != 1 || unparsed[0].Title != "File monitoring writer is flooding" {
		t.Fatalf("UnparsedShare=0.9: items = %+v, want one flooding item", unparsed)
	}
	ok := ESServiceItems(time.Now(), collect.ESServiceSnapshot{State: "running", SpoolMtime: time.Now(), UnparsedShare: 0.1})
	if len(ok) != 0 {
		t.Fatalf("UnparsedShare=0.1: items = %+v, want none", ok)
	}
}

// File events stored with their event time but delivered hours later read as
// a late monitor, not a healthy one; a stale spool's last lag does not.
func TestESServiceItemsLagging(t *testing.T) {
	late := ESServiceItems(time.Now(), collect.ESServiceSnapshot{State: "running", SpoolMtime: time.Now(), NewestEventAt: timeAt(time.Now().Add(-2 * time.Hour)), LagSeconds: 7200})
	if len(late) != 1 || late[0].Title != "File monitoring is running late" || late[0].Severity != 2 || !strings.Contains(late[0].Detail, "delivery is 2h0m0s behind") {
		t.Fatalf("lag 2h: items = %+v, want one running-late item", late)
	}
	onTime := ESServiceItems(time.Now(), collect.ESServiceSnapshot{State: "running", SpoolMtime: time.Now(), NewestEventAt: timeAt(time.Now()), LagSeconds: 119})
	if len(onTime) != 0 {
		t.Fatalf("lag 119s: items = %+v, want none", onTime)
	}
	idle := ESServiceItems(time.Now(), collect.ESServiceSnapshot{State: "running", SpoolMtime: time.Now().Add(-10 * time.Minute), NewestEventAt: timeAt(time.Now().Add(-2 * time.Hour)), LagSeconds: 7200})
	if len(idle) != 0 {
		t.Fatalf("spool idle 10 min: items = %+v, want none", idle)
	}
}

// Garbage left in a spool nobody writes is not a flood: once the writer
// stops, the verdict yields to the service's real state.
func TestESServiceItemsStaleFloodYieldsToServiceState(t *testing.T) {
	idle := time.Now().Add(-10 * time.Minute)
	off := ESServiceItems(time.Now(), collect.ESServiceSnapshot{State: "not-loaded", SpoolMtime: idle, Flooding: true, UnparsedShare: 0.99})
	if len(off) != 1 || off[0].Title != "File monitoring is off" || !strings.Contains(off[0].Detail, "Full Disk Access") {
		t.Fatalf("not-loaded after a flood: items = %+v, want one File monitoring is off item", off)
	}
	quiet := ESServiceItems(time.Now(), collect.ESServiceSnapshot{State: "running", SpoolMtime: idle, Flooding: true, UnparsedShare: 0.99})
	if len(quiet) != 0 {
		t.Fatalf("running, spool idle 10 min, stale flood stats: items = %+v, want none", quiet)
	}
}
