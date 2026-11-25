package api

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/hostid"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// Each test changes one input that no store statement records between two
// GET /snapshot calls; the second response must follow it.

type liveInputsView struct {
	Patterns []struct {
		Subject struct {
			Sub string `json:"sub"`
		} `json:"subject"`
		Actions []struct {
			ID string `json:"id"`
		} `json:"actions"`
	} `json:"patterns"`
	Events []struct {
		Detail     string `json:"detail"`
		PriceClass string `json:"price_class"`
	} `json:"events"`
}

func liveInputs(t *testing.T, a *API) liveInputsView {
	t.Helper()
	var v liveInputsView
	if err := json.Unmarshal(mustGet(t, a, "/snapshot"), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// patternOffers reports whether the snapshot's only pattern offers action id.
func patternOffers(t *testing.T, a *API, id string) bool {
	t.Helper()
	v := liveInputs(t, a)
	if len(v.Patterns) != 1 {
		t.Fatalf("patterns = %d, want 1", len(v.Patterns))
	}
	for _, act := range v.Patterns[0].Actions {
		if act.ID == id {
			return true
		}
	}
	return false
}

// putPattern stores three open flags of one pattern, newest first, inside
// the 24 h window.
func putPattern(t *testing.T, a *API, now time.Time, flag func(i int) model.Flag) []model.Flag {
	t.Helper()
	var out []model.Flag
	for i := range 3 {
		f := flag(i)
		f.TS = now.Add(-time.Duration(i+1) * time.Minute)
		if _, err := a.store.PutFlag(f); err != nil {
			t.Fatal(err)
		}
		out = append(out, f)
	}
	return out
}

func requireNoStoreWrite(t *testing.T, a *API, gen uint64) {
	t.Helper()
	if got := a.store.WriteGeneration(); got != gen {
		t.Fatalf("a store write ran between the requests: generation %d -> %d", gen, got)
	}
}

func egressFlag(id, host string, pid int32) model.Flag {
	return model.Flag{ID: id, Rule: "untrusted-egress", Severity: 2, PID: pid, Agent: "codex",
		Evidence: []model.EvidenceItem{{Kind: "connect", Label: host + ":443", Sub: "egress"}}}
}

func TestSnapshotPatternFollowsAllowlist(t *testing.T) {
	clock := cacheTestClock()
	a, _ := cacheTestAPI(t, &clock)
	putPattern(t, a, clock, func(i int) model.Flag { return egressFlag(fmt.Sprintf("al%d", i), "allow.example.net", 71) })
	if !patternOffers(t, a, "allow-host") {
		t.Fatal("allow-host missing while the host is not allowed")
	}
	gen := a.store.WriteGeneration()
	if err := a.allowlist.Add("codex", "allow.example.net"); err != nil {
		t.Fatal(err)
	}
	requireNoStoreWrite(t, a, gen)
	if patternOffers(t, a, "allow-host") {
		t.Fatal("allow-host still offered after the host was allowed")
	}
}

func TestSnapshotPatternFollowsLiveAgents(t *testing.T) {
	clock := cacheTestClock()
	var live atomic.Bool
	live.Store(true)
	deps := explainTestDeps(t)
	deps.Status = func() Status {
		if live.Load() {
			return Status{Running: true, Agents: []AgentSummary{{PID: 81, Name: "codex"}}}
		}
		return Status{Running: true}
	}
	a := cacheFreeAPI(deps, &clock)
	putPattern(t, a, clock, func(i int) model.Flag { return keychainFlag(fmt.Sprintf("kl%d", i), "codex", 81, clock, 2) })
	if !patternOffers(t, a, "kill") {
		t.Fatal("kill missing while pid 81 is live")
	}
	gen := a.store.WriteGeneration()
	live.Store(false)
	requireNoStoreWrite(t, a, gen)
	if patternOffers(t, a, "kill") {
		t.Fatal("kill still offered after pid 81 left the status")
	}
}

func TestSnapshotPatternFollowsExpectations(t *testing.T) {
	clock := cacheTestClock()
	deps := explainTestDeps(t)
	deps.Policy.Expected = correlate.NewExpectStore(filepath.Join(t.TempDir(), "expected.json"))
	a := cacheFreeAPI(deps, &clock)
	flags := putPattern(t, a, clock, func(i int) model.Flag {
		return model.Flag{ID: fmt.Sprintf("ex%d", i), Rule: readConnectRule, Severity: 2, PID: 73, Agent: "codex",
			Evidence: []model.EvidenceItem{
				{Kind: "read", Label: "/Users/dev/.config/gh/hosts.yml", Sub: "sensitive read", Exe: "/usr/local/bin/gh"},
				{Kind: "connect", Label: "github.com:443", Sub: "egress"}}}
	})
	if !patternOffers(t, a, "expect") {
		t.Fatal("expect missing while the pair is not expected")
	}
	p, ok := a.nextExpectedPattern(flags[0])
	if !ok {
		t.Fatal("no expected pattern for the newest flag")
	}
	gen := a.store.WriteGeneration()
	if _, err := a.expected.Add(p); err != nil {
		t.Fatal(err)
	}
	requireNoStoreWrite(t, a, gen)
	if patternOffers(t, a, "expect") {
		t.Fatal("expect still offered after the pair was marked expected")
	}
}

func TestSnapshotPatternFollowsHostIdentityCache(t *testing.T) {
	clock := cacheTestClock()
	a, _ := cacheTestAPI(t, &clock)
	const ip = "198.51.100.77"
	putPattern(t, a, clock, func(i int) model.Flag { return egressFlag(fmt.Sprintf("hi%d", i), ip, 72) })
	org := func() string {
		v := liveInputs(t, a)
		if len(v.Patterns) != 1 {
			t.Fatalf("patterns = %d, want 1", len(v.Patterns))
		}
		return v.Patterns[0].Subject.Sub
	}
	if got := org(); got != "" {
		t.Fatalf("subject org %q before any PTR lookup", got)
	}
	gen := a.store.WriteGeneration()
	restore := hostid.SetLookupAddrForTest(func(context.Context, string) ([]string, error) {
		return []string{"ec2-198-51-100-77.compute-1.amazonaws.com."}, nil
	})
	defer restore()
	want := hostid.Identify(ip).Org
	if want == "" {
		t.Fatal("the PTR name maps to no org")
	}
	requireNoStoreWrite(t, a, gen)
	if got := org(); got != want {
		t.Fatalf("subject org %q after the PTR lookup, want %q", got, want)
	}
}

func TestSnapshotEventsFollowUserPrices(t *testing.T) {
	clock := cacheTestClock()
	a, _ := cacheTestAPI(t, &clock)
	t.Cleanup(func() { collect.SetUserPrices(nil) })
	if _, err := a.store.PutEvent(event.Event{Kind: event.KindModelCall, PID: 91, TS: clock, Model: "acme-x1", Provider: "acme", Detail: "acme-call"}); err != nil {
		t.Fatal(err)
	}
	class := func() string {
		for _, e := range liveInputs(t, a).Events {
			if e.Detail == "acme-call" {
				return e.PriceClass
			}
		}
		t.Fatal("model call missing from the snapshot")
		return ""
	}
	if got := class(); got == collect.ClassPriced {
		t.Fatalf("price class %q before the model has a price", got)
	}
	gen := a.store.WriteGeneration()
	collect.SetUserPrices(map[string][2]float64{"acme-x1": {1, 2}})
	requireNoStoreWrite(t, a, gen)
	if got := class(); got != collect.ClassPriced {
		t.Fatalf("price class %q after the model was priced, want %q", got, collect.ClassPriced)
	}
}
