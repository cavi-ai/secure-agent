package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestFlagSeverityKeepsIntegersAndRejectsFractionalValues(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
		want    int64
		wide    bool
	}{
		{"weak", `{"severity":1}`, 1, false},
		{"suspicious", `{"severity":2}`, 2, false},
		{"critical", `{"severity":3}`, 3, false},
		{"fraction", `{"severity":3.9}`, 0, false},
		{"decimal", `{"severity":3.0}`, 0, false},
		{"exponent", `{"severity":3e0}`, 0, false},
		{"beyond-float-precision", `{"severity":9007199254740993}`, 9007199254740993, true},
		{"largest-signed", `{"severity":9223372036854775807}`, 9223372036854775807, true},
		{"outside-signed-range", `{"severity":18446744073709551615}`, 0, false},
		{"string", `{"severity":"3"}`, 0, false},
		{"boolean", `{"severity":true}`, 0, false},
		{"null", `{"severity":null}`, 0, false},
		{"absent", `{}`, 0, false},
		{"malformed", `{"severity":3`, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wide && strconv.IntSize < 64 {
				t.Skip("value requires a 64-bit native integer")
			}
			if got := flagSeverity(json.RawMessage(tc.payload)); int64(got) != tc.want {
				t.Errorf("severity = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestFleetCriticalCountsFollowIntegerSeverityAfterReplay(t *testing.T) {
	for _, tc := range []struct {
		name     string
		severity string
		critical int
		wide     bool
	}{
		{"critical", "3", 1, false},
		{"fraction", "3.9", 0, false},
		{"large-integer", "9223372036854775807", 1, true},
		{"outside-range", "18446744073709551615", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wide && strconv.IntSize < 64 {
				t.Skip("value requires a 64-bit native integer")
			}
			c, srv := testCollector(t, map[string]string{"n1": "[REDACTED]"})
			payload := json.RawMessage(`{"rule":"read-then-connect","severity":` + tc.severity + `}`)
			body, err := json.Marshal(Envelope{NodeID: "n1", Kind: "flag", Version: "v1", TS: time.Now().UTC().Format(time.RFC3339Nano), Payload: payload})
			if err != nil {
				t.Fatal(err)
			}
			resp := post(t, srv, "[REDACTED]", body, "n1")
			resp.Body.Close()
			if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
				t.Fatalf("signed flag rejected: %d", resp.StatusCode)
			}
			check := func() {
				t.Helper()
				var nodes []NodeState
				if err := json.Unmarshal([]byte(get(t, srv.URL+"/fleet")), &nodes); err != nil || len(nodes) != 1 {
					t.Fatalf("node rollup: %+v %v", nodes, err)
				}
				if nodes[0].Flags != 1 || nodes[0].Flags24h != 1 || nodes[0].CriticalFlags24h != tc.critical {
					t.Errorf("wrong flag counts: %+v", nodes[0])
				}
				var rules FleetRules
				if err := json.Unmarshal([]byte(get(t, srv.URL+"/fleet/rules")), &rules); err != nil || len(rules.Rules) != 1 {
					t.Fatalf("rule rollup: %+v %v", rules, err)
				}
				if r := rules.Rules[0]; r.Rule != "read-then-connect" || r.Nodes != 1 || r.Flags24h != 1 || r.Critical24h != tc.critical {
					t.Errorf("wrong rule counts: %+v", r)
				}
				var stored []envelopeFile
				if err := json.Unmarshal([]byte(get(t, srv.URL+"/nodes/n1/events")), &stored); err != nil || len(stored) != 1 || !bytes.Equal(stored[0].Envelope.Payload, payload) {
					t.Errorf("stored evidence changed: %+v %v", stored, err)
				}
			}
			check()
			// Stop serving before replacing the replayed state.
			srv.Close()
			c.store = NewStore(c.cfg.StoreDir)
			srv = httptest.NewServer(srv.Config.Handler)
			defer srv.Close()
			check()
		})
	}
}
