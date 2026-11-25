package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func postDelivery(t *testing.T, srv *httptest.Server, env Envelope, wantStatus int) {
	t.Helper()
	body, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	resp := post(t, srv, "s", body, env.NodeID)
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		t.Fatalf("delivery %d status = %d, want %d", env.Seq, resp.StatusCode, wantStatus)
	}
}

func assertDeliveryCount(t *testing.T, store *Store, want int) {
	t.Helper()
	if got := len(store.Query("n1", nil, 0)); got != want {
		t.Errorf("stored deliveries = %d, want %d", got, want)
	}
	rollup := store.Rollup()
	if len(rollup) != 1 || rollup[0].NodeID != "n1" {
		t.Fatalf("expected one node in rollup, got %+v", rollup)
	}
	if got := rollup[0].Flags; got != want {
		t.Errorf("rollup flags = %d, want %d", got, want)
	}
}

func TestRedeliveredEnvelopeIsNotStoredOrCounted(t *testing.T) {
	c, srv := testCollector(t, map[string]string{"n1": "s"})
	env := seqEnv("n1", "b1", 1)
	env.TS = time.Now().UTC().Format(time.RFC3339Nano)
	postDelivery(t, srv, env, http.StatusOK)
	postDelivery(t, srv, env, http.StatusOK)
	assertDeliveryCount(t, c.store, 1)
}

func TestDistinctSequencesStillCount(t *testing.T) {
	c, srv := testCollector(t, map[string]string{"n1": "s"})
	postDelivery(t, srv, seqEnv("n1", "b1", 1), http.StatusOK)
	postDelivery(t, srv, seqEnv("n1", "b1", 2), http.StatusOK)
	assertDeliveryCount(t, c.store, 2)
}

func TestLateFirstDeliveryFillingHoleIsStored(t *testing.T) {
	c, srv := testCollector(t, map[string]string{"n1": "s"})
	for _, seq := range []uint64{1, 3, 2} {
		postDelivery(t, srv, seqEnv("n1", "b1", seq), http.StatusOK)
	}
	assertDeliveryCount(t, c.store, 3)
}

func TestRedeliveryAfterCollectorRestartIsDropped(t *testing.T) {
	dir := t.TempDir()
	env := seqEnv("n1", "b1", 1)
	env.Payload = json.RawMessage(`{ "rule": "rule<>&" }`)
	mustAppend(t, openTestStore(t, dir), env)
	store := openTestStore(t, dir)
	mustAppend(t, store, env)
	assertDeliveryCount(t, store, 1)
}

func TestDistinctEnvelopesWithSameSequenceAreKept(t *testing.T) {
	c, srv := testCollector(t, map[string]string{"n1": "s"})
	now := time.Now().UTC()
	first := seqEnv("n1", "b1", 1)
	first.TS = now.Format(time.RFC3339Nano)
	distinctPayload := first
	distinctPayload.Payload = json.RawMessage(`{"rule":"different-rule","severity":3}`)
	distinctTime := first
	distinctTime.TS = now.Add(time.Nanosecond).Format(time.RFC3339Nano)
	deliveries := []Envelope{first, distinctPayload, distinctTime}
	for _, env := range deliveries {
		postDelivery(t, srv, env, http.StatusOK)
	}
	for _, env := range deliveries {
		postDelivery(t, srv, env, http.StatusOK)
	}
	assertDeliveryCount(t, c.store, len(deliveries))

	store := openTestStore(t, c.cfg.StoreDir)
	assertDeliveryCount(t, store, len(deliveries))
	for _, env := range deliveries {
		mustAppend(t, store, env)
	}
	assertDeliveryCount(t, store, len(deliveries))
}

func TestRedeliveryCoversPublisherRetryHorizon(t *testing.T) {
	for _, tc := range []struct {
		name string
		age  time.Duration
		want int
	}{
		{"final retry", 38 * time.Second, 1},
		{"expired", 2 * time.Minute, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			env := seqEnv("n1", "b1", 1)
			log := &jsonlLog{dir: dir}
			receivedAt := time.Now().UTC().Add(-tc.age).Format(time.RFC3339Nano)
			if err := log.Append(env, receivedAt); err != nil {
				t.Fatal(err)
			}
			store := openTestStore(t, dir)
			mustAppend(t, store, env)
			assertDeliveryCount(t, store, tc.want)
		})
	}
}

func TestFailedFirstDeliveryDoesNotRegisterNode(t *testing.T) {
	c, srv := testCollector(t, map[string]string{"n1": "s"})
	path := filepath.Join(c.cfg.StoreDir, "n1.jsonl")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	env := seqEnv("n1", "b1", 1)
	postDelivery(t, srv, env, http.StatusInternalServerError)
	if got := len(c.store.Rollup()); got != 0 {
		t.Errorf("rollup nodes after failed append = %d, want 0", got)
	}
	if got := c.store.RuleAggregates().TotalNodes; got != 0 {
		t.Errorf("rule aggregate nodes after failed append = %d, want 0", got)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	postDelivery(t, srv, env, http.StatusOK)
	postDelivery(t, srv, env, http.StatusOK)
	assertDeliveryCount(t, c.store, 1)
}
