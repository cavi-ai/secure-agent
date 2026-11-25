package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func postSeq(t *testing.T, srvURL, node, secret, boot string, seq uint64) int {
	t.Helper()
	body, _ := json.Marshal(Envelope{
		NodeID: node, Kind: "flag", TS: time.Now().UTC().Format(time.RFC3339Nano),
		Version: "v1", Boot: boot, Seq: seq,
		Payload: json.RawMessage(`{"rule":"aws-key","severity":3}`),
	})
	req, _ := http.NewRequest("POST", srvURL+"/hooks/secure-agent", bytes.NewReader(body))
	req.Header.Set("X-SecureAgent-Signature", sign(t, secret, body))
	req.Header.Set("X-SecureAgent-Node", node)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func storedSeqs(c *Collector, node string) int {
	return len(c.store.log.Query(node, nil, 0))
}

func flagCount(c *Collector, node string) int {
	for _, n := range c.store.Rollup() {
		if n.NodeID == node {
			return n.Flags
		}
	}
	return 0
}

func TestRedeliveredEnvelopeIsNotStoredOrCounted(t *testing.T) {
	c, srv := testCollector(t, map[string]string{"n1": "s"})
	for i := 0; i < 2; i++ {
		if code := postSeq(t, srv.URL, "n1", "s", "b1", 1); code != 200 {
			t.Fatalf("delivery %d status = %d", i, code)
		}
	}
	if got := storedSeqs(c, "n1"); got != 1 {
		t.Fatalf("stored records = %d, want 1", got)
	}
	if got := flagCount(c, "n1"); got != 1 {
		t.Fatalf("flags = %d, want 1", got)
	}
}

func TestDistinctSequencesStillCount(t *testing.T) {
	c, srv := testCollector(t, map[string]string{"n1": "s"})
	postSeq(t, srv.URL, "n1", "s", "b1", 1)
	postSeq(t, srv.URL, "n1", "s", "b1", 2)
	if got, n := storedSeqs(c, "n1"), flagCount(c, "n1"); got != 2 || n != 2 {
		t.Fatalf("stored=%d flags=%d, want 2/2", got, n)
	}
}

func TestLateFirstDeliveryFillingHoleIsStored(t *testing.T) {
	c, srv := testCollector(t, map[string]string{"n1": "s"})
	for _, seq := range []uint64{1, 3, 2} {
		if code := postSeq(t, srv.URL, "n1", "s", "b1", seq); code != 200 {
			t.Fatalf("seq %d status = %d", seq, code)
		}
	}
	if got, n := storedSeqs(c, "n1"), flagCount(c, "n1"); got != 3 || n != 3 {
		t.Fatalf("stored=%d flags=%d, want 3/3", got, n)
	}
}

func TestRedeliveryAfterCollectorRestartIsDropped(t *testing.T) {
	c, srv := testCollector(t, map[string]string{"n1": "s"})
	postSeq(t, srv.URL, "n1", "s", "b1", 1)
	c.store = NewStore(c.cfg.StoreDir)
	if code := postSeq(t, srv.URL, "n1", "s", "b1", 1); code != 200 {
		t.Fatalf("status = %d", code)
	}
	if got, n := storedSeqs(c, "n1"), flagCount(c, "n1"); got != 1 || n != 1 {
		t.Fatalf("stored=%d flags=%d, want 1/1", got, n)
	}
}
