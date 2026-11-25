package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

const testLogMaxBytes = 2048

func appendIndexed(t *testing.T, s *Store, from, to int) {
	t.Helper()
	for i := from; i < to; i++ {
		env := Envelope{NodeID: "n1", Kind: "flag", Version: "v1", Payload: json.RawMessage(fmt.Sprintf(`{"i":%d}`, i))}
		if err := s.Append(env); err != nil {
			t.Fatal(err)
		}
	}
}

func queriedIndexes(t *testing.T, s *Store, limit int) []int {
	t.Helper()
	var out []int
	for _, rec := range s.Query("n1", nil, limit) {
		var p struct{ I int }
		if err := json.Unmarshal(rec.Envelope.Payload, &p); err != nil {
			t.Fatal(err)
		}
		out = append(out, p.I)
	}
	return out
}

func assertNewestFirst(t *testing.T, got []int, newest int) {
	t.Helper()
	for k, v := range got {
		if v != newest-k {
			t.Fatalf("position %d = %d, want %d (got %v)", k, v, newest-k, got)
		}
	}
}

func rotatedFiles(t *testing.T, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "n1.*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestAppendPastLimitRotatesAndQueryReadsBoth(t *testing.T) {
	dir := t.TempDir()
	s := newStoreWithLog(newJSONLLog(dir, testLogMaxBytes, 1000))
	appendIndexed(t, s, 0, 60)

	if len(rotatedFiles(t, dir)) == 0 {
		t.Fatal("no rotated file after exceeding the size limit")
	}
	live, err := os.Stat(filepath.Join(dir, "n1.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if live.Size() > testLogMaxBytes {
		t.Fatalf("live log is %d bytes, limit %d", live.Size(), testLogMaxBytes)
	}
	got := queriedIndexes(t, s, 100)
	if len(got) != 60 {
		t.Fatalf("query returned %d events, want 60", len(got))
	}
	assertNewestFirst(t, got, 59)
}

func TestRetentionDropsOldestRotatedFile(t *testing.T) {
	dir := t.TempDir()
	s := newStoreWithLog(newJSONLLog(dir, testLogMaxBytes, 2))
	appendIndexed(t, s, 0, 300)

	if n := len(rotatedFiles(t, dir)); n != 2 {
		t.Fatalf("rotated files = %d, want 2", n)
	}
	got := queriedIndexes(t, s, 1000)
	if len(got) == 0 || len(got) >= 300 {
		t.Fatalf("retained %d events, want fewer than 300", len(got))
	}
	assertNewestFirst(t, got, 299)
	if got[len(got)-1] == 0 {
		t.Fatal("oldest event survived retention")
	}
}

func TestRestartReplaysRotatedAndLiveFiles(t *testing.T) {
	dir := t.TempDir()
	s1 := newStoreWithLog(newJSONLLog(dir, testLogMaxBytes, 3))
	appendIndexed(t, s1, 0, 100)
	before := queriedIndexes(t, s1, 1000)

	s2 := newStoreWithLog(newJSONLLog(dir, testLogMaxBytes, 3))
	after := queriedIndexes(t, s2, 1000)
	if fmt.Sprint(before) != fmt.Sprint(after) {
		t.Fatalf("query after restart differs:\nbefore %v\nafter  %v", before, after)
	}
	r := s2.Rollup()
	if len(r) != 1 || r[0].Flags != len(before) {
		t.Fatalf("replayed flags = %+v, want %d", r, len(before))
	}
}

func TestRestartAfterRenameWithoutLiveFile(t *testing.T) {
	dir := t.TempDir()
	s1 := newStoreWithLog(newJSONLLog(dir, testLogMaxBytes, 3))
	appendIndexed(t, s1, 0, 5)
	if err := os.Rename(filepath.Join(dir, "n1.jsonl"), filepath.Join(dir, "n1.000001.jsonl")); err != nil {
		t.Fatal(err)
	}

	s2 := newStoreWithLog(newJSONLLog(dir, testLogMaxBytes, 3))
	if r := s2.Rollup(); len(r) != 1 || r[0].Flags != 5 {
		t.Fatalf("replayed rollup = %+v, want 5 flags", r)
	}
	appendIndexed(t, s2, 5, 8)
	got := queriedIndexes(t, s2, 100)
	if len(got) != 8 {
		t.Fatalf("query returned %d events, want 8", len(got))
	}
	assertNewestFirst(t, got, 7)
}

func TestQueryStopsAtLimitAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	s := newStoreWithLog(newJSONLLog(dir, testLogMaxBytes, 1000))
	appendIndexed(t, s, 0, 60)
	got := queriedIndexes(t, s, 45)
	if len(got) != 45 {
		t.Fatalf("query returned %d events, want 45", len(got))
	}
	assertNewestFirst(t, got, 59)
}

func TestQueryReadsLinesLargerThanReadBlock(t *testing.T) {
	dir := t.TempDir()
	s := newStoreWithLog(newJSONLLog(dir, 0, 0))
	pad := make([]byte, 150<<10)
	for i := range pad {
		pad[i] = 'x'
	}
	for i := 0; i < 5; i++ {
		env := Envelope{NodeID: "n1", Kind: "flag", Version: "v1", Payload: json.RawMessage(fmt.Sprintf(`{"i":%d,"pad":"%s"}`, i, pad))}
		if err := s.Append(env); err != nil {
			t.Fatal(err)
		}
	}
	got := queriedIndexes(t, s, 100)
	if len(got) != 5 {
		t.Fatalf("query returned %d events, want 5", len(got))
	}
	assertNewestFirst(t, got, 4)
}

func TestSymlinkedLiveLogIsNotFollowed(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.jsonl")
	seed := `{"received_at":"2026-01-01T00:00:00Z","envelope":{"node_id":"n1","kind":"flag","version":"v1","payload":{"i":99}}}` + "\n"
	if err := os.WriteFile(outside, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "n1.jsonl")); err != nil {
		t.Fatal(err)
	}
	s := newStoreWithLog(newJSONLLog(dir, testLogMaxBytes, 3))

	if got := s.Query("n1", nil, 10); len(got) != 0 {
		t.Fatalf("query read %d events through the symlink", len(got))
	}
	env := Envelope{NodeID: "n1", Kind: "flag", Version: "v1", Payload: json.RawMessage(`{"i":1}`)}
	if err := s.Append(env); err == nil {
		t.Fatal("append through a symlinked log returned nil")
	}
	after, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != seed {
		t.Fatalf("outside file changed: %q", after)
	}
}

func TestEventsLimitParameterRule(t *testing.T) {
	c, srv := testCollector(t, map[string]string{"n1": "s3cret"})
	appendIndexed(t, c.store, 0, maxEventsLimit+5)

	cases := []struct {
		query string
		want  int
	}{
		{"", defaultEventsLimit},
		{"?limit=3", 3},
		{"?limit=1000000", maxEventsLimit},
		{"?limit=0", defaultEventsLimit},
		{"?limit=-7", defaultEventsLimit},
		{"?limit=abc", defaultEventsLimit},
		{"?limit=12abc", defaultEventsLimit},
	}
	for _, tc := range cases {
		resp, err := http.Get(srv.URL + "/nodes/n1/events" + tc.query)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var events []envelopeFile
		if err := json.Unmarshal(body, &events); err != nil {
			t.Fatalf("%q: %v", tc.query, err)
		}
		if resp.StatusCode != http.StatusOK || len(events) != tc.want {
			t.Fatalf("%q: status %d, %d events, want %d", tc.query, resp.StatusCode, len(events), tc.want)
		}
	}
}
