package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
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
	s := openTestStoreWithLog(t, newJSONLLog(dir, testLogMaxBytes, 1000))
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
	s := openTestStoreWithLog(t, newJSONLLog(dir, testLogMaxBytes, 2))
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
	s1 := openTestStoreWithLog(t, newJSONLLog(dir, testLogMaxBytes, 3))
	appendIndexed(t, s1, 0, 100)
	before := queriedIndexes(t, s1, 1000)

	s2 := openTestStoreWithLog(t, newJSONLLog(dir, testLogMaxBytes, 3))
	after := queriedIndexes(t, s2, 1000)
	if fmt.Sprint(before) != fmt.Sprint(after) {
		t.Fatalf("query after restart differs:\nbefore %v\nafter  %v", before, after)
	}
	r := s2.Rollup()
	if len(r) != 1 || r[0].Flags != 100 {
		t.Fatalf("replayed flags = %+v, want 100", r)
	}
}

func TestRestartAfterRenameWithoutLiveFile(t *testing.T) {
	dir := t.TempDir()
	s1 := openTestStoreWithLog(t, newJSONLLog(dir, testLogMaxBytes, 3))
	appendIndexed(t, s1, 0, 5)
	if err := os.Rename(filepath.Join(dir, "n1.jsonl"), filepath.Join(dir, "n1.000001.jsonl")); err != nil {
		t.Fatal(err)
	}

	s2 := openTestStoreWithLog(t, newJSONLLog(dir, testLogMaxBytes, 3))
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
	s := openTestStoreWithLog(t, newJSONLLog(dir, testLogMaxBytes, 1000))
	appendIndexed(t, s, 0, 60)
	got := queriedIndexes(t, s, 45)
	if len(got) != 45 {
		t.Fatalf("query returned %d events, want 45", len(got))
	}
	assertNewestFirst(t, got, 59)
}

func TestQueryReadsLinesLargerThanReadBlock(t *testing.T) {
	dir := t.TempDir()
	s := openTestStoreWithLog(t, newJSONLLog(dir, 0, 0))
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
	s := openTestStoreWithLog(t, newJSONLLog(dir, testLogMaxBytes, 3))

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

func TestPruningPreservesFleetStateAndRedeliveryAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	open := func() *Store { return openTestStoreWithLog(t, newJSONLLog(dir, 512, 0)) }

	s := open()
	flag := seqEnv("n1", "boot", 1)
	flag.Payload = json.RawMessage(`{"rule":"keep-me","severity":3}`)
	mustAppend(t, s, flag)
	mustAppend(t, s, Envelope{NodeID: "n1", Boot: "boot", Seq: 3, Kind: "session",
		Payload: json.RawMessage(`{"id":"session","status":"active"}`)})
	for i := 0; i < 5; i++ {
		mustAppend(t, s, Envelope{NodeID: "n1", Kind: "trace",
			Payload: json.RawMessage(fmt.Sprintf(`{"session_id":"session","tool":"tool-%d","pad":"%s"}`, i, strings.Repeat("x", 280)))})
	}
	if retained := s.Query("n1", nil, 0); len(retained) != 1 || retained[0].Envelope.Kind != "trace" {
		t.Fatalf("history still contains pruned records: %d retained", len(retained))
	}
	wantNodes, wantRules, wantSessions := s.Rollup(), s.RuleAggregates(), s.Sessions()
	wantTrace := s.nodes["n1"].lastTrace["session"]

	s = open()
	if got := s.RuleAggregates(); !reflect.DeepEqual(got, wantRules) {
		t.Fatalf("rules after restart = %+v, want %+v", got, wantRules)
	}
	if got := s.Sessions(); !reflect.DeepEqual(got, wantSessions) {
		t.Fatalf("sessions after restart = %+v, want %+v", got, wantSessions)
	}
	if got := s.nodes["n1"].lastTrace["session"]; got != wantTrace {
		t.Fatalf("trace after restart = %+v, want %+v", got, wantTrace)
	}
	mustAppend(t, s, flag)
	if got := s.Rollup(); !reflect.DeepEqual(got, wantNodes) {
		t.Fatalf("rollup changed after restart and duplicate retry: got %+v, want %+v", got[0], wantNodes[0])
	}
	// Another rotation with no retained archives must advance the checkpoint.
	mustAppend(t, s, Envelope{NodeID: "n1", Kind: "flag",
		Payload: json.RawMessage(`{"rule":"new-rule"}`)})
	if got := open().Rollup()[0].Flags; got != 2 {
		t.Fatalf("lifetime flags after second restart = %d, want 2", got)
	}
}

func TestRotationAbortsWhenArchiveListingFails(t *testing.T) {
	dir := t.TempDir()
	l := newJSONLLog(dir, 1, 2)
	for _, file := range []string{liveName("n1"), rotatedName("n1", 1)} {
		if err := os.WriteFile(filepath.Join(dir, file), []byte(file), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Chmod(dir, 0o300); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Error(err)
		}
	}()
	if _, err := fs.ReadDir(root.FS(), "."); err == nil {
		t.Skip("directory listing restrictions do not apply to this process")
	}
	if err := l.rotateIfNeeded(root, "n1", 1); err == nil {
		t.Error("rotation accepted an unreadable archive listing")
	}
	for _, file := range []string{liveName("n1"), rotatedName("n1", 1)} {
		b, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil || string(b) != file {
			t.Errorf("%s changed during failed rotation: %q, %v", file, b, err)
		}
	}
}

func TestOversizeLegacyRecordDoesNotHideAdjacentRecords(t *testing.T) {
	dir := t.TempDir()
	var log bytes.Buffer
	writtenAt := time.Now().UTC().Format(time.RFC3339Nano)
	for i, pad := range []string{"", strings.Repeat("x", maxLogLine), ""} {
		record := envelopeFile{ReceivedAt: writtenAt, Envelope: Envelope{NodeID: "n1", Kind: "flag",
			Payload: json.RawMessage(fmt.Sprintf(`{"i":%d,"pad":"%s"}`, i, pad))}}
		if err := json.NewEncoder(&log).Encode(record); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, liveName("n1")), log.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	s := openTestStore(t, dir)
	if got := queriedIndexes(t, s, 10); !reflect.DeepEqual(got, []int{2, 0}) {
		t.Errorf("queried indexes = %v, want [2 0]", got)
	}
	if got := s.Rollup()[0].Flags; got != 2 {
		t.Errorf("replayed flags = %d, want 2", got)
	}
}

func TestMaxSizeWebhookRemainsReadableAfterRestart(t *testing.T) {
	c, srv := testCollector(t, map[string]string{"n1": "s"})
	const bodyLimit = 2 << 20
	prefix := `{"node_id":"n1","kind":"flag","payload":{"pad":"`
	suffix := `"}}`
	body := []byte(prefix + strings.Repeat("<", bodyLimit-len(prefix)-len(suffix)) + suffix)
	resp := post(t, srv, "s", body, "n1")
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("webhook status = %d, want 200", resp.StatusCode)
	}
	assertDeliveryCount(t, openTestStore(t, c.cfg.StoreDir), 1)
}

func TestQuerySnapshotSurvivesAppendAndPrune(t *testing.T) {
	dir := t.TempDir()
	l := newJSONLLog(dir, testLogMaxBytes, 0)
	s := openTestStoreWithLog(t, l)
	appendIndexed(t, s, 0, 1)
	segments := l.querySegments("n1")
	if len(segments) != 1 {
		t.Fatalf("snapshot opened %d segments, want 1", len(segments))
	}
	segment := segments[0]
	defer segment.file.Close()
	if !l.mu.TryLock() {
		t.Fatal("query snapshot holds the write lock path while reading")
	}
	l.mu.Unlock()

	// Append to the same inode, then rotate and unlink it.
	appendIndexed(t, s, 1, 2)
	st, err := segment.file.Stat()
	if err != nil || st.Size() <= segment.size {
		t.Fatalf("append did not extend the open file: %v, %v", st, err)
	}
	appendIndexed(t, s, 2, 60)
	if n := len(rotatedFiles(t, dir)); n != 0 {
		t.Fatalf("rotation left %d archives with zero retention", n)
	}
	var got []int
	scanLinesReverse(segment.file, segment.size, func(line []byte) bool {
		var rec envelopeFile
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatal(err)
		}
		var payload struct{ I int }
		if err := json.Unmarshal(rec.Envelope.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		got = append(got, payload.I)
		return false
	})
	if !reflect.DeepEqual(got, []int{0}) {
		t.Fatalf("snapshot returned indexes %v, want [0]", got)
	}
}

func TestFailedCheckpointLeavesArchiveForReplayAndRetry(t *testing.T) {
	dir := t.TempDir()
	open := func() *Store { return openTestStoreWithLog(t, newJSONLLog(dir, 1, 0)) }
	s := open()
	appendIndexed(t, s, 0, 1)
	checkpoint := filepath.Join(dir, "n1"+checkpointSuffix)
	if err := os.Mkdir(checkpoint, 0o700); err != nil {
		t.Fatal(err)
	}
	env := Envelope{NodeID: "n1", Kind: "flag", Payload: json.RawMessage(`{"i":1}`)}
	if err := s.Append(env); err == nil {
		t.Fatal("append succeeded despite a failed checkpoint")
	}
	if n := len(rotatedFiles(t, dir)); n != 1 {
		t.Fatalf("checkpoint failure left %d archives, want 1", n)
	}
	if err := os.Remove(checkpoint); err != nil {
		t.Fatal(err)
	}
	s = open()
	mustAppend(t, s, env)
	if n := len(rotatedFiles(t, dir)); n != 0 {
		t.Fatalf("retry left %d archives, want 0", n)
	}
	if got := open().Rollup()[0].Flags; got != 2 {
		t.Fatalf("rollup after retry and restart = %d flags, want 2", got)
	}
}

func TestStoreStartupRejectsUnreadableRegularLog(t *testing.T) {
	dir := t.TempDir()
	appendIndexed(t, openTestStore(t, dir), 0, 1)
	path := filepath.Join(dir, liveName("n1"))
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	if f, err := os.Open(path); err == nil {
		f.Close()
		t.Skip("file read restrictions do not apply to this process")
	}
	if _, err := NewStore(dir); err == nil {
		t.Fatal("opened an incomplete rollup that could be checkpointed")
	}
}
