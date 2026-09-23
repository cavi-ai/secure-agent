package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// chunkReader returns one chunk per Read call, then io.EOF.
type chunkReader struct {
	chunks []string
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[0])
	r.chunks = r.chunks[1:]
	return n, nil
}

func TestPumpToSpoolWritesEachRecordIntact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spool.jsonl")
	r := &chunkReader{chunks: []string{`{"a":1}` + "\n" + `{"b":2}` + "\n" + `{"c":`, "3}\n"}}

	if err := pumpToSpoolAt(r, path); err != nil {
		t.Fatalf("pumpToSpoolAt: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read spool: %v", err)
	}
	want := `{"a":1}` + "\n" + `{"b":2}` + "\n" + `{"c":3}` + "\n"
	if string(got) != want {
		t.Fatalf("spool = %q, want %q", got, want)
	}
	for i, line := range bytes.Split(bytes.TrimSuffix(got, []byte("\n")), []byte("\n")) {
		var v map[string]any
		if err := json.Unmarshal(line, &v); err != nil {
			t.Fatalf("line %d %q is not a JSON object: %v", i, line, err)
		}
	}
}
