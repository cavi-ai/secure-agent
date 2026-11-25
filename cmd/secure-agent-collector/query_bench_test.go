package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkQuery measures a limit=100 query over a node log of about 100 MB
// written directly in the JSONL format the store uses.
func BenchmarkQuery(b *testing.B) {
	dir := b.TempDir()
	f, err := os.OpenFile(filepath.Join(dir, "n1.jsonl"), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		b.Fatal(err)
	}
	w := bufio.NewWriterSize(f, 1<<20)
	payload := json.RawMessage(`{"rule":"aws-key","summary":"Secret leaving in agent traffic","pad":"` + padding(400) + `"}`)
	var written int64
	for i := 0; written < 100<<20; i++ {
		kind := "flag"
		if i%2 == 1 {
			kind = "guard"
		}
		line, err := json.Marshal(envelopeFile{
			ReceivedAt: "2026-01-01T00:00:00Z",
			Envelope:   Envelope{NodeID: "n1", Kind: kind, Version: "v1", Payload: payload},
		})
		if err != nil {
			b.Fatal(err)
		}
		line = append(line, '\n')
		n, err := w.Write(line)
		if err != nil {
			b.Fatal(err)
		}
		written += int64(n)
	}
	if err := w.Flush(); err != nil {
		b.Fatal(err)
	}
	if err := f.Close(); err != nil {
		b.Fatal(err)
	}
	l := &jsonlLog{dir: dir}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := l.Query("n1", map[string]bool{"flag": true}, 100); len(got) != 100 {
			b.Fatalf("got %d events, want 100", len(got))
		}
	}
}

func padding(n int) string {
	p := make([]byte, n)
	for i := range p {
		p[i] = 'x'
	}
	return string(p)
}
