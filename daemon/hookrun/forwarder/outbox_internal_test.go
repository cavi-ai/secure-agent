package forwarder

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

type unavailableDurableSender struct{}

func (unavailableDurableSender) Send(context.Context, []byte) error { return errors.New("unavailable") }
func (unavailableDurableSender) SendDurable(context.Context, []byte) error {
	return errors.New("unavailable")
}

func TestOutboxReplacementConnectionsRetainDurabilityAndBudget(t *testing.T) {
	c, err := New(Config{Harness: "hermes", Sender: unavailableDurableSender{}, OutboxDir: filepath.Join(t.TempDir(), "box"), OutboxMaxBytes: 65536})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// database/sql replaces interrupted SQLite connections. Force replacement
	// on each checkout rather than relying on a cancellation timing race.
	c.outbox.db.SetMaxIdleConns(0)
	for i := 0; i < 2; i++ {
		conn, err := c.outbox.db.Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, test := range []struct {
			pragma string
			want   int
		}{{"max_page_count", 16}, {"synchronous", 2}, {"fullfsync", 1}, {"trusted_schema", 0}, {"journal_size_limit", 0}} {
			var got int
			if err := conn.QueryRowContext(context.Background(), "PRAGMA "+test.pragma).Scan(&got); err != nil {
				conn.Close()
				t.Fatal(err)
			}
			if got != test.want {
				conn.Close()
				t.Fatalf("replacement connection lost %s: got %d want %d", test.pragma, got, test.want)
			}
		}
		conn.Close()
	}
}
