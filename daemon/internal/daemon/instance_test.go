package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLockInstanceExcludesASecondDaemon(t *testing.T) {
	db := filepath.Join(t.TempDir(), "state", "events.db")
	first, err := LockInstance(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(db + ".lock")
	if err != nil || strings.TrimSpace(string(data)) != strconv.Itoa(os.Getpid()) {
		t.Fatalf("lock file = %q, %v; want this pid", data, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*instanceLockPoll)
	defer cancel()
	if second, err := LockInstance(ctx, db); !errors.Is(err, context.DeadlineExceeded) {
		if second != nil {
			second.Release()
		}
		t.Fatalf("second lock while held: err = %v; want deadline exceeded", err)
	}

	first.Release()
	second, err := LockInstance(context.Background(), db)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	second.Release()
}

func TestLockInstanceWaitsForTheHolderToExit(t *testing.T) {
	db := filepath.Join(t.TempDir(), "events.db")
	first, err := LockInstance(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	released := make(chan struct{})
	go func() {
		time.Sleep(2 * instanceLockPoll)
		first.Release()
		close(released)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	second, err := LockInstance(ctx, db)
	if err != nil {
		t.Fatalf("waiting lock: %v", err)
	}
	defer second.Release()
	select {
	case <-released:
	default:
		t.Fatal("second lock acquired while the first was held")
	}
}

func TestLockInstanceInMemoryStoreNeedsNoLock(t *testing.T) {
	l, err := LockInstance(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	l.Release()
}
