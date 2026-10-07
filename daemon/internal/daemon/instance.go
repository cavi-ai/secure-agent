package daemon

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// instanceLockPoll is how often a waiting daemon retries the instance lock.
const instanceLockPoll = 250 * time.Millisecond

// ErrParentGone ends a lock wait whose owning parent exited.
var ErrParentGone = errors.New("owning parent exited")

// InstanceLock is one daemon's exclusive claim on a store. Two daemons on one
// store would ingest every source twice, race on its checkpoints, and the
// later one would unlink the earlier one's socket.
type InstanceLock struct {
	f *os.File
}

// LockInstance takes the exclusive lock beside dbPath. While another daemon
// holds it (an exiting instance during a restart, or a second daemon on the
// same store) it waits until the lock frees, ctx ends, or the owning parent
// exits. An empty dbPath (in-memory store) needs no lock.
func LockInstance(ctx context.Context, dbPath string) (*InstanceLock, error) {
	if dbPath == "" {
		return &InstanceLock{}, nil
	}
	path := dbPath + ".lock"
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("instance lock dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("instance lock: %w", err)
	}
	ppid := os.Getppid()
	tick := time.NewTicker(instanceLockPoll)
	defer tick.Stop()
	waiting := false
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			f.Close()
			return nil, fmt.Errorf("instance lock %s: %w", path, err)
		}
		if !waiting {
			waiting = true
			log.Printf("secure-agentd: daemon pid %s holds %s; waiting for it to exit", lockHolder(path), path)
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-tick.C:
		}
		if ppid != 1 && os.Getppid() != ppid {
			f.Close()
			return nil, ErrParentGone
		}
	}
	if waiting {
		log.Printf("secure-agentd: acquired %s", path)
	}
	if err := f.Truncate(0); err == nil {
		_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	}
	return &InstanceLock{f: f}, nil
}

// lockHolder reads the pid the holding daemon recorded, or "unknown".
func lockHolder(path string) string {
	data, err := os.ReadFile(path)
	if pid := strings.TrimSpace(string(data)); err == nil && pid != "" {
		return pid
	}
	return "unknown"
}

// Release frees the lock. The file stays: removing it would let a waiter lock
// an unlinked inode while a third daemon creates a fresh one.
func (l *InstanceLock) Release() {
	if l.f != nil {
		l.f.Close()
		l.f = nil
	}
}
