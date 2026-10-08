package correlate

import (
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// ownMark records a file an agent root's tree opened for writing.
type ownMark struct {
	at    time.Time
	path  string
	ino   uint64
	birth int64
}

// underCredentialOwner reports whether path is a credential_owners path or
// inside one.
func (c *Correlator) underCredentialOwner(path string) bool {
	for _, o := range c.cfg.CredentialOwners {
		if path == o.Path || strings.HasPrefix(path, o.Path+"/") {
			return true
		}
	}
	return false
}

// readsContents reports whether the event read a file's contents: not a
// directory open, not a write-only open, and not the owning program's own use
// of its credential.
func (c *Correlator) readsContents(e event.Event) bool {
	if e.Kind != event.KindFileOpen {
		return true
	}
	return !e.IsDirOpen() && e.OpensForRead() && !ownerProgramRead(c.cfg.CredentialOwners, e.Path, e.ExePath)
}

// Birth-to-open skew within which a write open counts as the file's creation.
const (
	createSkewBefore = time.Second
	createSkewAfter  = 5 * time.Second
)

// createdAtOpen reports whether the file was born at this open.
func createdAtOpen(e event.Event) bool {
	if e.FileBirth == 0 {
		return false
	}
	d := time.Duration(e.TS.UnixNano() - e.FileBirth)
	return d >= -createSkewBefore && d <= createSkewAfter
}

// rememberOwnLocked records a write open that created the file, under the same
// bound and expiry as read marks, and reports whether it did. A
// credential_owners path is never own data.
func (c *Correlator) rememberOwnLocked(rootPID int32, e event.Event) bool {
	if rootPID == 0 || e.FileIno == 0 || !createdAtOpen(e) || c.underCredentialOwner(e.Path) {
		return false
	}
	list := c.owned[rootPID]
	for i, m := range list {
		if m.path == e.Path {
			list = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(list) >= 50 {
		list = list[1:]
	}
	c.owned[rootPID] = append(list, ownMark{at: e.TS, path: e.Path, ino: e.FileIno, birth: e.FileBirth})
	return true
}

// isOwnDataLocked reports whether the open is of a file this root's tree
// wrote: same path, inode and birth time.
func (c *Correlator) isOwnDataLocked(rootPID int32, e event.Event) bool {
	if e.FileIno == 0 || c.underCredentialOwner(e.Path) {
		return false
	}
	for _, m := range c.owned[rootPID] {
		if m.path == e.Path && m.ino == e.FileIno && m.birth == e.FileBirth && e.TS.Sub(m.at) <= 10*time.Minute {
			return true
		}
	}
	return false
}

func (c *Correlator) evictOwnedLocked(now time.Time) {
	for pid, list := range c.owned {
		var valid []ownMark
		for _, m := range list {
			if now.Sub(m.at) <= 10*time.Minute {
				valid = append(valid, m)
			}
		}
		if len(valid) == 0 {
			delete(c.owned, pid)
		} else {
			c.owned[pid] = valid
		}
	}
}
