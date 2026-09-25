package collect

import (
	"os"
	"time"
)

// dbSettle is how old a database's newest modification must be before its
// fingerprint may stand for "unchanged": a filesystem with coarse timestamps
// can take a second write inside the same tick without moving the mtime, and
// a WAL that restarts after a checkpoint rewrites from its start without
// growing.
const dbSettle = 2 * time.Second

// dbFingerprint is a SQLite database's change signal: the size and
// modification time of the main file and of its -wal file, zero for a file
// that does not exist.
type dbFingerprint struct {
	size, walSize int64
	mod, walMod   time.Time
}

// fingerprintDB stats path and path-wal.
func fingerprintDB(path string) dbFingerprint {
	var fp dbFingerprint
	if fi, err := os.Stat(path); err == nil {
		fp.size, fp.mod = fi.Size(), fi.ModTime()
	}
	if fi, err := os.Stat(path + "-wal"); err == nil {
		fp.walSize, fp.walMod = fi.Size(), fi.ModTime()
	}
	return fp
}

func (fp dbFingerprint) equal(o dbFingerprint) bool {
	return fp.size == o.size && fp.walSize == o.walSize && fp.mod.Equal(o.mod) && fp.walMod.Equal(o.walMod)
}

// newest is the later of the two modification times.
func (fp dbFingerprint) newest() time.Time {
	if fp.walMod.After(fp.mod) {
		return fp.walMod
	}
	return fp.mod
}

// dbChange skips polls of a database that has not changed since the last
// poll that found nothing new in it. The poll calls begin first and done
// only when it read without error and found no rows past its watermark: a
// poll that failed, or that read rows (a backlog may remain past its row
// limit), does not call done, so the next poll runs.
type dbChange struct {
	last     dbFingerprint
	recorded bool
	now      func() time.Time // nil: time.Now
	// polls counts the polls begin let through; tests read it.
	polls int
}

// begin fingerprints path and reports whether the poll must run: always on
// the first poll, and whenever the fingerprint differs from the recorded one.
func (c *dbChange) begin(path string) (dbFingerprint, bool) {
	fp := fingerprintDB(path)
	if c.recorded && fp.equal(c.last) {
		return fp, false
	}
	c.polls++
	return fp, true
}

// done records fp, taken by begin before the poll read the database, as a
// state with nothing left to read. A fingerprint modified within dbSettle is
// not recorded, so a write its timestamps could not tell apart is still read.
func (c *dbChange) done(fp dbFingerprint) {
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	if now().Sub(fp.newest()) < dbSettle {
		c.recorded = false
		return
	}
	c.last, c.recorded = fp, true
}
