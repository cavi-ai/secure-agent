package correlate

import "os"

// policyCache holds a policy file's last decoded content keyed by the file's
// identity, size and modification time: the event path stats the file and
// reads and decodes it again only after it changed (an edit through the store
// replaces the file atomically). A failed load is kept until the file
// changes, so its warning is logged once per change, not once per event.
// Callers hold the owning store's lock and must not modify the value.
type policyCache[T any] struct {
	valid bool
	fi    os.FileInfo // nil: the file was missing
	val   T
	err   error
}

// get returns the policy and whether it was read now (not from the cache).
func (c *policyCache[T]) get(path string, read func() (T, error)) (T, bool, error) {
	fi, statErr := os.Stat(path)
	if statErr != nil && !os.IsNotExist(statErr) {
		c.valid = false
		v, err := read()
		return v, true, err
	}
	if statErr != nil {
		fi = nil
	}
	if c.valid && sameFileState(c.fi, fi) {
		return c.val, false, c.err
	}
	c.val, c.err = read()
	c.fi, c.valid = fi, true
	return c.val, true, c.err
}

func sameFileState(a, b os.FileInfo) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}
