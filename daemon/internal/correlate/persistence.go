package correlate

// ResolvePersistence must be called for each returned flag before the next
// Observe. Rejected writes release that flag's suppression and consumed
// evidence; successful writes retain them. No observations are replayed and
// no retry queue is retained. Callers that do not persist flags can continue
// to use Observe without resolving them.
func (c *Correlator) ResolvePersistence(flagID string, persisted bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	undo := c.persistenceUndo[flagID]
	delete(c.persistenceUndo, flagID)
	if !persisted {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
	}
}

func (c *Correlator) recordPersistenceUndoLocked(id string, undo func()) {
	if c.persistenceUndo == nil {
		c.persistenceUndo = make(map[string][]func())
	}
	c.persistenceUndo[id] = append(c.persistenceUndo[id], undo)
}

func (c *Correlator) consumeFlagEvidenceLocked(id string, rootPID, directPID int32) {
	for _, pid := range []int32{rootPID, directPID} {
		if pid == 0 {
			continue
		}
		for i := range c.marks[pid] {
			if mark := &c.marks[pid][i]; !mark.consumed {
				c.recordPersistenceUndoLocked(id, func() { mark.consumed = false })
				mark.consumed = true
			}
		}
		for i := range c.conns[pid] {
			if conn := &c.conns[pid][i]; !conn.consumed {
				c.recordPersistenceUndoLocked(id, func() { conn.consumed = false })
				conn.consumed = true
			}
		}
	}
}
