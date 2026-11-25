package agents

import (
	"slices"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

// Lineage is one parent-child pair the kernel reported at At: a fork, or the
// parent of a process that exec'd. A zero start time was not in the record.
type Lineage struct {
	ParentPID   int32
	ParentStart time.Time
	ChildPID    int32
	ChildStart  time.Time
	At          time.Time
}

// lineageRetention is how long an exited process's record still names the
// family of children whose fork or exec records are read after it exited.
const lineageRetention = 2 * time.Minute

// lineageCap bounds the lineage records; at the cap, exited records are
// dropped oldest first, then live ones.
const lineageCap = 8192

// lineageRecord is the agent family a process joined when its family member
// parent forked it or it exec'd.
type lineageRecord struct {
	name      string
	kind      string
	rootPID   int32
	rootStart time.Time
	// start is the process's start time, zero when the record lacked it; at
	// is the record's time.
	start time.Time
	at    time.Time
	// gone is when a refresh first found the pid absent or held by another
	// process; zero while the process is listed.
	gone time.Time
}

// of reports whether the record is that of the process started at start.
// Start times are compared at microseconds, the precision of both the process
// table and Endpoint Security; a record without one is that of a process
// started no later than the record.
func (r lineageRecord) of(start time.Time) bool {
	switch {
	case start.IsZero():
		return false
	case !r.start.IsZero():
		return sameStart(r.start, start)
	default:
		return !start.After(r.at)
	}
}

func sameStart(a, b time.Time) bool {
	return a.Truncate(time.Microsecond).Equal(b.Truncate(time.Microsecond))
}

func (t *Tagger) expiredLocked(r lineageRecord) bool {
	return !r.gone.IsZero() && t.now().Sub(r.gone) > lineageRetention
}

// NoteLineage records that l.ChildPID joined its parent's agent family: the
// parent is tagged, or holds a record that is still that process's. A parent
// in no family stores nothing and reads no process source.
func (t *Tagger) NoteLineage(l Lineage) {
	if l.ParentPID <= 0 || l.ChildPID <= 0 || l.ParentPID == l.ChildPID {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	fam, ok := t.familyOfLocked(l.ParentPID, l.ParentStart, l.At)
	if !ok {
		return
	}
	fam.start, fam.at, fam.gone = l.ChildStart, l.At, time.Time{}
	if _, held := t.lineage[l.ChildPID]; !held {
		t.makeRoomLocked()
	}
	t.lineage[l.ChildPID] = fam
	if _, cached := t.cache[l.ChildPID]; cached && !t.tagged[l.ChildPID] {
		delete(t.cache, l.ChildPID)
		delete(t.tagged, l.ChildPID)
	}
}

// familyOfLocked returns the family of the process that held pid at time
// at, started at start when that is known: its tag, else its record.
func (t *Tagger) familyOfLocked(pid int32, start, at time.Time) (lineageRecord, bool) {
	if info, ok := t.cache[pid]; ok && t.tagged[pid] {
		s := info.StartedAt
		if s.IsZero() || (start.IsZero() && !s.After(at)) || (!start.IsZero() && sameStart(s, start)) {
			root := info.RootPID
			if root <= 0 {
				root = pid
			}
			return lineageRecord{name: info.Name, kind: info.Kind, rootPID: root, rootStart: t.startOfLocked(root, pid, s)}, true
		}
	}
	r, ok := t.lineage[pid]
	if !ok || t.expiredLocked(r) {
		return lineageRecord{}, false
	}
	if !start.IsZero() {
		return r, r.of(start)
	}
	// Named by pid alone: the process listed under it if that one had started
	// by then, else the record's process if it had started and not exited.
	if p, listed := t.table[pid]; listed && !p.StartTime.IsZero() && !p.StartTime.After(at) {
		return r, r.of(p.StartTime)
	}
	return r, (r.start.IsZero() || !r.start.After(at)) && (r.gone.IsZero() || !r.gone.Before(at))
}

// startOfLocked is the start time of root, a tagged process's family root.
func (t *Tagger) startOfLocked(root, pid int32, pidStart time.Time) time.Time {
	if root == pid {
		return pidStart
	}
	if info, ok := t.cache[root]; ok && t.tagged[root] {
		return info.StartedAt
	}
	return t.table[root].StartTime
}

// makeRoomLocked keeps the records under lineageCap: expired records go
// first, then exited ones oldest first, then live ones oldest first.
func (t *Tagger) makeRoomLocked() {
	if len(t.lineage) < lineageCap {
		return
	}
	type aged struct {
		pid int32
		at  time.Time
	}
	var exited, live []aged
	for pid, r := range t.lineage {
		switch {
		case t.expiredLocked(r):
			delete(t.lineage, pid)
		case !r.gone.IsZero():
			exited = append(exited, aged{pid, r.at})
		default:
			live = append(live, aged{pid, r.at})
		}
	}
	// Dropping an eighth at once keeps the scan to one per lineageCap/8 records.
	excess := len(t.lineage) - lineageCap*7/8
	byAge := func(a, b aged) int { return a.at.Compare(b.at) }
	slices.SortFunc(exited, byAge)
	slices.SortFunc(live, byAge)
	for _, a := range append(exited, live...) {
		if excess <= 0 {
			return
		}
		delete(t.lineage, a.pid)
		excess--
	}
}

// pruneLineageLocked marks the records of processes the table no longer
// lists as exited and drops them after lineageRetention. Callers hold t.mu.
func (t *Tagger) pruneLineageLocked(at time.Time) {
	for pid, r := range t.lineage {
		if p, ok := t.table[pid]; ok && r.of(p.StartTime) {
			if !r.gone.IsZero() {
				r.gone = time.Time{}
				t.lineage[pid] = r
			}
			continue
		}
		switch {
		case r.gone.IsZero():
			r.gone = at
			t.lineage[pid] = r
		case at.Sub(r.gone) > lineageRetention:
			delete(t.lineage, pid)
		}
	}
}

// retainLineageLocked keeps the records of families still defined, with
// each definition's current kind.
func (t *Tagger) retainLineageLocked(defs []config.AgentDef) {
	for pid, r := range t.lineage {
		i := slices.IndexFunc(defs, func(d config.AgentDef) bool { return d.Name == r.name })
		if i < 0 {
			delete(t.lineage, pid)
			continue
		}
		r.kind = config.NormalizeAgentKind(defs[i].Kind)
		t.lineage[pid] = r
	}
}

// lineageTagLocked tags self, the live process holding pid, with the family
// its own record names.
func (t *Tagger) lineageTagLocked(pid int32, self ProcInfo) (AgentInfo, bool) {
	r, ok := t.lineage[pid]
	if !ok || !r.of(self.StartTime) {
		return AgentInfo{}, false
	}
	exe := self.Exe
	if exe == "" {
		exe = self.Comm
	}
	return AgentInfo{
		Name:      r.name,
		Kind:      r.kind,
		ExePath:   exe,
		CWD:       self.CWD,
		PID:       pid,
		PPID:      self.PPID,
		Chain:     []int32{pid, r.rootPID},
		StartedAt: self.StartTime,
		RSSBytes:  self.RSSBytes,
		CPUTime:   self.CPUTime,
		RootPID:   r.rootPID,
		sampledAt: t.now(),
	}, true
}
