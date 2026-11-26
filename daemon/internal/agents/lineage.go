package agents

import (
	"cmp"
	"slices"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

// Lineage is a fork or exec observation from Endpoint Security. A zero start
// time was not in the record.
type Lineage struct {
	ParentPID   int32
	ParentStart time.Time
	ParentExe   string
	ChildPID    int32
	ChildStart  time.Time
	ExecPath    string
	At          time.Time
	// OriginalParent means ParentPID names the child's parent at birth.
	OriginalParent bool
}

// lineageRetention is how long an exited process's record still names the
// family of children whose fork or exec records are read after it exited.
const lineageRetention = 2 * time.Minute

// lineageCap bounds the lineage records; at the cap, exited records are
// dropped first, then ones the process table does not list, then listed ones.
const lineageCap = 8192

// lineageRecord is the agent family a process joined when its family member
// parent forked it or it exec'd.
type lineageRecord struct {
	name      string
	kind      string
	rootPID   int32
	rootStart time.Time
	// Once the root PID has been reused, it cannot name this family again.
	rootReused bool
	// exact marks a verified fork or direct executable match for this process.
	exact bool
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

// NoteLineage records a child's family from the parent or from a matching
// executable the kernel observed, even before the first process refresh.
func (t *Tagger) NoteLineage(l Lineage) {
	if l.ChildPID <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	prior, held := t.lineage[l.ChildPID]
	if held && !l.ChildStart.IsZero() && prior.start.After(l.ChildStart) && !sameStart(prior.start, l.ChildStart) {
		return // A replay for an older occupant must not replace the child's record.
	}
	var fam lineageRecord
	parentAt := l.At
	if l.OriginalParent {
		parentAt = l.ChildStart
	}
	if l.ParentPID > 0 && l.ParentPID != l.ChildPID && !parentAt.IsZero() {
		fam = t.familyOfLocked(l.ParentPID, l.ParentStart, parentAt)
		if observed, ok := t.observedFamilyLocked(l.ParentPID, l.ParentStart, l.ParentExe); ok && observed.name != fam.name {
			fam = observed
		}
	}

	executed, matched := t.observedFamilyLocked(l.ChildPID, l.ChildStart, l.ExecPath)
	if held && prior.exact && (l.ChildStart.IsZero() || prior.of(l.ChildStart)) &&
		l.ParentStart.IsZero() && (!matched || executed.name == prior.name) {
		return // An inferred exec parent cannot replace a verified family.
	}
	fam.exact = !l.ParentStart.IsZero() && !l.ChildStart.IsZero()
	if matched && executed.name != fam.name {
		fam = executed
		fam.exact = true
	}
	if fam.rootPID <= 0 {
		return
	}
	if fam.rootPID == prior.rootPID && sameStart(fam.rootStart, prior.rootStart) {
		fam.rootReused = fam.rootReused || prior.rootReused
	}
	fam.rootReused = fam.rootReused || t.rootReusedLocked(fam.rootPID, fam.rootStart)
	fam.start, fam.at, fam.gone = l.ChildStart, l.At, time.Time{}
	if !held {
		t.makeRoomLocked()
	}
	t.lineage[l.ChildPID] = fam
	t.noteAgentStartLocked(fam.name, fam.kind, fam.rootStart)
	if info, cached := t.cache[l.ChildPID]; cached && (!t.tagged[l.ChildPID] ||
		(fam.of(info.StartedAt) && (info.fromLineage || (matched && info.Name != fam.name)))) {
		delete(t.cache, l.ChildPID)
		delete(t.tagged, l.ChildPID)
	}
}

// observedFamilyLocked recognizes the executable of a known process
// generation. Node programs also need the entry point from that process.
func (t *Tagger) observedFamilyLocked(pid int32, start time.Time, exe string) (lineageRecord, bool) {
	if start.IsZero() || exe == "" {
		return lineageRecord{}, false
	}
	p := ProcInfo{Exe: exe}
	if nodeExecutable(exe) && slices.ContainsFunc(t.cfg.Agents, func(d config.AgentDef) bool { return d.Name == "openclaw" }) {
		if live, ok := t.ps.Info(pid); ok && sameStart(live.StartTime, start) && live.Exe == exe {
			p.RuntimeProgram, p.Comm = live.RuntimeProgram, live.Comm
		}
	}
	def, ok := t.matchLocked(p)
	return lineageRecord{name: def.Name, kind: config.NormalizeAgentKind(def.Kind), rootPID: pid, rootStart: start}, ok
}

// familyOfLocked looks up the parent at the observation time. A matching
// record carries the original root identity even after the root exits.
func (t *Tagger) familyOfLocked(pid int32, start, at time.Time) lineageRecord {
	if start.IsZero() {
		p := t.table[pid]
		if !p.StartTime.IsZero() && !p.StartTime.After(at) {
			start = p.StartTime
		}
	}
	if r, ok := t.lineage[pid]; ok && !t.expiredLocked(r) {
		if !start.IsZero() {
			if r.of(start) {
				return r
			}
		} else {
			s := r.start
			if s.IsZero() {
				s = r.at
			}
			if !s.IsZero() && !s.After(at) && (r.gone.IsZero() || !r.gone.Before(at)) {
				return r
			}
		}
	}
	if info, ok := t.cache[pid]; ok && t.tagged[pid] {
		s := info.StartedAt
		if !s.IsZero() && (sameStart(s, start) || (start.IsZero() && !s.After(at))) {
			return lineageRecord{name: info.Name, kind: info.Kind, rootPID: info.RootPID, rootStart: info.rootStart, rootReused: info.rootReused}
		}
	}
	return lineageRecord{}
}

// makeRoomLocked keeps the records under lineageCap. It drops expired records,
// then exited ones, then ones the table does not list as that process, then
// listed ones; within each, oldest record first, then lowest pid.
func (t *Tagger) makeRoomLocked() {
	if len(t.lineage) < lineageCap {
		return
	}
	type ranked struct {
		class int
		at    time.Time
		pid   int32
	}
	var order []ranked
	for pid, r := range t.lineage {
		switch {
		case t.expiredLocked(r):
			delete(t.lineage, pid)
		case !r.gone.IsZero():
			order = append(order, ranked{0, r.at, pid})
		case !r.of(t.table[pid].StartTime):
			order = append(order, ranked{1, r.at, pid})
		default:
			order = append(order, ranked{2, r.at, pid})
		}
	}
	slices.SortFunc(order, func(a, b ranked) int {
		return cmp.Or(cmp.Compare(a.class, b.class), a.at.Compare(b.at), cmp.Compare(a.pid, b.pid))
	})
	// Dropping an eighth at once keeps the scan to one per lineageCap/8 records.
	excess := len(t.lineage) - lineageCap*7/8
	for _, r := range order[:min(max(excess, 0), len(order))] {
		delete(t.lineage, r.pid)
	}
}

// pruneLineageLocked marks the records of processes the table no longer
// lists as exited and drops them after lineageRetention. Callers hold t.mu.
func (t *Tagger) pruneLineageLocked(at time.Time) {
	for pid, r := range t.lineage {
		previous := r
		r.rootReused = r.rootReused || t.rootReusedLocked(r.rootPID, r.rootStart)
		switch {
		case r.of(t.table[pid].StartTime):
			r.gone = time.Time{}
		case r.gone.IsZero():
			r.gone = at
		case at.Sub(r.gone) > lineageRetention:
			delete(t.lineage, pid)
			continue
		}
		if r != previous {
			t.lineage[pid] = r
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
	chain := []int32{pid}
	if r.rootPID != pid {
		chain = append(chain, r.rootPID)
	}
	return AgentInfo{
		Name:        r.name,
		Kind:        r.kind,
		ExePath:     exe,
		CWD:         self.CWD,
		PID:         pid,
		PPID:        self.PPID,
		Chain:       chain,
		StartedAt:   self.StartTime,
		RSSBytes:    self.RSSBytes,
		CPUTime:     self.CPUTime,
		RootPID:     r.rootPID,
		rootStart:   r.rootStart,
		rootReused:  r.rootReused,
		fromLineage: true,
		sampledAt:   t.now(),
	}, true
}

func (t *Tagger) rootReusedLocked(pid int32, start time.Time) bool {
	if start.IsZero() {
		return false
	}
	p := t.table[pid]
	// The last sample can predate the record. Only a later occupant proves reuse.
	return p.StartTime.After(start) && !sameStart(p.StartTime, start)
}

// rootedInfoLocked presents a safe root to callers without replacing the
// cached identity that later lineage records need to inherit.
func (t *Tagger) rootedInfoLocked(info AgentInfo) AgentInfo {
	info.rootReused = info.rootReused || t.rootReusedLocked(info.RootPID, info.rootStart)
	if info.rootReused {
		info.RootPID, info.rootStart, info.Chain = info.PID, info.StartedAt, []int32{info.PID}
	}
	return info
}
