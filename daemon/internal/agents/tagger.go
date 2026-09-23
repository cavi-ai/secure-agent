package agents

import (
	"strings"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

type ProcInfo struct {
	PID       int32
	PPID      int32
	Comm      string
	Exe       string
	CWD       string
	StartTime time.Time
	RSSBytes  uint64
	CPUTime   time.Duration
}

type AgentInfo struct {
	Name string
	// Kind is "agent" or "infra" (IDEs, local model servers) from the matched
	// AgentDef. Infra is tracked and killable but never counted as an agent.
	Kind       string
	ExePath    string
	CWD        string
	PID        int32
	PPID       int32
	Chain      []int32
	StartedAt  time.Time
	RSSBytes   uint64
	CPUTime    time.Duration
	CPUPercent float64
	RootPID    int32
	IsOrphan   bool
	sampledAt  time.Time
}

type ProcSource interface {
	List() []ProcInfo
	Info(pid int32) (ProcInfo, bool)
}

type Tagger struct {
	mu     sync.RWMutex
	cfg    config.Config
	ps     ProcSource
	table  map[int32]ProcInfo
	cache  map[int32]AgentInfo
	tagged map[int32]bool
	now    func() time.Time
}

func New(cfg config.Config, ps ProcSource) *Tagger {
	return &Tagger{
		cfg:    cfg,
		ps:     ps,
		table:  make(map[int32]ProcInfo),
		cache:  make(map[int32]AgentInfo),
		tagged: make(map[int32]bool),
		now:    time.Now,
	}
}

func (t *Tagger) isCandidateLocked(pid int32) bool {
	curr := pid
	visited := make(map[int32]bool)
	for hops := 0; hops < 32 && curr > 0; hops++ {
		if visited[curr] {
			break
		}
		visited[curr] = true
		pInfo, ok := t.table[curr]
		if !ok {
			break
		}
		targetStr := pInfo.Comm
		if pInfo.Exe != "" {
			targetStr = pInfo.Exe
		}
		if targetStr != "" {
			targetLower := strings.ToLower(targetStr)
			for _, agentDef := range t.cfg.Agents {
				for _, matchStr := range agentDef.Match {
					if strings.Contains(targetLower, strings.ToLower(matchStr)) {
						return true
					}
				}
			}
		}
		curr = pInfo.PPID
	}
	return false
}

func (t *Tagger) Refresh() {
	t.mu.Lock()
	defer t.mu.Unlock()
	sampledAt := t.now()

	procs := t.ps.List()
	newTable := make(map[int32]ProcInfo, len(procs))
	for _, p := range procs {
		newTable[p.PID] = p
	}
	t.table = newTable

	// Prune cache entries for dead pids. Beyond bounding growth on a
	// long-running daemon with heavy process churn, this is a correctness fix:
	// a recycled pid must never inherit the previous process's agent tag.
	for pid := range t.cache {
		if _, alive := newTable[pid]; !alive {
			delete(t.cache, pid)
			delete(t.tagged, pid)
		}
	}

	// Refresh volatile counters only for processes already attributed to an
	// agent. This keeps idle scans cheap while making the cached resource view
	// current for live sessions.
	for pid, previous := range t.cache {
		if !t.tagged[pid] {
			continue
		}
		fresh, ok := t.ps.Info(pid)
		if !ok {
			continue
		}
		fresh = mergeProcInfo(newTable[pid], fresh)
		if !previous.StartedAt.IsZero() && !fresh.StartTime.IsZero() && !previous.StartedAt.Equal(fresh.StartTime) {
			delete(t.cache, pid)
			delete(t.tagged, pid)
			continue
		}

		previous.PPID = fresh.PPID
		if fresh.Exe != "" {
			previous.ExePath = fresh.Exe
		} else if fresh.Comm != "" {
			previous.ExePath = fresh.Comm
		}
		if fresh.CWD != "" {
			previous.CWD = fresh.CWD
		}
		if !fresh.StartTime.IsZero() {
			previous.StartedAt = fresh.StartTime
		}
		if fresh.RSSBytes != 0 || previous.RSSBytes == 0 {
			previous.RSSBytes = fresh.RSSBytes
		}
		if fresh.CPUTime != 0 || previous.CPUTime == 0 {
			previous.CPUPercent = cpuPercent(previous.CPUTime, previous.sampledAt, fresh.CPUTime, sampledAt)
			previous.CPUTime = fresh.CPUTime
			previous.sampledAt = sampledAt
		}
		t.cache[pid] = previous
		t.table[pid] = fresh
	}

	// Pre-populate tagging for candidate process trees without discarding existing positively tagged agent cache
	for pid := range t.table {
		if t.isCandidateLocked(pid) {
			t.tagLocked(pid)
		}
	}
}

func (t *Tagger) Tag(pid int32) (AgentInfo, bool) {
	t.mu.RLock()
	info, ok := t.cache[pid]
	tagged := t.tagged[pid]
	t.mu.RUnlock()

	if ok && tagged {
		return info, true
	}
	if ok && !tagged {
		return AgentInfo{}, false
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	return t.tagLocked(pid)
}

// ParentPID returns pid's parent from the last process table, falling back to
// the process source for a pid the table does not hold. 0, false when the pid
// is unknown to both.
func (t *Tagger) ParentPID(pid int32) (int32, bool) {
	t.mu.RLock()
	p, ok := t.table[pid]
	t.mu.RUnlock()
	if ok {
		return p.PPID, true
	}
	if p, ok := t.ps.Info(pid); ok {
		return p.PPID, true
	}
	return 0, false
}

func (t *Tagger) tagLocked(pid int32) (AgentInfo, bool) {
	if info, ok := t.cache[pid]; ok {
		return info, t.tagged[pid]
	}

	chain := make([]int32, 0, 8)
	curr := pid
	visited := make(map[int32]bool)

	for hops := 0; hops < 32 && curr > 0; hops++ {
		if visited[curr] {
			break
		}
		visited[curr] = true
		chain = append(chain, curr)

		pInfo, ok := t.procLocked(curr)
		if !ok {
			break
		}

		if agentDef, matched := t.matchLocked(pInfo); matched {
			targetProc, _ := t.table[pid]
			exePath := targetProc.Exe
			if exePath == "" {
				exePath = targetProc.Comm
			}
			res := AgentInfo{
				Name: agentDef.Name,
				// Normalize here too: configs built in-process (tests)
				// skip the loader's normalization pass.
				Kind:      config.NormalizeAgentKind(agentDef.Kind),
				ExePath:   exePath,
				CWD:       targetProc.CWD,
				PID:       pid,
				PPID:      targetProc.PPID,
				Chain:     chain,
				StartedAt: targetProc.StartTime,
				RSSBytes:  targetProc.RSSBytes,
				CPUTime:   targetProc.CPUTime,
				RootPID:   t.familyRootLocked(curr, pInfo, agentDef.Name, visited, 32-hops-1),
				sampledAt: t.now(),
			}
			t.cache[pid] = res
			t.tagged[pid] = true
			return res, true
		}

		curr = pInfo.PPID
	}

	if targetProc, ok := t.table[pid]; ok && (targetProc.Exe != "" || targetProc.Comm != "") {
		t.tagged[pid] = false
		t.cache[pid] = AgentInfo{}
	}
	return AgentInfo{}, false
}

// procLocked reads pid from the process table, filling a missing entry or a
// missing exe from the process source.
func (t *Tagger) procLocked(pid int32) (ProcInfo, bool) {
	pInfo, ok := t.table[pid]
	if ok && pInfo.Exe != "" {
		return pInfo, true
	}
	if dynamicInfo, found := t.ps.Info(pid); found && dynamicInfo.Exe != "" {
		if ok {
			dynamicInfo = mergeProcInfo(pInfo, dynamicInfo)
		}
		t.table[pid] = dynamicInfo
		return dynamicInfo, true
	}
	return pInfo, ok
}

// matchLocked returns the first agent definition matching the process's exe
// (or comm when the exe is unknown).
func (t *Tagger) matchLocked(p ProcInfo) (config.AgentDef, bool) {
	matchTarget := p.Exe
	if matchTarget == "" {
		matchTarget = p.Comm
	}
	if matchTarget == "" {
		return config.AgentDef{}, false
	}
	matchTargetLower := strings.ToLower(matchTarget)
	for _, agentDef := range t.cfg.Agents {
		for _, matchStr := range agentDef.Match {
			if strings.Contains(matchTargetLower, strings.ToLower(matchStr)) {
				return agentDef, true
			}
		}
	}
	return config.AgentDef{}, false
}

// familyRootLocked walks up from the matched process while each parent
// matches the same agent definition and returns the highest such pid — the
// family root (a harness wrapper that execs its native binary is one family).
func (t *Tagger) familyRootLocked(matched int32, p ProcInfo, name string, visited map[int32]bool, budget int) int32 {
	root := matched
	for ; budget > 0; budget-- {
		ppid := p.PPID
		if ppid <= 0 || visited[ppid] {
			break
		}
		visited[ppid] = true
		parent, ok := t.procLocked(ppid)
		if !ok {
			break
		}
		if def, same := t.matchLocked(parent); !same || def.Name != name {
			break
		}
		root, p = ppid, parent
	}
	return root
}

// RefreshInterval is how long to wait between kern.proc.all walks.
// Idle (no tagged agents): 5s. Live sessions: 3s — spawn/exit still shows
// up on a glance, without a 1 Hz walk on the multi-harness machine.
func RefreshInterval(anyTagged bool) time.Duration {
	if anyTagged {
		return 3 * time.Second
	}
	return 5 * time.Second
}

func cpuPercent(previousCPU time.Duration, previousAt time.Time, currentCPU time.Duration, currentAt time.Time) float64 {
	if previousAt.IsZero() || !currentAt.After(previousAt) || currentCPU < previousCPU {
		return 0
	}
	return float64(currentCPU-previousCPU) / float64(currentAt.Sub(previousAt)) * 100
}

func (t *Tagger) Any() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, isTagged := range t.tagged {
		if isTagged {
			return true
		}
	}
	return false
}

func (t *Tagger) TaggedPIDs() map[int32]AgentInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()
	res := make(map[int32]AgentInfo)
	for pid, info := range t.cache {
		if !t.tagged[pid] {
			continue
		}
		info.RootPID = rootPIDLocked(t.cache, t.tagged, info)
		_, parentAlive := t.table[info.PPID]
		info.IsOrphan = info.PPID > 1 && !parentAlive
		res[pid] = info
	}
	return res
}

// mergeProcInfo keeps List()-cheap fields (start time, ppid) when Info()
// only fills the lazy ones (exe, rss, cumulative CPU).
func mergeProcInfo(listed, info ProcInfo) ProcInfo {
	if info.PPID == 0 {
		info.PPID = listed.PPID
	}
	if info.StartTime.IsZero() {
		info.StartTime = listed.StartTime
	}
	if info.RSSBytes == 0 {
		info.RSSBytes = listed.RSSBytes
	}
	if info.CPUTime == 0 {
		info.CPUTime = listed.CPUTime
	}
	if info.CWD == "" {
		info.CWD = listed.CWD
	}
	if info.Comm == "" {
		info.Comm = listed.Comm
	}
	return info
}

// rootPIDLocked walks up same-family tagged parents. The instance root is
// the highest ancestor still tagged with the same agent name.
func rootPIDLocked(cache map[int32]AgentInfo, tagged map[int32]bool, info AgentInfo) int32 {
	cur := info
	seen := map[int32]bool{}
	for hops := 0; hops < 32; hops++ {
		if seen[cur.PID] {
			return cur.PID
		}
		seen[cur.PID] = true
		parent, ok := cache[cur.PPID]
		if !ok || !tagged[cur.PPID] || parent.Name != cur.Name {
			return cur.PID
		}
		cur = parent
	}
	return cur.PID
}
