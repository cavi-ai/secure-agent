package agents

import (
	"strings"
	"sync"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

type ProcInfo struct {
	PID  int32
	PPID int32
	Comm string
	Exe  string
	CWD  string
}

type AgentInfo struct {
	Name    string
	ExePath string
	CWD     string
	PID     int32
	PPID    int32
	Chain   []int32
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
}

func New(cfg config.Config, ps ProcSource) *Tagger {
	return &Tagger{
		cfg:    cfg,
		ps:     ps,
		table:  make(map[int32]ProcInfo),
		cache:  make(map[int32]AgentInfo),
		tagged: make(map[int32]bool),
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

	procs := t.ps.List()
	newTable := make(map[int32]ProcInfo, len(procs))
	for _, p := range procs {
		newTable[p.PID] = p
	}
	t.table = newTable

	// Invalidate cache
	t.cache = make(map[int32]AgentInfo)
	t.tagged = make(map[int32]bool)

	// Pre-populate tagging ONLY for candidate process trees
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

		pInfo, ok := t.table[curr]
		if !ok || pInfo.Exe == "" {
			if dynamicInfo, found := t.ps.Info(curr); found && dynamicInfo.Exe != "" {
				if ok && dynamicInfo.PPID == 0 {
					dynamicInfo.PPID = pInfo.PPID
				}
				pInfo = dynamicInfo
				t.table[curr] = pInfo
			} else if !ok {
				break
			}
		}

		matchTarget := pInfo.Exe
		if matchTarget == "" {
			matchTarget = pInfo.Comm
		}
		if matchTarget != "" {
			matchTargetLower := strings.ToLower(matchTarget)
			for _, agentDef := range t.cfg.Agents {
				for _, matchStr := range agentDef.Match {
					if strings.Contains(matchTargetLower, strings.ToLower(matchStr)) {
						targetProc, _ := t.table[pid]
						exePath := targetProc.Exe
						if exePath == "" {
							exePath = targetProc.Comm
						}
						res := AgentInfo{
							Name:    agentDef.Name,
							ExePath: exePath,
							CWD:     targetProc.CWD,
							PID:     pid,
							PPID:    targetProc.PPID,
							Chain:   chain,
						}
						t.cache[pid] = res
						t.tagged[pid] = true
						return res, true
					}
				}
			}
		}

		curr = pInfo.PPID
	}

	if targetProc, ok := t.table[pid]; ok && targetProc.Exe != "" {
		t.tagged[pid] = false
		t.cache[pid] = AgentInfo{}
	}
	return AgentInfo{}, false
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
		if t.tagged[pid] {
			res[pid] = info
		}
	}
	return res
}
