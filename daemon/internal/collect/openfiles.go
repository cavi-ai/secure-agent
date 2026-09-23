package collect

import (
	"bufio"
	"bytes"
	"context"
	"log"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// A codex process holds its rollout file open for append; the file name ends
// in the session id (rollout-<ts>-<session id>.jsonl). Probing which codex
// process holds which rollout joins a trace-created session to its process
// tree when the harness+workspace key cannot (an orchestrated codex runs in
// the orchestrator's cwd while its rollout names another workspace).

const (
	// rolloutJoinInterval is the open-file probe cadence.
	rolloutJoinInterval = 30 * time.Second
	// maxProbePIDs bounds the pids one probe call names.
	maxProbePIDs = 64
	// openFilesTimeout bounds one lsof call.
	openFilesTimeout = 10 * time.Second
	// probeErrorLogEvery rate-limits probe error logging.
	probeErrorLogEvery = time.Minute
)

// RolloutSessionID returns the session id a codex rollout file name carries
// (the trailing UUID of rollout-<ts>-<id>.jsonl), "" for any other path.
func RolloutSessionID(path string) string {
	if !IsCodexRolloutPath(path) {
		return ""
	}
	base := strings.TrimSuffix(filepath.Base(path), ".jsonl")
	const uuidLen = 36
	if len(base) < len("rollout-")+uuidLen+1 || base[len(base)-uuidLen-1] != '-' {
		return ""
	}
	id := base[len(base)-uuidLen:]
	for i, c := range id {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return ""
			}
		default:
			if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
				return ""
			}
		}
	}
	return id
}

// OpenRolloutFiles returns, for each pid, the codex rollout files it holds
// open (paths under a codex sessions directory). Pids are probed at most
// maxProbePIDs per call.
func OpenRolloutFiles(pids []int32) (map[int32][]string, error) {
	return openRolloutFiles(pids)
}

// cmdRunner runs a command and returns its stdout; the lsof seam for tests.
type cmdRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// lsofRolloutFiles runs `lsof -w -p <pid>,<pid>,… -Fn` per chunk of
// maxProbePIDs pids and keeps the rollout paths. lsof exits nonzero when a
// named pid exited mid-scan; the files it did list are kept and the error is
// returned for the caller's rate-limited log.
func lsofRolloutFiles(run cmdRunner, bin string, pids []int32) (map[int32][]string, error) {
	out := map[int32][]string{}
	var firstErr error
	for chunk := range slices.Chunk(pids, maxProbePIDs) {
		list := make([]string, len(chunk))
		for i, p := range chunk {
			list[i] = strconv.Itoa(int(p))
		}
		ctx, cancel := context.WithTimeout(context.Background(), openFilesTimeout)
		b, err := run(ctx, bin, "-w", "-p", strings.Join(list, ","), "-Fn")
		cancel()
		if err != nil && firstErr == nil {
			firstErr = err
		}
		for pid, paths := range parseLsofRolloutFiles(b) {
			out[pid] = append(out[pid], paths...)
		}
	}
	return out, firstErr
}

// parseLsofRolloutFiles reads lsof -F output: a "p<pid>" line starts each
// process, "n<name>" lines name its files. Only codex rollout paths are kept.
func parseLsofRolloutFiles(b []byte) map[int32][]string {
	out := map[int32][]string{}
	var pid int32
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case 'p':
			n, err := strconv.ParseInt(line[1:], 10, 32)
			if err != nil {
				pid = 0
				continue
			}
			pid = int32(n)
		case 'n':
			if pid > 0 && IsCodexRolloutPath(line[1:]) {
				out[pid] = append(out[pid], line[1:])
			}
		}
	}
	return out
}

// RolloutJoiner joins each open codex rollout's session to the process holding
// it, every rolloutJoinInterval.
type RolloutJoiner struct {
	// PIDs lists the live pids the tagger names codex.
	PIDs func() []int32
	// Probe returns each pid's open rollout paths (OpenRolloutFiles).
	Probe func(pids []int32) (map[int32][]string, error)
	// SessionFor names the session a rollout path belongs to ("" if unknown).
	SessionFor func(path string) string
	// Join ties the session to the pid (Resolver.JoinTranscriptPID).
	Join func(sessionID string, pid int32)

	interval  time.Duration
	lastErrAt time.Time
}

// Run probes until ctx is done.
func (j *RolloutJoiner) Run(ctx context.Context) error {
	every := j.interval
	if every <= 0 {
		every = rolloutJoinInterval
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case now := <-ticker.C:
			j.tick(now)
		}
	}
}

// tick probes the live codex pids once and joins every open rollout. A pid's
// rollouts are joined oldest file name first.
func (j *RolloutJoiner) tick(now time.Time) {
	pids := j.PIDs()
	if len(pids) == 0 {
		return
	}
	slices.Sort(pids)
	files, err := j.Probe(pids)
	if err != nil && now.Sub(j.lastErrAt) >= probeErrorLogEvery {
		j.lastErrAt = now
		log.Printf("collect: open-rollout probe: %v", err)
	}
	for _, pid := range pids {
		paths := slices.Clone(files[pid])
		slices.Sort(paths)
		for _, p := range paths {
			if sid := j.SessionFor(p); sid != "" {
				j.Join(sid, pid)
			}
		}
	}
}
