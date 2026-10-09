package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type CoverageProbeChallenge struct {
	ID        string    `json:"id"`
	Harness   string    `json:"harness"`
	HookPath  string    `json:"hook_path"`
	Path      string    `json:"path"`
	ExpiresAt time.Time `json:"expires_at"`
}

// A receipt verifies this installed hook's manual round trip only. It never
// becomes session activity or an authorization, and restart clears it.
type CoverageProbeReceipt struct {
	Harness   string    `json:"harness"`
	HookPath  string    `json:"hook_path"`
	CheckedAt time.Time `json:"checked_at"`
	State     string    `json:"state"`
	Detail    string    `json:"detail"`
}

type pendingCoverageProbe struct {
	CoverageProbeChallenge
	fingerprint string
	answered    bool
}
type savedCoverageProbe struct {
	CoverageProbeReceipt
	fingerprint string
}
type coverageProbeState struct {
	mu      sync.Mutex
	pending map[string]pendingCoverageProbe
	saved   map[string]savedCoverageProbe
}

// Only the app's canonical installed paths are executable test targets.
// Hashes include dependencies, registration and policy files. Contents never
// leave this function; a missing optional config has its own stable marker.
func coverageProbeFingerprint(harness string) (string, string, error) {
	if harness != "claude" && harness != "cursor" {
		return "", "", fmt.Errorf("unsupported hook path")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}
	dir := filepath.Join(home, "."+harness, "hooks")
	paths := []string{filepath.Join(dir, "secret_guard.py"), filepath.Join(dir, "activity_log.py"), filepath.Join(dir, "injection_scan.py"), filepath.Join(dir, "guard-rules.json")}
	settings := "settings.json"
	if harness == "cursor" {
		settings = "hooks.json"
	}
	paths = append(paths, filepath.Join(home, "."+harness, settings), filepath.Join(home, ".config", "secure-agent", "guard-modes.json"), filepath.Join(home, ".config", "secure-agent", "guard-cwd-overrides.json"))
	h := sha256.New()
	for i, path := range paths {
		fmt.Fprintf(h, "%s\x00", path)
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if i >= 4 && os.IsNotExist(err) {
			io.WriteString(h, "missing\x00")
			continue
		}
		if err != nil {
			return "", "", err
		}
		f := os.NewFile(uintptr(fd), path)
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
			f.Close()
			return "", "", fmt.Errorf("invalid hook configuration file")
		}
		n, readErr := io.Copy(h, io.LimitReader(f, (1<<20)+1))
		closeErr := f.Close()
		if readErr != nil || closeErr != nil || n > 1<<20 {
			return "", "", fmt.Errorf("hook configuration could not be read")
		}
		io.WriteString(h, "\x00")
	}
	return paths[0], hex.EncodeToString(h.Sum(nil)), nil
}

func (a *API) handleCoverageProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	limitBody(w, r)
	var req struct {
		Harness string `json:"harness"`
		ID      string `json:"id"`
		Passed  *bool  `json:"passed"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "invalid probe request", 400)
		return
	}
	if req.ID != "" {
		if req.Passed == nil {
			http.Error(w, "probe outcome required", 400)
			return
		}
		a.completeCoverageProbe(w, req.ID, *req.Passed)
		return
	}
	if req.Passed != nil || (req.Harness != "claude" && req.Harness != "cursor") {
		http.Error(w, "choose a supported installed hook", 400)
		return
	}
	hook, fingerprint, err := coverageProbeFingerprint(req.Harness)
	if err != nil {
		http.Error(w, "installed hook configuration unavailable; reinstall hooks", 503)
		return
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		http.Error(w, "probe unavailable", 503)
		return
	}
	id := hex.EncodeToString(nonce[:])
	now := time.Now().UTC()
	p := pendingCoverageProbe{CoverageProbeChallenge: CoverageProbeChallenge{ID: id, Harness: req.Harness, HookPath: hook, Path: "/secure-agent-probe/" + id + "/inert.txt", ExpiresAt: now.Add(30 * time.Second)}, fingerprint: fingerprint}
	c := &a.coverageProbes
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending == nil {
		c.pending = map[string]pendingCoverageProbe{}
	}
	for oldID, old := range c.pending {
		if !old.ExpiresAt.After(now) {
			delete(c.pending, oldID)
			continue
		}
		if old.Harness == req.Harness {
			http.Error(w, "a probe is already running", 409)
			return
		}
	}
	c.pending[id] = p
	writeJSON(w, p.CoverageProbeChallenge)
}

func (a *API) answerCoverageProbe(w http.ResponseWriter, req guardDecisionRequest) {
	c := &a.coverageProbes
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.pending[req.ProbeID]
	if !ok || !p.ExpiresAt.After(time.Now()) || p.Harness != req.Agent || p.Path != req.Path || req.Tool != "Read" || req.RuleID != "coverage-probe" {
		http.Error(w, "probe does not match an active inert challenge", 409)
		return
	}
	// This branch never visits policy, the broker, the advisor or the event
	// bus. Its only possible decision is deny, for the inert fixture path.
	p.answered = true
	c.pending[req.ProbeID] = p
	writeJSON(w, map[string]string{"verdict": "deny", "scope": "once", "reason": "coverage-probe", "probe_id": req.ProbeID})
}

func (a *API) completeCoverageProbe(w http.ResponseWriter, id string, passed bool) {
	c := &a.coverageProbes
	c.mu.Lock()
	p, ok := c.pending[id]
	c.mu.Unlock()
	if !ok {
		http.Error(w, "probe no longer exists", 404)
		return
	}
	_, fingerprint, err := coverageProbeFingerprint(p.Harness)
	c.mu.Lock()
	defer c.mu.Unlock()
	current, ok := c.pending[id]
	if !ok {
		http.Error(w, "probe no longer exists", 404)
		return
	}
	if !current.ExpiresAt.After(time.Now()) {
		delete(c.pending, id)
		http.Error(w, "probe expired; run it again", 409)
		return
	}
	if passed && !current.answered {
		http.Error(w, "no hook round-trip receipt", 409)
		return
	}
	delete(c.pending, id)
	receipt := CoverageProbeReceipt{Harness: p.Harness, HookPath: p.HookPath, CheckedAt: time.Now().UTC(), State: "failed", Detail: "The installed hook round trip did not pass."}
	if passed && err == nil && fingerprint == p.fingerprint {
		receipt.State = "passed"
		receipt.Detail = "This installed hook returned the daemon's inert deny response. This manual check does not prove a running agent invokes the hook or that real requests are protected. Policy was unchanged."
	} else if err != nil || fingerprint != p.fingerprint {
		receipt.State = "changed"
		receipt.Detail = "Hook configuration changed or could not be read. Run the check again."
	}
	if c.saved == nil {
		c.saved = map[string]savedCoverageProbe{}
	}
	c.saved[p.Harness] = savedCoverageProbe{CoverageProbeReceipt: receipt, fingerprint: p.fingerprint}
	writeJSON(w, receipt)
}

func (a *API) coverageProbeReceipts() []CoverageProbeReceipt {
	c := &a.coverageProbes
	c.mu.Lock()
	saved := []savedCoverageProbe{}
	for _, p := range c.saved {
		saved = append(saved, p)
	}
	c.mu.Unlock()
	out := []CoverageProbeReceipt{}
	for _, p := range saved {
		r := p.CoverageProbeReceipt
		if r.State == "passed" {
			_, current, err := coverageProbeFingerprint(r.Harness)
			if err != nil || current != p.fingerprint {
				r.State = "changed"
				r.Detail = "The checked hook configuration changed or is unavailable. Run the check again."
			} else if time.Since(r.CheckedAt) > 24*time.Hour {
				r.State = "expired"
				r.Detail = "This check is older than 24 hours. Run it again before relying on it."
			}
		}
		if r.State != p.State {
			c.mu.Lock()
			if current, ok := c.saved[r.Harness]; ok && current.CheckedAt.Equal(r.CheckedAt) {
				current.CoverageProbeReceipt = r
				c.saved[r.Harness] = current
			}
			c.mu.Unlock()
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Harness < out[j].Harness })
	return out
}
