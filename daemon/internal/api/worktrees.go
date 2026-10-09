package api

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/advisor"
	"github.com/cavi-ai/secure-agent/daemon/internal/agentask"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"github.com/cavi-ai/secure-agent/daemon/internal/worktreehunter"
)

// handleWorktrees serves the worktree hunter's report. ?refresh=1 asks for a
// rescan (the hunter still answers from a scan finished moments ago).
func (a *API) handleWorktrees(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.worktrees == nil {
		http.Error(w, "worktree hunter not enabled", http.StatusServiceUnavailable)
		return
	}
	refresh := r.URL.Query().Get("refresh") == "1"
	rep := a.worktrees.Report(r.Context(), refresh)
	rep.Advice = a.worktreeNotes(rep)
	rep.Asks = a.latestAsks()
	rep.Askable = a.askableWorktrees(rep)
	if a.store != nil {
		t := a.store.CleanupTotals(time.Now())
		rep.Reclaimed = &t
	}
	writeJSON(w, rep)
}

func (a *API) askableWorktrees(rep worktreehunter.ScanReport) map[string]string {
	if a.store == nil || a.asker == nil {
		return nil
	}
	sessions := a.store.ListSessions(store.SessionFilter{Status: model.SessionActive, Limit: 10000})
	out := map[string]string{}
	for _, repo := range rep.Repos {
		for _, wt := range repo.Worktrees {
			if !wt.InUse || (wt.State != worktreehunter.StateKeep && wt.State != worktreehunter.StateReview) || wt.Orphan {
				continue
			}
			for _, sess := range sessions {
				if !agentask.EligibleSession(sess) {
					continue
				}
				rel, err := filepath.Rel(wt.Path, sess.Workspace)
				if err == nil && rel != ".." && !filepath.IsAbs(rel) && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					out[wt.Path] = sess.Harness
					break
				}
			}
		}
	}
	return out
}

// latestAsks maps each worktree path to its newest agent ask.
func (a *API) latestAsks() map[string]model.AgentAsk {
	if a.store == nil {
		return nil
	}
	out := map[string]model.AgentAsk{}
	for _, ask := range a.store.AgentAsks(500) {
		if _, seen := out[ask.Path]; !seen {
			out[ask.Path] = ask
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// handleWorktreeAsk resumes the conversation of the agent that worked in a
// keep or review worktree ({"path"}) and asks it to open a pull request for
// work worth keeping or to say the worktree can go. The answer arrives
// later in GET /worktrees/asks and the report's asks.
func (a *API) handleWorktreeAsk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.worktrees == nil || a.asker == nil {
		http.Error(w, "asking agents is not enabled", http.StatusServiceUnavailable)
		return
	}
	limitBody(w, r)
	var req struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !filepath.IsAbs(req.Path) {
		http.Error(w, `Invalid payload: {"path"} (absolute)`, http.StatusBadRequest)
		return
	}
	row, repo, err := a.worktrees.Inspect(r.Context(), req.Path)
	switch {
	case errors.Is(err, worktreehunter.ErrNotWorktree):
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	case row.State != worktreehunter.StateKeep && row.State != worktreehunter.StateReview:
		http.Error(w, "only a keep or review worktree has work to sort out; this one is "+row.State, http.StatusConflict)
		return
	case !row.InUse:
		http.Error(w, "no agent is currently working in this worktree", http.StatusConflict)
		return
	}
	ask, err := a.asker.Ask(agentask.Request{Path: row.Path, Repo: repo, Branch: row.Branch, State: row.State, Reasons: row.Reasons})
	switch {
	case errors.Is(err, agentask.ErrNoSession):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, agentask.ErrBusy):
		http.Error(w, err.Error(), http.StatusConflict)
	case err != nil:
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	default:
		writeJSON(w, map[string]any{"status": "ok", "ask": ask})
	}
}

// handleWorktreeAsks lists agent asks, newest first.
func (a *API) handleWorktreeAsks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.store == nil {
		http.Error(w, "store not wired", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, a.store.AgentAsks(queryInt(r.URL.Query().Get("limit"), 50)))
}

// handleCleanupLedger serves the cleanup ledger: what was removed and the
// bytes it gave back, newest first, with all-time and 30-day totals.
// ?days=N adds the daily series of the N days ending today.
func (a *API) handleCleanupLedger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.store == nil {
		http.Error(w, "store not wired", http.StatusServiceUnavailable)
		return
	}
	now := time.Now()
	out := map[string]any{
		"totals":  a.store.CleanupTotals(now),
		"entries": a.store.CleanupLog(queryInt(r.URL.Query().Get("limit"), 100)),
	}
	if days := queryInt(r.URL.Query().Get("days"), 0); days > 0 {
		out["daily"] = a.store.CleanupDaily(now, days)
	}
	writeJSON(w, out)
}

// worktreeNotes looks up the stored advisor note for each row at its current
// HEAD. rep is the handler's copy: the map is new, the cached scan untouched.
func (a *API) worktreeNotes(rep worktreehunter.ScanReport) map[string]model.AdvisorVerdict {
	if a.store == nil {
		return nil
	}
	notes := map[string]model.AdvisorVerdict{}
	for _, repo := range rep.Repos {
		for _, wt := range repo.Worktrees {
			if wt.Head == "" || wt.State == worktreehunter.StateMain {
				continue
			}
			if v, ok := a.store.AdvisorVerdictFor(advisor.WorktreeSubjectID(wt.Path, wt.Head), "worktree"); ok {
				notes[wt.Path] = v
			}
		}
	}
	if len(notes) == 0 {
		return nil
	}
	return notes
}

// groupAdviseMaxRows bounds one group ask; the rest are skipped.
const groupAdviseMaxRows = 40

// A group ask hands the advisor one note at a time and waits for it, so the
// advisor's queue, shared with flag triage and guard recommendations, never
// holds more than one of them. Variables so a test can shorten them.
var (
	// groupAdviseTimeout bounds the background run of one group ask.
	groupAdviseTimeout = time.Hour
	// groupAdviseNoteWait bounds the wait for one note; an on-request
	// advisor call has a 5-minute deadline, plus its time in the queue.
	groupAdviseNoteWait = 6 * time.Minute
	// groupAdvisePoll is how often the store is read for that note.
	groupAdvisePoll = 2 * time.Second
)

// worktreeTarget decodes {"path"} or {"repo"}: exactly one, absolute. A
// refusal is already answered.
func worktreeTarget(w http.ResponseWriter, r *http.Request) (path, repo string, ok bool) {
	var req struct {
		Path string `json:"path"`
		Repo string `json:"repo"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (req.Path == "") == (req.Repo == "") ||
		(req.Path != "" && !filepath.IsAbs(req.Path)) || (req.Repo != "" && !filepath.IsAbs(req.Repo)) {
		http.Error(w, `Invalid payload: {"path"} or {"repo"} (absolute)`, http.StatusBadRequest)
		return "", "", false
	}
	if req.Repo != "" {
		return "", filepath.Clean(req.Repo), true
	}
	return req.Path, "", true
}

// reportRepo finds a repository in a report by its main worktree path.
func reportRepo(rep worktreehunter.ScanReport, path string) (worktreehunter.RepoReport, bool) {
	for _, repo := range rep.Repos {
		if repo.Path == path {
			return repo, true
		}
	}
	return worktreehunter.RepoReport{}, false
}

// groupAdvisePaths lists the rows a group ask covers: keep, review and
// remove rows git still records, at most groupAdviseMaxRows; skipped counts
// the rest.
func groupAdvisePaths(repo worktreehunter.RepoReport) (paths []string, skipped int) {
	for _, wt := range repo.Worktrees {
		if wt.Orphan || (wt.State != worktreehunter.StateKeep && wt.State != worktreehunter.StateReview && wt.State != worktreehunter.StateRemove) {
			continue
		}
		if len(paths) == groupAdviseMaxRows {
			skipped++
			continue
		}
		paths = append(paths, wt.Path)
	}
	return paths, skipped
}

// startGroupAdvise marks a repository's group ask as running; false when any
// group ask already is (one at a time keeps the advisor's queue short).
func (a *API) startGroupAdvise(repo string) bool {
	a.groupAdviseMu.Lock()
	defer a.groupAdviseMu.Unlock()
	if len(a.groupAdvise) > 0 {
		return false
	}
	if a.groupAdvise == nil {
		a.groupAdvise = map[string]bool{}
	}
	a.groupAdvise[repo] = true
	return true
}

func (a *API) finishGroupAdvise(repo string) {
	a.groupAdviseMu.Lock()
	defer a.groupAdviseMu.Unlock()
	delete(a.groupAdvise, repo)
}

// adviseRepo asks the advisor about every keep, review and remove row of a
// repository in the cached report. The first row is handed over before the
// answer, so an advisor that is off or busy says so (200, queued 0) as a
// single ask does; the rest follow in the background, each once the previous
// note is stored (adviseRest). 202 lists the paths it covers.
func (a *API) adviseRepo(w http.ResponseWriter, r *http.Request, repoPath string) {
	repo, ok := reportRepo(a.worktrees.Report(r.Context(), false), repoPath)
	if !ok {
		http.Error(w, "repository is not in the worktree report", http.StatusNotFound)
		return
	}
	paths, skipped := groupAdvisePaths(repo)
	if len(paths) == 0 {
		http.Error(w, "the repository has no keep, review or remove worktree to ask about", http.StatusConflict)
		return
	}
	if !a.startGroupAdvise(repo.Path) {
		http.Error(w, "an advisor group ask is already running", http.StatusConflict)
		return
	}
	var subject string
	var at time.Time
	next := 0
	for next < len(paths) && subject == "" {
		s, t, queued, err := a.askWorktreeNote(r.Context(), paths[next])
		next++
		if err != nil {
			log.Printf("api: group advice for %s: skipped %s: %v", repo.Path, paths[next-1], err)
			continue
		}
		if !queued {
			a.finishGroupAdvise(repo.Path)
			writeJSON(w, map[string]any{"status": "ok", "queued": 0, "rows": len(paths), "skipped": skipped})
			return
		}
		subject, at = s, t
	}
	if subject == "" {
		a.finishGroupAdvise(repo.Path)
		http.Error(w, "none of the repository's worktrees could be inspected", http.StatusConflict)
		return
	}
	if skipped > 0 {
		log.Printf("api: group advice for %s: asking about %d of %d worktrees", repo.Path, len(paths), len(paths)+skipped)
	}
	go a.adviseRest(repo.Path, subject, at, paths[next:])
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]any{"status": "accepted", "queued": 1, "rows": len(paths), "skipped": skipped, "paths": paths})
}

// lifetime is the serving context, or Background before the API serves
// (tests drive handlers directly).
func (a *API) lifetime() context.Context {
	a.groupAdviseMu.Lock()
	defer a.groupAdviseMu.Unlock()
	if a.life == nil {
		return context.Background()
	}
	return a.life
}

// askWorktreeNote inspects one worktree and hands it to the advisor: the
// note's subject, when it was asked, and whether the advisor took it.
func (a *API) askWorktreeNote(ctx context.Context, path string) (subject string, at time.Time, queued bool, err error) {
	adv, err := a.worktrees.AdviceRequest(ctx, path)
	if err != nil {
		return "", time.Time{}, false, err
	}
	at = time.Now()
	return advisor.WorktreeSubjectID(adv.Path, adv.Head), at, a.worktreeAdvisor(adv), nil
}

// adviseRest works through a group ask after its first note: it waits for
// the previous note, then asks about the next row. It stops when the
// advisor turns a row away (off or busy), at daemon shutdown or after
// groupAdviseTimeout, and never takes the daemon down with it.
func (a *API) adviseRest(repo, subject string, at time.Time, paths []string) {
	defer a.finishGroupAdvise(repo)
	defer func() {
		if p := recover(); p != nil {
			log.Printf("api: group advice for %s stopped: panic: %v", repo, p)
		}
	}()
	ctx, cancel := context.WithTimeout(a.lifetime(), groupAdviseTimeout)
	defer cancel()
	for _, p := range paths {
		if !a.waitWorktreeNote(ctx, subject, at) {
			log.Printf("api: group advice for %s stopped: %v", repo, ctx.Err())
			return
		}
		s, t, queued, err := a.askWorktreeNote(ctx, p)
		if err != nil {
			log.Printf("api: group advice for %s: skipped %s: %v", repo, p, err)
			if ctx.Err() != nil {
				return
			}
			continue
		}
		if !queued {
			log.Printf("api: group advice for %s stopped: the advisor is off or busy", repo)
			return
		}
		subject, at = s, t
	}
}

// waitWorktreeNote waits until the note for subject asked at at is stored,
// or groupAdviseNoteWait passes (a failed call stores nothing; the run moves
// on). False only when ctx ends.
func (a *API) waitWorktreeNote(ctx context.Context, subject string, at time.Time) bool {
	deadline := time.Now().Add(groupAdviseNoteWait)
	// Stored times may be whole seconds.
	since := at.Truncate(time.Second)
	for time.Now().Before(deadline) {
		if v, ok := a.store.AdvisorVerdictFor(subject, "worktree"); ok && !v.CreatedAt.Before(since) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(groupAdvisePoll):
		}
	}
	return ctx.Err() == nil
}

// handleWorktreeAdvise queues one worktree ({"path"}) or every keep, review
// and remove row of a repository ({"repo"}) for an advisory note from the
// local model. The note is displayed beside the row; it never changes the
// verdict or what Remove accepts.
func (a *API) handleWorktreeAdvise(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.worktrees == nil || a.worktreeAdvisor == nil {
		http.Error(w, "worktree advice not enabled", http.StatusServiceUnavailable)
		return
	}
	limitBody(w, r)
	path, repo, ok := worktreeTarget(w, r)
	if !ok {
		return
	}
	if repo != "" {
		a.adviseRepo(w, r, repo)
		return
	}
	adv, err := a.worktrees.AdviceRequest(r.Context(), path)
	switch {
	case errors.Is(err, worktreehunter.ErrNotWorktree):
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	case errors.Is(err, worktreehunter.ErrNothingToAdvise):
		http.Error(w, err.Error(), http.StatusConflict)
		return
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"status": "ok", "queued": a.worktreeAdvisor(adv), "subject": advisor.WorktreeSubjectID(adv.Path, adv.Head)})
}

// handleWorktreeRepos edits the saved repo list: {"path"} adds the repository
// containing path (unhiding it), {"path", "hidden": true} hides it.
func (a *API) handleWorktreeRepos(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.worktrees == nil {
		http.Error(w, "worktree hunter not enabled", http.StatusServiceUnavailable)
		return
	}
	limitBody(w, r)
	var req struct {
		Path   string `json:"path"`
		Hidden bool   `json:"hidden"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Path == "" {
		http.Error(w, `Invalid payload: {"path", "hidden"?}`, http.StatusBadRequest)
		return
	}
	if req.Hidden {
		if !a.worktrees.HideRepo(req.Path) {
			http.Error(w, "repository is not on the saved list", http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]any{"status": "ok", "hidden": true})
		return
	}
	main, err := a.worktrees.AddRepo(req.Path)
	switch {
	case errors.Is(err, worktreehunter.ErrNotRepo):
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	case err != nil:
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"status": "ok", "path": main})
}

// handleWorktreeRemove removes one worktree ({"path"}) or prunes a
// repository's missing ones ({"repo", "prune": true}). The hunter inspects
// the worktree again first and removes it only on a fresh remove verdict;
// a refusal answers 409 with that verdict's state and reasons. With
// "async": true it answers 202 at once and GET /worktrees reports the
// removal's steps and outcome under "removals".
func (a *API) handleWorktreeRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.worktrees == nil {
		http.Error(w, "worktree hunter not enabled", http.StatusServiceUnavailable)
		return
	}
	limitBody(w, r)
	var req struct {
		Path  string `json:"path"`
		Repo  string `json:"repo"`
		Prune bool   `json:"prune"`
		Async bool   `json:"async"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (req.Prune && req.Repo == "") || (!req.Prune && req.Path == "") {
		http.Error(w, `Invalid payload: {"path"} or {"repo", "prune": true}`, http.StatusBadRequest)
		return
	}
	target := req.Path
	if req.Prune {
		target = req.Repo
	}
	if !filepath.IsAbs(target) {
		http.Error(w, "path must be absolute", http.StatusBadRequest)
		return
	}
	if req.Prune {
		pruned, err := a.worktrees.Prune(r.Context(), req.Repo)
		switch {
		case errors.Is(err, worktreehunter.ErrNotRepo):
			http.Error(w, err.Error(), http.StatusNotFound)
		case errors.Is(err, worktreehunter.ErrNothingToPrune):
			http.Error(w, err.Error(), http.StatusConflict)
		case err != nil:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		default:
			writeJSON(w, map[string]any{"status": "ok", "pruned": pruned})
		}
		return
	}
	if req.Async {
		rm, err := a.worktrees.StartRemove(req.Path)
		if errors.Is(err, worktreehunter.ErrRemoving) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]any{"status": "accepted", "removal": rm})
		return
	}
	row, err := a.worktrees.Remove(r.Context(), req.Path)
	var refused *worktreehunter.NotRemovableError
	switch {
	case errors.Is(err, worktreehunter.ErrRemoving):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.As(err, &refused):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]any{"error": "not removable", "state": refused.Row.State, "reasons": refused.Row.Reasons})
	case errors.Is(err, worktreehunter.ErrNotWorktree):
		http.Error(w, err.Error(), http.StatusNotFound)
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	default:
		writeJSON(w, map[string]any{"status": "ok", "removed": row.Path, "branch": row.Branch, "reasons": row.Reasons,
			"bytes": row.SizeBytes, "bytes_partial": row.SizePartial})
	}
}

// worktreePath decodes {"path"} for the worktree folder actions.
func (a *API) worktreePath(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return "", false
	}
	if a.worktrees == nil {
		http.Error(w, "worktree hunter not enabled", http.StatusServiceUnavailable)
		return "", false
	}
	limitBody(w, r)
	var req filePathRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !filepath.IsAbs(req.Path) {
		http.Error(w, `Invalid payload: {"path": "<absolute path>"}`, http.StatusBadRequest)
		return "", false
	}
	return filepath.Clean(req.Path), true
}

// handleWorktreeReveal serves POST /worktrees/reveal: Finder selects a
// folder the current worktree report lists.
func (a *API) handleWorktreeReveal(w http.ResponseWriter, r *http.Request) {
	p, ok := a.worktreePath(w, r)
	if !ok {
		return
	}
	if !a.worktrees.Listed(p) {
		http.Error(w, "not a folder the worktree report lists", http.StatusNotFound)
		return
	}
	if _, err := os.Stat(p); err != nil {
		http.Error(w, "the folder no longer exists", http.StatusGone)
		return
	}
	if err := a.openPath("-R", p); err != nil {
		if errors.Is(err, errors.ErrUnsupported) {
			http.Error(w, "opening folders is supported on macOS only", http.StatusNotImplemented)
			return
		}
		http.Error(w, "open failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	a.store.PutAudit(store.AuditEntry{Action: "worktree-reveal", Detail: p})
	writeJSON(w, map[string]bool{"ok": true})
}

// handleWorktreeReconnect serves POST /worktrees/reconnect: `git worktree
// repair` in the repository that still records an orphan folder.
func (a *API) handleWorktreeReconnect(w http.ResponseWriter, r *http.Request) {
	p, ok := a.worktreePath(w, r)
	if !ok {
		return
	}
	repo, err := a.worktrees.Reconnect(r.Context(), p)
	switch {
	case errors.Is(err, worktreehunter.ErrNotOrphan):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, worktreehunter.ErrNoReconnect):
		http.Error(w, err.Error(), http.StatusConflict)
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	default:
		writeJSON(w, map[string]any{"status": "ok", "repo": repo})
	}
}

// handleWorktreeTrash serves POST /worktrees/trash: an orphan folder goes
// to the Trash on its volume.
func (a *API) handleWorktreeTrash(w http.ResponseWriter, r *http.Request) {
	p, ok := a.worktreePath(w, r)
	if !ok {
		return
	}
	res, err := a.worktrees.TrashOrphan(r.Context(), p)
	switch {
	case errors.Is(err, worktreehunter.ErrNotOrphan):
		http.Error(w, err.Error(), http.StatusNotFound)
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	default:
		writeJSON(w, map[string]any{"status": "ok", "result": res})
	}
}

// handleWorktreeReviewTrash is an explicit, recoverable cleanup after the
// operator has inspected a review row. The hunter rechecks the fresh facts.
func (a *API) handleWorktreeReviewTrash(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.worktrees == nil {
		http.Error(w, "worktree hunter not enabled", http.StatusServiceUnavailable)
		return
	}
	limitBody(w, r)
	var req struct {
		Path    string   `json:"path"`
		Head    string   `json:"head"`
		Reasons []string `json:"reasons"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !filepath.IsAbs(req.Path) || req.Head == "" || len(req.Reasons) == 0 {
		http.Error(w, "absolute path, reviewed head and reasons are required", http.StatusBadRequest)
		return
	}
	res, err := a.worktrees.TrashReviewed(r.Context(), req.Path, req.Head, req.Reasons)
	var notReviewable *worktreehunter.NotReviewableError
	switch {
	case errors.Is(err, worktreehunter.ErrNotWorktree):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, worktreehunter.ErrReviewChanged), errors.As(err, &notReviewable):
		http.Error(w, err.Error(), http.StatusConflict)
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	default:
		writeJSON(w, map[string]any{"status": "ok", "result": res})
	}
}
