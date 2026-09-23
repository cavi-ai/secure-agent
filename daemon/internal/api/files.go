package api

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/redact"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// File detail bounds: findings and accesses listed, hits excerpted, bytes
// read from one hit's line, bytes scanned to find a hit with no recorded
// offset, bytes kept either side of a masked secret, excerpt size.
const (
	fileListLimit  = 20
	fileMaxHits    = 3
	fileReadCap    = 1 << 20
	fileScanCap    = 64 << 20
	fileWindow     = 1536
	fileExcerptCap = 4096
)

const redactedMarker = "[REDACTED"

// evidencePath accepts an absolute path that is already clean; the daemon
// matches stored evidence on that exact string.
func evidencePath(p string) (string, bool) {
	if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return "", false
	}
	return p, true
}

// isEvidencePath reports whether a stored flag, incident or agent-session
// file event names p.
func (a *API) isEvidencePath(p string) bool {
	return len(a.store.PathFindings(p, 1)) > 0 || len(a.store.PathAccesses(p, 1)) > 0
}

// handleFileDetail serves GET /files/detail?path=: what the daemon knows
// about one evidence file, with a masked excerpt around each transcript hit.
func (a *API) handleFileDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p, ok := evidencePath(r.URL.Query().Get("path"))
	if !ok {
		http.Error(w, "path must be absolute and clean", http.StatusBadRequest)
		return
	}
	findings := a.store.PathFindings(p, fileListLimit)
	accesses := a.store.PathAccesses(p, fileListLimit)
	if len(findings) == 0 && len(accesses) == 0 {
		http.Error(w, "no stored evidence names this path", http.StatusNotFound)
		return
	}
	writeJSON(w, a.fileDetail(p, findings, accesses))
}

func (a *API) fileDetail(p string, findings []model.FileFinding, accesses []model.FileAccess) model.FileDetail {
	home := explainHome()
	d := model.FileDetail{Path: p, Display: displayPath(p, home), Findings: findings, Accesses: accesses, Hits: []model.FileHit{}}
	fi, statErr := os.Stat(p)
	if statErr == nil {
		d.Exists = true
		d.Size = fi.Size()
		d.ModTime = fi.ModTime().UTC().Format(time.RFC3339)
		d.OwnedByUser = ownedByUser(fi)
	}

	ev := model.EvidenceItem{Kind: "read", Label: p}
	haveEvidence := false
	sessionID := ""
	for _, f := range findings {
		if sessionID == "" {
			sessionID = f.SessionID
		}
		if f.Kind != "flag" {
			continue
		}
		if !haveEvidence && f.EvidenceKind != "" {
			ev.Kind, ev.Rule, haveEvidence = f.EvidenceKind, f.EvidenceRule, true
		}
		if f.EvidenceKind == "transcript" && len(d.Hits) < fileMaxHits {
			d.Hits = append(d.Hits, model.FileHit{FlagID: f.ID, Rule: f.EvidenceRule, Offset: f.Offset, TS: f.TS})
		}
	}
	for _, acc := range accesses {
		if sessionID == "" {
			sessionID = acc.SessionID
		}
	}
	var workspace, repo string
	if sessionID != "" {
		if s, ok := a.store.GetSession(sessionID); ok {
			d.Session = &s
			workspace, repo = s.Workspace, s.Repo
		}
	}
	d.Subject = explainSubject(ev, workspace, repo, home)
	if d.Exists && !fi.IsDir() && len(d.Hits) > 0 {
		d.Excerpt, d.ExcerptWithheld = a.fileExcerpt(p, d.Hits)
	}
	return d
}

func ownedByUser(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}

// fileExcerpt returns the masked text around each hit, or why none is shown.
// Only text around a mask marker is shown; a line whose rescan still finds a
// secret withholds the whole excerpt.
func (a *API) fileExcerpt(p string, hits []model.FileHit) (string, string) {
	if a.fwEngine == nil {
		return "", "masking is unavailable: the firewall engine is not running"
	}
	f, err := os.Open(p)
	if err != nil {
		return "", "the file could not be read"
	}
	defer f.Close()

	var parts []string
	seen := map[int64]bool{}
	for _, h := range hits {
		off := h.Offset
		if off == 0 {
			if off = a.findHitLine(f, h.Rule); off < 0 {
				continue
			}
		}
		if seen[off] {
			continue
		}
		seen[off] = true
		line, truncated, err := readLineAt(f, off, fileReadCap)
		if err != nil {
			continue
		}
		masked, clean := a.fwEngine.Mask(line)
		if !clean {
			return "", "a secret in this file is still readable after masking (it appears encoded), so no excerpt is shown"
		}
		masked = redact.Scrub(masked)
		if truncated {
			masked = dropTrailingToken(masked)
		}
		if win := markerWindow(masked, fileWindow); win != "" {
			parts = append(parts, win)
		}
	}
	if len(parts) == 0 {
		return "", "the secret's line was not found in the current file"
	}
	return truncateUTF8(strings.Join(parts, "\n…\n"), fileExcerptCap), ""
}

// findHitLine returns the byte offset of the first line in which the
// engine finds rule, scanning at most fileScanCap bytes and the first
// fileReadCap bytes of each line; -1 when absent.
func (a *API) findHitLine(f *os.File, rule string) int64 {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return -1
	}
	r := bufio.NewReaderSize(f, fileReadCap)
	var off int64
	for off < fileScanCap {
		start := off
		frag, err := r.ReadSlice('\n')
		head := string(frag)
		off += int64(len(frag))
		for err == bufio.ErrBufferFull { // skip the rest of an overlong line
			frag, err = r.ReadSlice('\n')
			off += int64(len(frag))
		}
		for _, h := range a.fwEngine.ScanText(head) {
			if h.RuleID == rule {
				return start
			}
		}
		if err != nil {
			return -1
		}
	}
	return -1
}

// readLineAt reads the line starting at off, at most max bytes; truncated
// reports that the line continues past max.
func readLineAt(f *os.File, off int64, max int) (string, bool, error) {
	buf := make([]byte, max)
	n, err := f.ReadAt(buf, off)
	if n == 0 {
		if err == nil {
			err = io.EOF
		}
		return "", false, err
	}
	buf = buf[:n]
	if i := bytes.IndexByte(buf, '\n'); i >= 0 {
		return string(buf[:i]), false, nil
	}
	return string(buf), n == max, nil
}

// dropTrailingToken cuts a truncated line after its last token break, so a
// secret split by the read cap is never shown in part.
func dropTrailingToken(s string) string {
	if i := strings.LastIndexAny(s, " \t\"',;:={}[]()<>&"); i >= 0 {
		return s[:i+1]
	}
	return ""
}

// markerWindow returns the text within n bytes either side of the first mask
// marker, "" when there is none.
func markerWindow(s string, n int) string {
	i := strings.Index(s, redactedMarker)
	if i < 0 {
		return ""
	}
	start, end := i-n, i+n
	if start < 0 {
		start = 0
	}
	if end > len(s) {
		end = len(s)
	}
	if j := strings.IndexByte(s[i:], ']'); j >= 0 && i+j+1 > end {
		end = i + j + 1
	}
	for start > 0 && !utf8.RuneStart(s[start]) {
		start++
	}
	for end < len(s) && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[start:end]
}

func truncateUTF8(s string, max int) string {
	if len(s) <= max {
		return s
	}
	for max > 0 && !utf8.RuneStart(s[max]) {
		max--
	}
	return s[:max]
}

type filePathRequest struct {
	Path string `json:"path"`
}

// handleFileReveal serves POST /files/reveal: Finder selects the file.
func (a *API) handleFileReveal(w http.ResponseWriter, r *http.Request) {
	a.fileAction(w, r, "file-reveal", "-R")
}

// handleFileOpen serves POST /files/open: the default text editor opens the
// file, so nothing is ever executed.
func (a *API) handleFileOpen(w http.ResponseWriter, r *http.Request) {
	a.fileAction(w, r, "file-open", "-t")
}

func (a *API) fileAction(w http.ResponseWriter, r *http.Request, action, flag string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req filePathRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&req); err != nil {
		http.Error(w, "body must be {\"path\": \"…\"}", http.StatusBadRequest)
		return
	}
	p, ok := evidencePath(req.Path)
	if !ok {
		http.Error(w, "path must be absolute and clean", http.StatusBadRequest)
		return
	}
	if !a.isEvidencePath(p) {
		http.Error(w, "no stored evidence names this path", http.StatusNotFound)
		return
	}
	fi, err := os.Stat(p)
	if err != nil {
		http.Error(w, "the file no longer exists", http.StatusGone)
		return
	}
	if flag == "-t" && fi.IsDir() {
		http.Error(w, "a folder cannot be opened in an editor; reveal it instead", http.StatusBadRequest)
		return
	}
	if err := a.openPath(flag, p); err != nil {
		if errors.Is(err, errors.ErrUnsupported) {
			http.Error(w, "opening files is supported on macOS only", http.StatusNotImplemented)
			return
		}
		log.Printf("api: %s %s: %v", action, p, err)
		http.Error(w, "open failed", http.StatusInternalServerError)
		return
	}
	a.store.PutAudit(store.AuditEntry{Action: action, Detail: p})
	writeJSON(w, map[string]bool{"ok": true})
}

// openWithSystem runs /usr/bin/open with args on macOS.
func openWithSystem(args ...string) error {
	if runtime.GOOS != "darwin" {
		return errors.ErrUnsupported
	}
	return exec.Command("/usr/bin/open", args...).Run()
}

// consoleNoAgent guards a NoAgent route on the console listener: the TCP
// client must be identified and outside every agent family.
func (a *API) consoleNoAgent(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.isAgentPID == nil || a.tcpClientPID == nil {
			http.Error(w, "forbidden: agent processes cannot use this endpoint", http.StatusForbidden)
			return
		}
		pid, err := a.tcpClientPID(r.RemoteAddr)
		if err != nil || a.isAgentPID(pid) {
			log.Printf("api: refused %s %s on the console listener: peer %s pid=%d err=%v", r.Method, r.URL.Path, r.RemoteAddr, pid, err)
			http.Error(w, "forbidden: agent processes cannot use this endpoint", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}
