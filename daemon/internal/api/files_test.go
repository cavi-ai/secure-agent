package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/apiroutes"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// fileSecret is a registered secret, assembled at runtime so no scannable
// literal sits in source.
var fileSecret = "synthetic-" + "known-secret-" + "0123456789"

func fileTestAPI(t *testing.T) *API {
	t.Helper()
	a := newTestAPI("", testStore(t), &fakeKiller{}, func() Status { return Status{Running: true} })
	eng, err := firewall.NewEngine(config.FirewallConfig{
		Mode:     "monitor",
		Patterns: []config.PatternConfig{{ID: "aws-key", Type: "cloud-key", Re: `AKIA[0-9A-Z]{16}`, Mode: "monitor"}},
	}, []byte("salt"))
	if err != nil {
		t.Fatal(err)
	}
	eng.SetFingerprints([]config.Fingerprint{
		{ID: "fp1", Type: firewall.TypeEnvValue, Len: len(fileSecret), HMAC: firewall.Fingerprint([]byte("salt"), fileSecret)},
	})
	a.setFirewallForTest(FirewallControl{Engine: eng})
	return a
}

// writeTranscript writes lines to a file and returns its path and the byte
// offset of each line.
func writeTranscript(t *testing.T, lines ...string) (string, []int64) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "rollout-2026-09-23T12-53-26-s.jsonl")
	var offs []int64
	var b strings.Builder
	for _, l := range lines {
		offs = append(offs, int64(b.Len()))
		b.WriteString(l + "\n")
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p, offs
}

func putTranscriptFlag(a *API, id, path string, offset int64) {
	a.store.PutFlag(model.Flag{ID: id, Rule: "secret-in-transcript", Severity: 3, TS: time.Now(), Agent: "codex", SessionID: "s1",
		Evidence: []model.EvidenceItem{{Kind: "transcript", Label: path, Sub: "fingerprint match", Rule: "fp1", Offset: offset}}})
}

func getDetail(t *testing.T, a *API, path string) (*httptest.ResponseRecorder, model.FileDetail) {
	t.Helper()
	w := httptest.NewRecorder()
	a.handleFileDetail(w, httptest.NewRequest(http.MethodGet, "/files/detail?path="+url.QueryEscape(path), nil))
	var d model.FileDetail
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
			t.Fatal(err)
		}
	}
	return w, d
}

// Only an absolute, clean path that stored evidence names is served.
func TestFileDetailServesEvidencePathsOnly(t *testing.T) {
	a := fileTestAPI(t)
	p, _ := writeTranscript(t, "one")
	for path, want := range map[string]int{
		"":                          http.StatusBadRequest,
		"relative/x.jsonl":          http.StatusBadRequest,
		filepath.Dir(p) + "/../x/y": http.StatusBadRequest,
		p:                           http.StatusNotFound,
	} {
		if w, _ := getDetail(t, a, path); w.Code != want {
			t.Errorf("path %q: status %d, want %d", path, w.Code, want)
		}
	}
	w := httptest.NewRecorder()
	a.handleFileDetail(w, httptest.NewRequest(http.MethodPost, "/files/detail?path="+url.QueryEscape(p), nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: status %d, want 405", w.Code)
	}
}

// A transcript hit yields the transcript subject, the hit with its offset and
// an excerpt with the secret masked.
func TestFileDetailTranscriptHitMaskedExcerpt(t *testing.T) {
	a := fileTestAPI(t)
	p, offs := writeTranscript(t,
		`{"type":"session_meta"}`,
		`{"type":"message","content":"list the env"}`,
		`{"type":"function_call_output","output":"TOKEN=`+fileSecret+` ok"}`)
	putTranscriptFlag(a, "f1", p, offs[2])

	w, d := getDetail(t, a, p)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if !d.Exists || d.Size == 0 || !d.OwnedByUser || d.Subject == nil || d.Subject.Category != "transcript" {
		t.Fatalf("detail facts = %+v subject=%+v", d, d.Subject)
	}
	if len(d.Findings) != 1 || len(d.Hits) != 1 || d.Hits[0].Offset != offs[2] || d.Hits[0].Rule != "fp1" {
		t.Fatalf("findings=%+v hits=%+v", d.Findings, d.Hits)
	}
	if strings.Contains(w.Body.String(), fileSecret) || !strings.Contains(d.Excerpt, "[REDACTED:fp1]") || d.ExcerptWithheld != "" {
		t.Fatalf("excerpt=%q withheld=%q", d.Excerpt, d.ExcerptWithheld)
	}
}

// A hit recorded before offsets existed (offset 0) is found by scanning.
func TestFileDetailFindsHitWithoutOffset(t *testing.T) {
	a := fileTestAPI(t)
	p, _ := writeTranscript(t, `{"type":"session_meta"}`, `{"output":"TOKEN=`+fileSecret+`"}`)
	putTranscriptFlag(a, "f1", p, 0)

	_, d := getDetail(t, a, p)
	if !strings.Contains(d.Excerpt, "[REDACTED:fp1]") || strings.Contains(d.Excerpt, fileSecret) {
		t.Fatalf("excerpt=%q withheld=%q", d.Excerpt, d.ExcerptWithheld)
	}
}

// A deleted evidence file still has its findings; nothing is read.
func TestFileDetailDeletedFile(t *testing.T) {
	a := fileTestAPI(t)
	p := filepath.Join(t.TempDir(), "gone.jsonl")
	putTranscriptFlag(a, "f1", p, 42)

	w, d := getDetail(t, a, p)
	if w.Code != http.StatusOK || d.Exists || d.Excerpt != "" || len(d.Findings) != 1 || len(d.Hits) != 1 {
		t.Fatalf("status %d detail %+v", w.Code, d)
	}
}

// A multi-MB single line yields a bounded excerpt with the secret masked.
func TestFileDetailHugeLineExcerptBounded(t *testing.T) {
	a := fileTestAPI(t)
	line := `{"output":"` + strings.Repeat("x ", 250_000) + "TOKEN=" + fileSecret + " " + strings.Repeat("y ", 750_000) + `"}`
	p, offs := writeTranscript(t, line)
	putTranscriptFlag(a, "f1", p, offs[0])

	w, d := getDetail(t, a, p)
	if len(d.Excerpt) == 0 || len(d.Excerpt) > 4096 || !strings.Contains(d.Excerpt, "[REDACTED:fp1]") || strings.Contains(w.Body.String(), fileSecret) {
		t.Fatalf("excerpt len=%d withheld=%q", len(d.Excerpt), d.ExcerptWithheld)
	}
}

// A secret that survives masking (present encoded next to a maskable one)
// withholds the excerpt instead of showing the window around the mask.
func TestFileDetailWithholdsWhenMaskingIsIncomplete(t *testing.T) {
	a := fileTestAPI(t)
	enc := base64StdForTest(fileSecret)
	p, offs := writeTranscript(t, `{"output":"TOKEN=`+fileSecret+` blob `+enc+` end"}`)
	putTranscriptFlag(a, "f1", p, offs[0])

	w, d := getDetail(t, a, p)
	if d.Excerpt != "" || !strings.Contains(d.ExcerptWithheld, "encoded") || strings.Contains(w.Body.String(), enc) {
		t.Fatalf("excerpt=%q withheld=%q", d.Excerpt, d.ExcerptWithheld)
	}
}

type openRecorder struct{ calls [][]string }

func (o *openRecorder) open(args ...string) error {
	o.calls = append(o.calls, args)
	return nil
}

func postFile(a *API, h func(http.ResponseWriter, *http.Request), method, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"path": path})
	h(w, httptest.NewRequest(method, "/files/x", strings.NewReader(string(body))))
	return w
}

// Reveal runs open -R and Open runs open -t on an evidence file only; each is
// audited.
func TestFileRevealAndOpen(t *testing.T) {
	a := fileTestAPI(t)
	rec := &openRecorder{}
	a.openPath = rec.open
	p, _ := writeTranscript(t, "one")
	putTranscriptFlag(a, "f1", p, 0)
	dir := t.TempDir()
	putTranscriptFlag(a, "f2", dir, 0)
	gone := filepath.Join(dir, "gone.jsonl")
	putTranscriptFlag(a, "f3", gone, 0)

	cases := []struct {
		name   string
		h      func(http.ResponseWriter, *http.Request)
		method string
		path   string
		want   int
	}{
		{"reveal", a.handleFileReveal, http.MethodPost, p, http.StatusOK},
		{"open", a.handleFileOpen, http.MethodPost, p, http.StatusOK},
		{"reveal dir", a.handleFileReveal, http.MethodPost, dir, http.StatusOK},
		{"open dir", a.handleFileOpen, http.MethodPost, dir, http.StatusBadRequest},
		{"not evidence", a.handleFileOpen, http.MethodPost, "/w/other.txt", http.StatusNotFound},
		{"deleted", a.handleFileReveal, http.MethodPost, gone, http.StatusGone},
		{"GET", a.handleFileOpen, http.MethodGet, p, http.StatusMethodNotAllowed},
	}
	for _, c := range cases {
		if w := postFile(a, c.h, c.method, c.path); w.Code != c.want {
			t.Errorf("%s: status %d, want %d (%s)", c.name, w.Code, c.want, w.Body.String())
		}
	}
	want := fmt.Sprint([][]string{{"-R", p}, {"-t", p}, {"-R", dir}})
	if got := fmt.Sprint(rec.calls); got != want {
		t.Fatalf("open calls = %s, want %s", got, want)
	}
	actions := map[string]int{}
	for _, e := range a.store.RecentAudit(20) {
		actions[e.Action]++
	}
	if actions["file-reveal"] != 2 || actions["file-open"] != 1 {
		t.Fatalf("audit actions = %v", actions)
	}
}

// Off macOS, reveal and open report unsupported.
func TestFileOpenUnsupported(t *testing.T) {
	a := fileTestAPI(t)
	a.openPath = func(...string) error { return errors.ErrUnsupported }
	p, _ := writeTranscript(t, "one")
	putTranscriptFlag(a, "f1", p, 0)
	if w := postFile(a, a.handleFileReveal, http.MethodPost, p); w.Code != http.StatusNotImplemented {
		t.Fatalf("status %d, want 501", w.Code)
	}
}

// The file routes are console-admitted, NoAgent, and reveal/open mutate.
func TestFileRoutesAreNoAgent(t *testing.T) {
	for _, p := range []string{"/files/detail", "/files/reveal", "/files/open"} {
		if !apiroutes.IsNoAgent(p) || !apiroutes.ConsoleAllowed(p) {
			t.Errorf("%s: NoAgent=%v console=%v", p, apiroutes.IsNoAgent(p), apiroutes.ConsoleAllowed(p))
		}
	}
	if !apiroutes.IsMutation("POST", "/files/reveal") || !apiroutes.IsMutation("POST", "/files/open") || apiroutes.IsMutation("GET", "/files/detail") {
		t.Fatal("reveal/open must be mutations, detail a read")
	}
	a := &API{}
	for _, c := range []struct {
		r    role
		want bool
	}{{roleNone, false}, {roleForeign, false}, {roleAgent, false}, {roleOwner, true}, {roleUI, true}} {
		if got := a.authorize(c.r, http.MethodGet, "/files/detail"); got != c.want {
			t.Errorf("role %s GET /files/detail: %v, want %v", c.r, got, c.want)
		}
	}
}

// On the console listener a NoAgent route serves only a TCP peer that is
// identified and outside every agent family.
func TestConsoleNoAgentChecksTheTCPPeer(t *testing.T) {
	a := fileTestAPI(t)
	h := a.ConsoleHandler()
	get := func() int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/files/detail?path=%2Fw%2Fnone", nil)
		r.RemoteAddr = "127.0.0.1:50123"
		h.ServeHTTP(w, r)
		return w.Code
	}
	a.tcpClientPID = func(string) (int32, error) { return 777, nil }
	a.isAgentPID = func(pid int32) bool { return pid == 777 }
	if c := get(); c != http.StatusForbidden {
		t.Fatalf("agent peer: %d, want 403", c)
	}
	a.isAgentPID = func(int32) bool { return false }
	if c := get(); c != http.StatusNotFound {
		t.Fatalf("browser peer: %d, want 404 from the handler", c)
	}
	a.tcpClientPID = func(string) (int32, error) { return 0, errors.New("no peer") }
	if c := get(); c != http.StatusForbidden {
		t.Fatalf("unidentified peer: %d, want 403", c)
	}
	a.isAgentPID = nil
	a.tcpClientPID = func(string) (int32, error) { return 777, nil }
	if c := get(); c != http.StatusForbidden {
		t.Fatalf("no agent check wired: %d, want 403", c)
	}
}

// On the socket an owner-uid peer that the live family check calls an agent
// is refused a NoAgent route; other routes keep the owner's access.
func TestSocketNoAgentLiveFamilyCheck(t *testing.T) {
	sock := fmt.Sprintf("/tmp/sa_noagent_%d.sock", time.Now().UnixNano())
	defer os.Remove(sock)
	a := fileTestAPI(t)
	a.socketPath = sock
	a.setPeersForTest(loopbackChecker{NewPeerChecker()}, func() map[int32]struct{} { return nil })
	self := int32(os.Getpid())
	a.isAgentPID = func(pid int32) bool { return pid == self }
	ctx, cancel := contextWithCancel()
	defer cancel()
	go a.Serve(ctx)
	waitForSocket(t, sock)
	cl := unixClient(sock)

	resp, err := cl.Get("http://unix/files/detail?path=%2Fw%2Fnone")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("agent-family owner peer: %d, want 403", resp.StatusCode)
	}
	resp, err = cl.Get("http://unix/status")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/status for the same peer: %d, want 200", resp.StatusCode)
	}
	a.isAgentPID = func(int32) bool { return false }
	resp, err = cl.Get("http://unix/files/detail?path=%2Fw%2Fnone")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("owner peer: %d, want 404 from the handler", resp.StatusCode)
	}
}

// lsof -Fp lists both ends of a loopback connection; the daemon's own pid is
// dropped.
func TestParseLsofPIDs(t *testing.T) {
	out := []byte("p7725\nf26\np9142\nf40\n")
	if got := ParseLsofPIDs(out, 9142); fmt.Sprint(got) != "[7725]" {
		t.Fatalf("pids = %v, want [7725]", got)
	}
	if got := ParseLsofPIDs([]byte("garbage\n"), 1); len(got) != 0 {
		t.Fatalf("pids = %v, want none", got)
	}
}

func base64StdForTest(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
