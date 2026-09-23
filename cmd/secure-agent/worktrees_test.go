package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const worktreesBody = `{"duration_ms":4200,"cached":false,"stale_days":14,` +
	`"summary":{"repos":2,"worktrees":3,"remove":1,"review":1,"keep":1,"prune":0,"stale":1},` +
	`"repos":[` +
	`{"path":"/Users/x/code/app","source":"session","default_branch":"origin/main","worktrees":[` +
	`{"path":"/Users/x/code/app","branch":"main","state":"main","reasons":["main worktree of the repository"]},` +
	`{"path":"/Users/x/code/app/.worktrees/done","branch":"feat/done","state":"remove","stale":true,"idle_days":21,"last_activity":"2026-09-02T10:00:00Z","reasons":["merged into origin/main (squash)"]},` +
	`{"path":"/Users/x/.codex/worktrees/ab12/app","branch":"","detached":true,"state":"keep","idle_days":0,"last_activity":"2026-09-23T10:00:00Z","reasons":["2 uncommitted changes","an agent session is live here"]}]},` +
	`{"path":"/Users/x/code/lib","source":"manual","default_branch":"origin/main","worktrees":[` +
	`{"path":"/Users/x/code/lib/.worktrees/gone","branch":"feat/gone","state":"prune","idle_days":0,"reasons":["directory is gone; git still lists it"]},` +
	`{"path":"/Users/x/code/lib/.claude/worktrees/x","branch":"feat/x","state":"review","idle_days":3,"last_activity":"2026-09-20T10:00:00Z","reasons":["ignored files that only live here: .env"]}]}],` +
	`"errors":["/Users/x/code/broken: git worktree: not a git repository"],` +
	`"advice":{"/Users/x/code/app/.worktrees/done":{"assessment":"remove","confidence":0.8,"rationale":"merged; nothing local"}}}`

func TestFormatWorktrees(t *testing.T) {
	var rep wtReport
	if err := json.Unmarshal([]byte(worktreesBody), &rep); err != nil {
		t.Fatal(err)
	}
	out := formatWorktrees(rep, wtFilter{}, "/Users/x")
	for _, want := range []string{
		"~/code/app  (origin/main, session)\n",
		"  remove  stale    21d  feat/done                         .worktrees/done\n",
		"          merged into origin/main (squash)\n",
		"          advisor: remove (80%) — merged; nothing local\n",
		"  keep              0d  (detached)                        ~/.codex/worktrees/ab12/app\n",
		"          an agent session is live here\n",
		"  prune              -  feat/gone                         .worktrees/gone\n",
		"~/code/lib  (origin/main, manual)\n",
		"2 repos · 3 worktrees · 1 remove · 1 review · 1 keep · 0 prune · 1 stale (idle > 14d) · scan 4.2s\n",
		"error: /Users/x/code/broken: git worktree: not a git repository\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "main worktree of the repository") {
		t.Fatalf("main rows must not print:\n%s", out)
	}

	only := formatWorktrees(rep, wtFilter{State: "review"}, "/Users/x")
	if strings.Contains(only, "~/code/app  (") || !strings.Contains(only, "~/code/lib  (") {
		t.Fatalf("--state review kept the wrong repos:\n%s", only)
	}
	stale := formatWorktrees(rep, wtFilter{Stale: true, Repo: "app"}, "/Users/x")
	if !strings.Contains(stale, "feat/done") || strings.Contains(stale, "(detached)") || strings.Contains(stale, "~/code/lib") {
		t.Fatalf("--stale --repo app:\n%s", stale)
	}
}

// fakeWorktreesDaemon records the requests the CLI makes.
func fakeWorktreesDaemon(t *testing.T, seen *[]string) *http.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		*seen = append(*seen, r.Method+" "+r.URL.String()+" "+string(body))
		switch r.URL.Path {
		case "/worktrees":
			fmt.Fprint(w, worktreesBody)
		case "/worktrees/repos":
			fmt.Fprint(w, `{"status":"ok","path":"/abs/repo"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}}}
}

func TestRunWorktreesRequests(t *testing.T) {
	var seen []string
	client := fakeWorktreesDaemon(t, &seen)

	var js strings.Builder
	if err := runWorktrees(&js, client, []string{"--refresh", "--json"}); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(js.String()) != worktreesBody {
		t.Fatalf("--json must pass the body through:\n%s", js.String())
	}
	var add strings.Builder
	if err := runWorktrees(&add, client, []string{"add", "/abs/repo/sub"}); err != nil {
		t.Fatal(err)
	}
	if err := runWorktrees(io.Discard, client, []string{"hide", "/abs/repo"}); err != nil {
		t.Fatal(err)
	}
	if err := runWorktrees(io.Discard, client, []string{"add"}); err == nil {
		t.Fatal("add without a path must fail")
	}
	want := []string{
		"GET /worktrees?refresh=1 ",
		`POST /worktrees/repos {"hidden":false,"path":"/abs/repo/sub"}`,
		`POST /worktrees/repos {"hidden":true,"path":"/abs/repo"}`,
	}
	if strings.Join(seen, "\n") != strings.Join(want, "\n") {
		t.Fatalf("requests =\n%s\nwant\n%s", strings.Join(seen, "\n"), strings.Join(want, "\n"))
	}
	if add.String() != "added /abs/repo\n" {
		t.Fatalf("add output = %q", add.String())
	}
}

func TestRunWorktreeRemove(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen = append(seen, string(body))
		switch {
		case strings.Contains(string(body), `"prune":true`):
			fmt.Fprint(w, `{"status":"ok","pruned":["/abs/repo/.worktrees/gone"]}`)
		case strings.Contains(string(body), "forbidden"):
			http.Error(w, "forbidden: this endpoint requires a more privileged client", http.StatusForbidden)
		case strings.Contains(string(body), "dirty"):
			w.WriteHeader(http.StatusConflict)
			fmt.Fprint(w, `{"error":"not removable","state":"keep","reasons":["1 uncommitted change"]}`)
		default:
			fmt.Fprint(w, `{"status":"ok","removed":"/abs/repo/.worktrees/done","branch":"feat/done"}`)
		}
	}))
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}}}

	var out strings.Builder
	if err := runWorktrees(&out, client, []string{"remove", "/abs/repo/.worktrees/done"}); err != nil {
		t.Fatal(err)
	}
	if err := runWorktrees(&out, client, []string{"prune", "/abs/repo"}); err != nil {
		t.Fatal(err)
	}
	if want := "removed /abs/repo/.worktrees/done (branch feat/done kept)\npruned /abs/repo/.worktrees/gone\n"; out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
	err := runWorktrees(io.Discard, client, []string{"remove", "/abs/repo/.worktrees/dirty"})
	if err == nil || !strings.Contains(err.Error(), "is keep") || !strings.Contains(err.Error(), "1 uncommitted change") {
		t.Fatalf("refusal err = %v", err)
	}
	if err := runWorktrees(io.Discard, client, []string{"prune"}); err == nil {
		t.Fatal("prune without a path must fail")
	}
	err = runWorktrees(io.Discard, client, []string{"remove", "/abs/repo/.worktrees/forbidden"})
	if err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "Worktrees tab") {
		t.Fatalf("403 err = %v", err)
	}
	want := []string{
		`{"path":"/abs/repo/.worktrees/done"}`,
		`{"prune":true,"repo":"/abs/repo"}`,
		`{"path":"/abs/repo/.worktrees/dirty"}`,
		`{"path":"/abs/repo/.worktrees/forbidden"}`,
	}
	if strings.Join(seen, "\n") != strings.Join(want, "\n") {
		t.Fatalf("bodies =\n%s\nwant\n%s", strings.Join(seen, "\n"), strings.Join(want, "\n"))
	}
}

func TestRunWorktreeAdvise(t *testing.T) {
	queued := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/worktrees/advise" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, `{"status":"ok","queued":%v}`, queued)
	}))
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}}}
	var out strings.Builder
	if err := runWorktrees(&out, client, []string{"advise", "/abs/repo/.worktrees/x"}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "asked the advisor about /abs/repo/.worktrees/x") {
		t.Fatalf("output = %q", out.String())
	}
	queued = false
	if err := runWorktrees(io.Discard, client, []string{"advise", "/abs/repo/.worktrees/x"}); err == nil || !strings.Contains(err.Error(), "advisor is off") {
		t.Fatalf("unqueued err = %v", err)
	}
}
