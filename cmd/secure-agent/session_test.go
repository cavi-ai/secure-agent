package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFormatSessionsTable(t *testing.T) {
	start := time.Date(2026, 9, 1, 10, 0, 0, 0, time.Local)
	ended := start.Add(2*time.Hour + 3*time.Minute)
	rows := []sessionRow{
		{ID: "7f3a9c21-4b2e-4a1d", Harness: "claude", Repo: "api-service", Branch: "main", StartedAt: start, LastSeenAt: start.Add(12*time.Minute + 5*time.Second), Status: "active"},
		{ID: "abc", Harness: "opencode", Workspace: "/w/scratch", StartedAt: start, LastSeenAt: start, EndedAt: &ended, Status: "ended"},
		{ID: "s3", Harness: "codex", StartedAt: start, LastSeenAt: start.Add(45 * time.Second), Status: "idle"},
	}
	out := formatSessionsTable(rows)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("want header + 3 rows, got %d lines:\n%s", len(lines), out)
	}
	for _, col := range []string{"ID", "HARNESS", "REPO@BRANCH", "STARTED", "DURATION", "STATUS"} {
		if !strings.Contains(lines[0], col) {
			t.Fatalf("header missing %q: %q", col, lines[0])
		}
	}
	for i, want := range [][]string{
		{"7f3a9c21", "claude", "api-service@main", "2026-09-01", "10:00", "12m", "5s", "active"},
		{"abc", "opencode", "/w/scratch", "2026-09-01", "10:00", "2h", "3m", "ended"},
		{"s3", "codex", "—", "2026-09-01", "10:00", "45s", "idle"},
	} {
		if got := strings.Fields(lines[i+1]); strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("row %d = %q, want %q", i, got, want)
		}
	}
	// Fixed-width: every row's status starts in the STATUS column.
	statusCol := len([]rune(lines[0])) - len("STATUS")
	for i, l := range lines[1:] {
		if r := []rune(l); len(r) <= statusCol || r[statusCol] == ' ' {
			t.Fatalf("row %d status not in the STATUS column:\n%s", i, out)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func sessionTestClient(handler http.Handler) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		r := httptest.NewRecorder()
		handler.ServeHTTP(r, req)
		return r.Result(), nil
	})}
}

func TestRunSessionResolvesPrefixThroughEndpoint(t *testing.T) {
	for _, format := range []string{"md", "json"} {
		t.Run(format, func(t *testing.T) {
			var paths []string
			client := sessionTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				paths = append(paths, r.URL.RequestURI())
				switch r.URL.Path {
				case "/sessions/abcdef/report":
					w.WriteHeader(http.StatusNotFound)
				case "/sessions/resolve":
					if r.URL.Query().Get("prefix") != "abcdef" {
						t.Errorf("prefix query = %q", r.URL.Query().Get("prefix"))
					}
					io.WriteString(w, `[{"id":"abcdef00-0000-4000-8000-000000000001","harness":"codex"}]`)
				case "/sessions/abcdef00-0000-4000-8000-000000000001/report":
					if r.URL.Query().Get("format") != format {
						t.Errorf("format = %q", r.URL.Query().Get("format"))
					}
					io.WriteString(w, "report body\n")
				default:
					t.Errorf("unexpected request %s", r.URL)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			var out strings.Builder
			if err := runSession(client, "abcdef", format, &out); err != nil {
				t.Fatal(err)
			}
			if out.String() != "report body\n" {
				t.Fatalf("output = %q", out.String())
			}
			if len(paths) != 3 || !strings.HasPrefix(paths[1], "/sessions/resolve?prefix=abcdef") {
				t.Fatalf("requests = %v", paths)
			}
		})
	}
}

func TestRunSessionPrefixLookupFailures(t *testing.T) {
	tests := []struct {
		name, body string
		status     int
		want       string
	}{
		{"no matches", `[]`, http.StatusOK, `no session matches "abcdef"`},
		{"legacy daemon", "", http.StatusNotFound, "does not support session prefix lookup"},
		{"unavailable", "", http.StatusServiceUnavailable, "lookup unavailable"},
		{"malformed json", "{", http.StatusOK, "invalid session prefix response"},
		{"foreign id", `[{"id":"wrong-id"}]`, http.StatusOK, "invalid session prefix response"},
		{"duplicate id", `[{"id":"abcdef-1"},{"id":"abcdef-1"}]`, http.StatusOK, "invalid session prefix response"},
		{"too many", `[{"id":"abcdef-1"},{"id":"abcdef-2"},{"id":"abcdef-3"}]`, http.StatusOK, "invalid session prefix response"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := sessionTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/sessions/abcdef/report" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			var out strings.Builder
			if err := runSession(client, "abcdef", "md", &out); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRunSessionExactMatchWinsOverLongerPrefix(t *testing.T) {
	id := "abcdef"
	// The initial exact report is a miss; the second report succeeds.
	var reportCalls int
	client := sessionTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sessions/abcdef/report" {
			reportCalls++
			if reportCalls == 1 {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			io.WriteString(w, "exact report\n")
			return
		}
		if r.URL.Path == "/sessions/resolve" {
			io.WriteString(w, `[{"id":"abcdef"},{"id":"abcdef-extra"}]`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	var out strings.Builder
	if err := runSession(client, id, "md", &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "exact report\n" || reportCalls != 2 {
		t.Fatalf("output=%q reportCalls=%d", out.String(), reportCalls)
	}
}

func TestRunSessionPrefixDoesNotResolveShortOrFullIDs(t *testing.T) {
	t.Run("short", func(t *testing.T) {
		resolverCalled := false
		client := sessionTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/sessions/resolve" {
				resolverCalled = true
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		var out strings.Builder
		err := runSession(client, "abc", "md", &out)
		if err == nil || !strings.Contains(err.Error(), "at least 6") || resolverCalled {
			t.Fatalf("error=%v resolverCalled=%v", err, resolverCalled)
		}
	})
	t.Run("full ID on old daemon", func(t *testing.T) {
		id := "abcdef00-0000-4000-8000-000000000001"
		resolverCalled := false
		client := sessionTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/sessions/resolve" {
				resolverCalled = true
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if r.URL.Path == "/sessions/"+id+"/report" {
				io.WriteString(w, "report\n")
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		var out strings.Builder
		if err := runSession(client, id, "md", &out); err != nil {
			t.Fatal(err)
		}
		if resolverCalled || out.String() != "report\n" {
			t.Fatalf("resolverCalled=%v output=%q", resolverCalled, out.String())
		}
	})
}

func TestRunSessionRejectsShortUnicodePrefixBeforeLookup(t *testing.T) {
	resolverCalled := false
	client := sessionTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sessions/resolve" {
			resolverCalled = true
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	var out strings.Builder
	err := runSession(client, "ééé", "md", &out)
	if err == nil || !strings.Contains(err.Error(), "at least 6") || resolverCalled {
		t.Fatalf("error=%v resolverCalled=%v", err, resolverCalled)
	}
}

func TestRunSessionRejectsInvalidUTF8PrefixBeforeLookup(t *testing.T) {
	resolverCalled := false
	client := sessionTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sessions/resolve" {
			resolverCalled = true
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	var out strings.Builder
	prefix := string([]byte{0xff, 'a', 'b', 'c', 'd', 'e'})
	err := runSession(client, prefix, "md", &out)
	if err == nil || !strings.Contains(err.Error(), "valid UTF-8") || resolverCalled {
		t.Fatalf("error=%v resolverCalled=%v", err, resolverCalled)
	}
}

func TestRunSessionAmbiguousPrefixSaysAtLeastTwo(t *testing.T) {
	client := sessionTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sessions/abcdef/report" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		io.WriteString(w, `[{"id":"abcdef-1"},{"id":"abcdef-2"}]`)
	}))
	var out strings.Builder
	err := runSession(client, "abcdef", "md", &out)
	if err == nil || !strings.Contains(err.Error(), "multiple sessions") || strings.Contains(err.Error(), "matches 2 sessions") ||
		!strings.Contains(err.Error(), "abcdef-1") || !strings.Contains(err.Error(), "abcdef-2") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunSessionReportFailureIsReturned(t *testing.T) {
	client := sessionTestClient(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "report failed")
	}))
	var out strings.Builder
	if err := runSession(client, "abcdef00-0000-4000-8000-000000000001", "json", &out); err == nil || !strings.Contains(err.Error(), "session failed (500)") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunSessionTransportFailureIsReturned(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/sessions/abcdef/report" {
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
		}
		return nil, fmt.Errorf("socket unavailable")
	})}
	var out strings.Builder
	if err := runSession(client, "abcdef", "md", &out); err == nil || !strings.Contains(err.Error(), "lookup unavailable") {
		t.Fatalf("error = %v", err)
	}
}
