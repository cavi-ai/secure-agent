package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

func configCheck(t *testing.T, a *API) DoctorCheck {
	t.Helper()
	rec := httptest.NewRecorder()
	a.buildMux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/doctor", nil))
	var rep DoctorReport
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	return doctorCheckByID(t, rep, "config")
}

// A config.yaml the daemon could not apply fails Doctor until a restart (at
// start) or a successful reload.
func TestDoctorReportsConfigProblems(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true, Uptime: "1h0m0s"} })

	if c := configCheck(t, a); c.State != doctorPass || c.Fix != "" {
		t.Fatalf("no problem: %+v", c)
	}

	boot := errors.New("overlay is malformed YAML: yaml: line 2: mapping values are not allowed in this context")
	a.SetConfigBootProblem(boot)
	c := configCheck(t, a)
	if c.State != doctorFail || c.Fix == "" || !strings.HasPrefix(c.Detail, "at start: ") || !strings.Contains(c.Detail, "until restart") {
		t.Fatalf("boot problem: %+v", c)
	}

	// The watcher's first read of the unchanged file reports the same
	// problem; it is shown once, as the boot problem.
	a.SetConfigReloadProblem(boot)
	if again := configCheck(t, a); again.Detail != c.Detail {
		t.Fatalf("same problem on reload: %q, want %q", again.Detail, c.Detail)
	}

	a.SetConfigReloadProblem(errors.New("advisor.managed_model is required when advisor.managed is true"))
	if c := configCheck(t, a); c.State != doctorFail || !strings.Contains(c.Detail, "latest reload skipped: advisor.managed_model") || !strings.HasPrefix(c.Detail, "at start: ") {
		t.Fatalf("boot and reload problems: %+v", c)
	}

	// A successful reload does not clear the boot problem: firewall, guard
	// and paths still came from defaults.
	a.SetConfigReloadProblem(nil)
	if c := configCheck(t, a); c.State != doctorFail || strings.Contains(c.Detail, "latest reload") {
		t.Fatalf("boot problem after a good reload: %+v", c)
	}

	a.SetConfigBootProblem(nil)
	a.SetConfigReloadProblem(errors.New("overlay is malformed YAML"))
	if c := configCheck(t, a); c.State != doctorFail || !strings.Contains(c.Detail, "running settings are kept") {
		t.Fatalf("reload problem: %+v", c)
	}
	a.SetConfigReloadProblem(nil)
	if c := configCheck(t, a); c.State != doctorPass {
		t.Fatalf("recovered: %+v", c)
	}
}

// Start-only settings changed in the file fail the check until a restart,
// named by their config.yaml keys.
func TestDoctorReportsRestartNeeded(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true, Uptime: "1h0m0s"} })

	a.SetConfigRestartNeeded([]string{"proxy_port", "firewall"})
	if c := configCheck(t, a); c.State != doctorFail || c.Detail != "changed since start, applied after restart: proxy_port, firewall" {
		t.Fatalf("restart needed: %+v", c)
	}
	a.SetConfigReloadProblem(errors.New("overlay is malformed YAML"))
	if c := configCheck(t, a); !strings.Contains(c.Detail, "latest reload skipped") || !strings.Contains(c.Detail, "applied after restart: proxy_port, firewall") {
		t.Fatalf("reload problem and restart needed: %+v", c)
	}
	a.SetConfigReloadProblem(nil)
	a.SetConfigRestartNeeded(nil)
	if c := configCheck(t, a); c.State != doctorPass {
		t.Fatalf("reverted: %+v", c)
	}
}

// Doctor shows a real validation error without the value the overlay holds.
func TestDoctorConfigCheckHidesOverlayValues(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true, Uptime: "1h0m0s"} })

	path := filepath.Join(t.TempDir(), "config.yaml")
	overlay := "advisor:\n  enabled: true\n  managed: false\n  endpoint: \"https://user:hunter2hunter2@api.example.com/v1\"\n  model: \"m\"\n"
	if err := os.WriteFile(path, []byte(overlay), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := config.LoadStrict(path)
	if err == nil {
		t.Fatal("LoadStrict accepted a non-loopback endpoint")
	}
	a.SetConfigReloadProblem(err)
	if c := configCheck(t, a); c.State != doctorFail || strings.Contains(c.Detail, "hunter2") || !strings.Contains(c.Detail, "advisor.endpoint") {
		t.Fatalf("validation error: %+v", c)
	}
}
