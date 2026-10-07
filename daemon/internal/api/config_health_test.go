package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
// start) or a successful reload; YAML errors never echo the file's values.
func TestDoctorReportsConfigProblems(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	st := testStore(t)
	t.Cleanup(func() { st.Close() })
	a := newTestAPI("", st, nil, func() Status { return Status{Running: true, Uptime: "1h0m0s"} })

	if c := configCheck(t, a); c.State != doctorPass || c.Fix != "" {
		t.Fatalf("no problem: %+v", c)
	}

	a.SetConfigBootProblem(errors.New("yaml: unmarshal errors:\n  line 3: cannot unmarshal !!str `hunter2hunter2` into int"))
	c := configCheck(t, a)
	if c.State != doctorFail || c.Fix == "" || !strings.Contains(c.Detail, "at start") || strings.Contains(c.Detail, "hunter2") {
		t.Fatalf("boot problem: %+v", c)
	}

	a.SetConfigReloadProblem(errors.New("overlay is malformed YAML"))
	if c := configCheck(t, a); c.State != doctorFail || !strings.Contains(c.Detail, "latest reload skipped") || !strings.Contains(c.Detail, "at start") {
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
