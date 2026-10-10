package collect

import (
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

func TestJSONLTracersPrimeCodexAndResetIdentity(t *testing.T) {
	path := "/work/sessions/rollout-id.jsonl"
	prefix := codexMetaLine + "\n" + codexSettingsLine + "\n"
	var tracers jsonlTracers
	r := tracers.Parse(path, codexTokenLine, int64(len(prefix)), strings.NewReader(prefix))
	if !r.Parsed || r.Session.Harness != "codex" || r.Session.ID != "019f58e8-6230" || r.Session.Workspace != "/Volumes/x/repo" {
		t.Fatalf("primed identity lost: %+v", r)
	}
	if len(r.Events) != 1 || r.Events[0].Kind != event.KindModelCall || r.Events[0].Model != "m-test" {
		t.Fatalf("primed model lost: %+v", r.Events)
	}
	tracers.Reset(path)
	if tracers.Session(path) != "" {
		t.Fatal("reset retained identity")
	}
	tracers.Parse(path, codexMetaLine, 0, strings.NewReader(""))
	r = tracers.Parse(path, codexTokenLine, 0, strings.NewReader(""))
	if len(r.Events) != 1 || r.Events[0].Model != "" {
		t.Fatalf("reset retained model: %+v", r.Events)
	}
}
