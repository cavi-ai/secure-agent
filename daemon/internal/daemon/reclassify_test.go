package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/correlate"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

func TestReclassifyReadFlagsAcknowledgesOnlyStaleOnes(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "e.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cfg, err := config.Load("/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()
	zshenv := filepath.Join(home, ".zshenv")
	aws := filepath.Join(home, ".aws", "credentials")
	now := time.Now()
	put := func(id, rule, path, match string) {
		st.PutFlag(model.Flag{ID: id, Rule: rule, Severity: 3, TS: now, PID: 7, Agent: "opencode",
			Evidence: []model.EvidenceItem{{Kind: "read", Label: path, Rule: match}}})
	}
	put("zshenv", "sensitive-read-then-connect", zshenv, "glob:"+zshenv)
	put("aws", "sensitive-read-then-connect", aws, "aws")
	put("other", "keychain-access", zshenv, "glob:"+zshenv)

	if n := reclassifyReadFlags(st, sensitive.New(cfg)); n != 1 {
		t.Fatalf("acknowledged = %d, want 1", n)
	}
	if f, _ := st.GetFlag("zshenv"); !f.Acknowledged || f.AckReason != correlate.ReclassifiedReadReason {
		t.Fatalf("zshenv flag = ack %v reason %q", f.Acknowledged, f.AckReason)
	}
	for _, id := range []string{"aws", "other"} {
		if f, _ := st.GetFlag(id); f.Acknowledged || f.AckReason != "" {
			t.Fatalf("%s must stay open, got ack %v reason %q", id, f.Acknowledged, f.AckReason)
		}
	}
	audit := st.RecentAudit(5)
	if len(audit) != 1 || audit[0].Action != "flag-reclassify" || audit[0].Rule != "sensitive-read-then-connect" {
		t.Fatalf("audit = %+v", audit)
	}
	if n := reclassifyReadFlags(st, sensitive.New(cfg)); n != 0 {
		t.Fatalf("second start acknowledged %d, want 0", n)
	}
}
