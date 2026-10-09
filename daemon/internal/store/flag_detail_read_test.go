package store

import (
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestFlagDetailRejectsMalformedReadsAndRecovers(t *testing.T) {
	for _, damage := range []string{"pid='invalid'", "ts='invalid'", "evidence='invalid'", "process='invalid'", "last_seen='invalid'"} {
		t.Run(damage, func(t *testing.T) {
			s := reviewStore(t)
			f := model.Flag{ID: "detail", Rule: "keychain-access", Severity: 3, PID: 42, TS: time.Now().UTC()}
			if _, err := s.PutFlag(f); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec("UPDATE flags SET " + damage + " WHERE id='detail'"); err != nil {
				t.Fatal(err)
			}
			if got, found := s.GetFlag(f.ID); found || got.ID != "" {
				t.Errorf("malformed detail accepted: found=%v %+v", found, got)
			}
			h := s.WriteHealth()
			if h.ReadFailures != 1 || len(h.ReadActive) != 1 || h.ReadActive[0] != "flag detail" {
				t.Errorf("detail read failure hidden: %+v", h)
			}
			if _, err := s.PutFlag(f); err != nil {
				t.Fatal(err)
			}
			if got, found := s.GetFlag(f.ID); !found || got.ID != f.ID || !got.TS.Equal(f.TS) {
				t.Errorf("detail recovery: found=%v %+v", found, got)
			}
			if h := s.WriteHealth(); h.ReadFailures != 1 || len(h.ReadActive) != 0 {
				t.Errorf("recovery lost read failure history: %+v", h)
			}
		})
	}
}

func TestFlagDetailPreservesNullableLegacyFields(t *testing.T) {
	s := reviewStore(t)
	f := model.Flag{ID: "legacy-detail", Rule: "keychain-access", Severity: 2, PID: 42, TS: time.Now().UTC()}
	if _, err := s.PutFlag(f); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE flags SET rule=NULL,agent=NULL,evidence=NULL,session_id=NULL,workspace=NULL,process=NULL,repeats=NULL,last_seen=NULL WHERE id=?", f.ID); err != nil {
		t.Fatal(err)
	}
	if got, found := s.GetFlag(f.ID); !found || got.ID != f.ID || got.Rule != "" || got.Agent != "" || got.Process != nil || got.Repeats != 0 || got.LastSeen != nil {
		t.Errorf("valid nullable legacy detail rejected: found=%v %+v", found, got)
	}
	if h := s.WriteHealth(); h.ReadFailures != 0 {
		t.Errorf("legacy fields counted as corruption: %+v", h)
	}
}
