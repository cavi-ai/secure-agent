package store

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestReviewSchemaIsAtomicVersionThree(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "reviews.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	var version, tables int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 3 {
		t.Fatalf("review schema version = %d, %v; want 3", version, err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name IN ('finding_reviews','finding_review_members','finding_review_actions')`).Scan(&tables); err != nil || tables != 3 {
		t.Fatalf("review tables = %d, %v; want 3", tables, err)
	}
}

func TestReviewTransactionWaitsForConcurrentWriter(t *testing.T) {
	s := reviewStore(t)
	f := reviewFlag("source")
	s.PutFlag(f)
	var seq int
	var name, path string
	if err := s.db.QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	writer, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	writer.SetMaxOpenConns(1)
	if _, err = writer.Exec(`BEGIN IMMEDIATE`); err != nil {
		t.Fatal(err)
	}
	released := make(chan error, 1)
	go func() {
		time.Sleep(100 * time.Millisecond)
		_, err := writer.Exec(`COMMIT`)
		released <- err
	}()
	_, reviewErr := s.ObserveFindingReview(f, model.AssessFinding(f))
	if err = <-released; err != nil {
		t.Fatal(err)
	}
	if reviewErr != nil {
		t.Fatalf("review transaction failed to wait for the bounded writer: %v", reviewErr)
	}
	if h := s.WriteHealth(); len(h.Active) != 0 {
		t.Fatalf("transient writer degraded the review projection: %+v", h)
	}
}

func reviewStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "reviews.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err = s.UpsertSession(model.Session{ID: "session", Harness: "codex", Confidence: model.ConfHook, StartedAt: time.Now(), LastSeenAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	return s
}

func reviewFlag(id string) model.Flag {
	at := time.Date(2026, 10, 8, 21, 0, 0, 0, time.UTC)
	return model.Flag{ID: id, Rule: "sensitive-read-then-connect", Agent: "codex", PID: 42, SessionID: "session", Workspace: "/work", Severity: 3, TS: at,
		Evidence: []model.EvidenceItem{{Kind: "read", Label: "/work/credentials", Sub: "sensitive read", PID: 42, Exe: "agent", TS: at.Format(time.RFC3339Nano)}, {Kind: "connect", Label: "203.0.113.5:443", Sub: "egress", PID: 42, TS: at.Add(time.Second).Format(time.RFC3339Nano)}}}
}

func TestReviewReadHealthFailureMissingAndRecovery(t *testing.T) {
	s := reviewStore(t)
	f := reviewFlag("source-health")
	if _, err := s.PutFlag(f); err != nil {
		t.Fatal(err)
	}
	r := onlyReview(t, s)
	if _, err := s.db.Exec("ALTER TABLE finding_review_members RENAME TO unavailable_members"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.FindingReviewID(f.ID); err == nil {
		t.Fatal("unavailable membership query reported success")
	}
	h := s.WriteHealth()
	if h.ReadFailures != 1 || len(h.ReadActive) != 1 || h.ReadActive[0] != "finding reviews" {
		t.Errorf("membership failure was not recorded: %+v", h)
	}
	if _, err := s.db.Exec("ALTER TABLE unavailable_members RENAME TO finding_review_members"); err != nil {
		t.Fatal(err)
	}
	if id, err := s.FindingReviewID(f.ID); err != nil || id != r.ID {
		t.Fatalf("membership recovery: %q %v", id, err)
	}
	if h := s.WriteHealth(); h.ReadFailures != 1 || len(h.ReadActive) != 0 {
		t.Errorf("membership recovery health: %+v", h)
	}
	if _, err := s.db.Exec("UPDATE finding_reviews SET record_json='invalid' WHERE id=?", r.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.GetFindingReview(r.ID); err == nil {
		t.Fatal("malformed record reported success")
	}
	if _, err := s.db.Exec("DELETE FROM finding_reviews WHERE id=?", r.ID); err != nil {
		t.Fatal(err)
	}
	if _, found, err := s.GetFindingReview(r.ID); err != nil || found {
		t.Fatalf("healthy missing row: found=%v err=%v", found, err)
	}
	if h := s.WriteHealth(); h.ReadFailures != 2 || len(h.ReadActive) != 0 {
		t.Errorf("healthy missing row did not clear stale warning: %+v", h)
	}
}

func onlyReview(t *testing.T, s *Store) model.ReviewRecord {
	t.Helper()
	p, err := s.ListFindingReviews("", 100)
	if err != nil || len(p.Reviews) != 1 {
		t.Fatalf("reviews=%+v err=%v", p, err)
	}
	return p.Reviews[0]
}

func TestReviewDecisionSurvivesReplayRepeatAndRestart(t *testing.T) {
	s := reviewStore(t)
	f := reviewFlag("first")
	s.PutFlag(f)
	r := onlyReview(t, s)
	req := model.ReviewDecisionRequest{ID: r.ID, Revision: r.Revision, Action: "acknowledge"}
	first, err := s.DecideFindingReview(req)
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.DecideFindingReview(req)
	if err != nil || !first.At.Equal(again.At) {
		t.Fatalf("duplicate receipt=%+v %v", again, err)
	}
	f.ID = "second"
	s.PutFlag(f)
	s.PutFlag(f)
	s.BumpFlagRepeat("second", f.TS.Add(time.Minute))
	r = onlyReview(t, s)
	if r.Count != 3 || r.ReviewState != "reviewed" || r.Revision != 1 || r.Assessment.Risk != "high" {
		t.Fatalf("identical activity recreated review or erased risk: %+v", r)
	}
	var actions int
	s.db.QueryRow(`SELECT COUNT(*) FROM finding_review_actions`).Scan(&actions)
	if actions != 1 {
		t.Fatalf("repeat appended actions: %d", actions)
	}
	var seq int
	var name, path string
	if err = s.db.QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	s.Close()
	reopened, err := Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	r = onlyReview(t, reopened)
	if r.ReviewState != "reviewed" || r.Count != 3 {
		t.Fatalf("backfill reset decision: %+v", r)
	}
}

func TestReviewStrongerLateEvidenceReopensAndRejectsStaleDecision(t *testing.T) {
	s := reviewStore(t)
	f := reviewFlag("first")
	s.PutFlag(f)
	old := onlyReview(t, s)
	s.DecideFindingReview(model.ReviewDecisionRequest{ID: old.ID, Revision: old.Revision, Action: "acknowledge"})
	f.ID = "stronger"
	f.TS = f.TS.Add(-time.Minute)
	f.Evidence[0].Sub = "agent tool read"
	s.PutFlag(f)
	r := onlyReview(t, s)
	if r.Revision != 2 || r.ReviewState != "unreviewed" || r.Assessment.Risk != "critical" {
		t.Fatalf("stronger late evidence inherited decision: %+v", r)
	}
	if r.EvidenceFlagID != "stronger" || !r.EvidenceFlagAvailable {
		t.Fatalf("critical review links weaker evidence: %+v", r)
	}
	_, err := s.DecideFindingReview(model.ReviewDecisionRequest{ID: r.ID, Revision: old.Revision, Action: "acknowledge"})
	if !errors.Is(err, ErrReviewConflict) {
		t.Fatalf("stale decision=%v", err)
	}
	f.ID = "weaker-late"
	f.Evidence[0].Sub = "sensitive read"
	f.TS = f.TS.Add(-time.Hour)
	s.PutFlag(f)
	r = onlyReview(t, s)
	if r.Revision != 2 || r.Assessment.Risk != "critical" || r.EvidenceFlagID != "stronger" {
		t.Fatalf("late weaker evidence downgraded review: %+v", r)
	}
}

func TestReviewContextSeparatesDestinationsSessionsAndUnknownIdentity(t *testing.T) {
	for _, variant := range []string{"destination", "port", "resource", "session", "unknown"} {
		t.Run(variant, func(t *testing.T) {
			s := reviewStore(t)
			f := reviewFlag("first")
			if variant == "unknown" {
				f.SessionID = ""
			}
			s.PutFlag(f)
			f.ID = "second"
			switch variant {
			case "destination":
				f.Evidence[1].Label = "203.0.113.6:443"
			case "port":
				f.Evidence[1].Label = "203.0.113.5:8443"
			case "resource":
				f.Evidence[0].Label = "/work/other"
			case "session":
				f.SessionID = "other"
				s.UpsertSession(model.Session{ID: "other", Confidence: model.ConfHook})
			}
			s.PutFlag(f)
			p, err := s.ListFindingReviews("", 100)
			if err != nil || len(p.Reviews) != 2 {
				t.Fatalf("contexts merged: %+v %v", p, err)
			}
		})
	}
}

func TestReviewSourceExpiryDoesNotResolveRisk(t *testing.T) {
	s := reviewStore(t)
	s.PutFlag(reviewFlag("source"))
	r := onlyReview(t, s)
	s.db.Exec(`DELETE FROM flags WHERE id='source'`)
	r, ok, err := s.GetFindingReview(r.ID)
	if err != nil || !ok || r.EvidenceAvailable || r.EvidenceFlagAvailable || r.ReviewState != "unreviewed" || r.Assessment.Risk != "high" {
		t.Fatalf("expiry fabricated safety: %+v %v", r, err)
	}
	_, err = s.DecideFindingReview(model.ReviewDecisionRequest{ID: r.ID, Revision: r.Revision, Action: "acknowledge"})
	if !errors.Is(err, ErrReviewMissing) {
		t.Fatalf("decision on unavailable evidence=%v", err)
	}
}

func TestReviewWriteFailureRetainsSourceAndDecisionIsAtomic(t *testing.T) {
	s := reviewStore(t)
	s.PutFlag(reviewFlag("source"))
	r := onlyReview(t, s)
	s.db.Exec(`CREATE TRIGGER fail_receipt BEFORE INSERT ON finding_review_actions BEGIN SELECT RAISE(ABORT,'fixture'); END`)
	_, err := s.DecideFindingReview(model.ReviewDecisionRequest{ID: r.ID, Revision: r.Revision, Action: "acknowledge"})
	if err == nil {
		t.Fatal("receipt failure accepted")
	}
	f, ok := s.GetFlag("source")
	if !ok || f.Acknowledged {
		t.Fatalf("partial acknowledgment: %+v", f)
	}
	r = onlyReview(t, s)
	if r.ReviewState != "unreviewed" {
		t.Fatalf("partial decision: %+v", r)
	}
	s.db.Exec(`CREATE TRIGGER fail_review BEFORE INSERT ON finding_reviews BEGIN SELECT RAISE(ABORT,'fixture'); END`)
	result, err := s.PutFlag(reviewFlag("second"))
	if err != nil || !result.Changed {
		t.Fatalf("projection lost detection: %+v %v", result, err)
	}
	if _, ok = s.GetFlag("second"); !ok {
		t.Fatal("source lost")
	}
	p, err := s.ListFindingReviews("", 100)
	if err != nil || !p.Degraded {
		t.Fatalf("projection failure hidden: %+v %v", p, err)
	}
}

func TestReviewCapacityRetainsUnresolvedSources(t *testing.T) {
	s := reviewStore(t)
	for i := 0; i < maxFindingReviews; i++ {
		if _, err := s.db.Exec(`INSERT INTO finding_reviews VALUES (?,?,?,'{}','unreviewed','',NULL)`, fmt.Sprint(i), fmt.Sprint(i), ""); err != nil {
			t.Fatal(err)
		}
	}
	res, err := s.PutFlag(reviewFlag("at-cap"))
	if err != nil || !res.Changed {
		t.Fatalf("cap lost flag: %+v %v", res, err)
	}
	if h := s.WriteHealth(); len(h.Active) == 0 {
		t.Fatalf("capacity failure hidden: %+v", h)
	}
	var total int
	s.db.QueryRow(`SELECT COUNT(*) FROM finding_reviews`).Scan(&total)
	if total != maxFindingReviews {
		t.Fatalf("cap evicted unresolved metadata: %d", total)
	}
}

func TestReviewSessionPromotionPreservesIdentityAndReopensRevision(t *testing.T) {
	s := reviewStore(t)
	s.PutFlag(reviewFlag("source"))
	old := onlyReview(t, s)
	s.DecideFindingReview(model.ReviewDecisionRequest{ID: old.ID, Revision: old.Revision, Action: "acknowledge"})
	if err := s.RekeySession("session", "canonical"); err != nil {
		t.Fatal(err)
	}
	r := onlyReview(t, s)
	if r.ID != old.ID || r.Context.SessionID != "canonical" || r.Revision != 2 || r.ReviewState != "unreviewed" {
		t.Fatalf("promotion lost or reused review: %+v", r)
	}
	f := reviewFlag("next")
	f.SessionID = "canonical"
	s.PutFlag(f)
	r = onlyReview(t, s)
	if r.Count != 2 {
		t.Fatalf("promotion lost continuity: %+v", r)
	}
}

func TestReviewSourceWriteWithoutProjectionRejectsOldRevision(t *testing.T) {
	s := reviewStore(t)
	f := reviewFlag("source")
	s.PutFlag(f)
	r := onlyReview(t, s)
	s.db.Exec(`CREATE TRIGGER fail_review BEFORE INSERT ON finding_reviews BEGIN SELECT RAISE(ABORT,'fixture'); END`)
	f.Evidence[0].Sub = "agent tool read"
	if _, err := s.PutFlag(f); err != nil {
		t.Fatal(err)
	}
	if id, err := s.FindingReviewID(f.ID); err != nil || id != "" {
		t.Fatalf("stale projection covers changed source: %q %v", id, err)
	}
	_, err := s.DecideFindingReview(model.ReviewDecisionRequest{ID: r.ID, Revision: r.Revision, Action: "acknowledge"})
	if !errors.Is(err, ErrReviewConflict) {
		t.Fatalf("changed source accepted old receipt: %v", err)
	}
}

func TestReviewLegacyAcknowledgmentPersistsAndDoesNotChangeRisk(t *testing.T) {
	s := reviewStore(t)
	s.PutFlag(reviewFlag("source"))
	if !s.AcknowledgeFlag("source") {
		t.Fatal("legacy acknowledgment failed")
	}
	r := onlyReview(t, s)
	if r.ReviewState != "reviewed" || r.Assessment.Risk != "high" || r.Decision == nil || r.Decision.Source != "legacy-source-state" {
		t.Fatalf("legacy state lost: %+v", r)
	}
	s.PutFlag(reviewFlag("identical"))
	r = onlyReview(t, s)
	if r.ReviewState != "reviewed" || r.Count != 2 {
		t.Fatalf("legacy review recreated chore: %+v", r)
	}
}

func TestReviewPromotionCollisionKeepsSeparateReceipts(t *testing.T) {
	s := reviewStore(t)
	s.UpsertSession(model.Session{ID: "canonical", Confidence: model.ConfHook})
	f := reviewFlag("old")
	s.PutFlag(f)
	f.ID = "canonical-source"
	f.SessionID = "canonical"
	s.PutFlag(f)
	if err := s.RekeySession("session", "canonical"); err != nil {
		t.Fatal(err)
	}
	p, err := s.ListFindingReviews("", 100)
	if err != nil || len(p.Reviews) != 2 {
		t.Fatalf("promotion merged contexts: %+v %v", p, err)
	}
	f.ID = "old"
	f.Repeats = 1
	s.PutFlag(f)
	if h := s.WriteHealth(); len(h.Active) > 0 {
		t.Fatalf("isolated source update failed: %+v", h)
	}
}

func TestReviewBackfillPreservesReportedLegacyClosure(t *testing.T) {
	s := reviewStore(t)
	f := reviewFlag("source")
	s.PutFlag(f)
	if _, err := s.db.Exec(`INSERT INTO incidents(id,flag_id,rule,session_id,status,resolved_at,report_json) VALUES ('incident','source','sensitive-read-then-connect','session','resolved','2026-10-08T22:00:00Z','{}')`); err != nil {
		t.Fatal(err)
	}
	if err := s.backfillFindingReviews(); err != nil {
		t.Fatal(err)
	}
	r := onlyReview(t, s)
	if r.ReviewState != "closed_reported" || r.Assessment.Risk != "high" || r.Decision == nil || r.Decision.Source != "legacy-incident-status" {
		t.Fatalf("legacy closure lost or treated as remediation: %+v", r)
	}
}
