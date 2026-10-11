package api

import (
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

type memoryPostureStore struct {
	memoryReviewStore
	flags          []model.Flag
	flagErr        error
	filter         store.FlagFilter
	reviewErr      error
	review         model.ReviewRecord
	reviewReads    int
	incidents      []model.IncidentReport
	incidentErr    error
	workflowErr    error
	workflowFound  bool
	workflowReads  int
	health         store.WriteHealth
	flagHealth     []string
	incidentHealth []string
}

func (s *memoryPostureStore) QueryFlagsResult(filter store.FlagFilter) ([]model.Flag, error) {
	s.filter = filter
	s.health.ReadActive = s.flagHealth
	return s.flags, s.flagErr
}

func (s *memoryPostureStore) ListFindingReviewsState(string, int, string) (store.ReviewPage, error) {
	return store.ReviewPage{}, s.reviewErr
}

func (s *memoryPostureStore) GetFindingReview(string) (model.ReviewRecord, bool, error) {
	s.reviewReads++
	return s.review, true, nil
}

func (s *memoryPostureStore) RecentIncidentsResult(int) ([]model.IncidentReport, error) {
	s.health.ReadActive = s.incidentHealth
	return s.incidents, s.incidentErr
}

func (s *memoryPostureStore) IncidentStatusResult(string) (store.IncidentWorkflow, bool, error) {
	s.workflowReads++
	s.health.ReadActive = nil
	return store.IncidentWorkflow{Status: "open"}, s.workflowFound, s.workflowErr
}

func (s *memoryPostureStore) WriteHealth() store.WriteHealth { return s.health }

func TestPostureEvidenceUsesSnapshotCutoff(t *testing.T) {
	at := time.Date(2020, 1, 1, 12, 0, 0, 0, time.UTC)
	s := &memoryPostureStore{flags: []model.Flag{
		{ID: "current", TS: at},
		{ID: "boundary", TS: at.Add(-24 * time.Hour)},
		{ID: "expired", TS: at.Add(-24*time.Hour - time.Nanosecond)},
		{ID: "undated"},
	}}
	in := loadPostureEvidence(s, postureInputs{Generated: at})
	var ids []string
	for _, f := range in.Flags {
		ids = append(ids, f.ID)
	}
	if !reflect.DeepEqual(ids, []string{"current", "boundary"}) {
		t.Fatalf("snapshot cutoff: %v", ids)
	}
	if s.filter.MinSeverity != 3 || s.filter.Limit != 25 || !s.filter.Unacted {
		t.Fatalf("attention query policy changed: %+v", s.filter)
	}
	if got := loadPostureEvidence(s, postureInputs{Generated: at.Add(24*time.Hour + time.Nanosecond)}).Flags; len(got) != 0 {
		t.Fatalf("expired flags retained after advancing snapshot: %+v", got)
	}
}

func TestPostureEvidenceFailureAndRecovery(t *testing.T) {
	failed := errors.New("read unavailable")
	for _, label := range []string{"flags", "finding reviews", "review link", "incidents", "incident workflows", "missing workflow"} {
		t.Run(label, func(t *testing.T) {
			at := time.Date(2020, 1, 1, 12, 0, 0, 0, time.UTC)
			s := &memoryPostureStore{flags: []model.Flag{{ID: "flag", Rule: readConnectRule, TS: at}},
				incidents: []model.IncidentReport{{ID: "incident", FlagID: "flag"}}, workflowFound: true}
			want := label
			switch label {
			case "flags":
				s.flagErr = failed
			case "finding reviews":
				s.reviewErr = failed
			case "review link":
				s.memoryReviewStore.err, want = failed, "finding reviews"
			case "incidents":
				s.incidentErr = failed
			case "incident workflows":
				s.workflowErr = failed
			case "missing workflow":
				s.workflowFound, want = false, "incident workflows"
			}
			input := postureInputs{Generated: at, Status: Status{Running: true, StorageHealth: &store.WriteHealth{}}}
			in := loadPostureEvidence(s, input)
			if !slices.Contains(in.FailedReads, want) {
				t.Fatalf("read failure hidden: %+v", in.FailedReads)
			}
			p := derivePosture(in)
			if p.State == "all-clear" || !slices.ContainsFunc(p.CoverageItems, func(item PostureItem) bool { return item.Kind == "storage_read_failure" }) {
				t.Fatalf("failure did not reach posture: %+v", p)
			}
			s.flagErr, s.reviewErr, s.memoryReviewStore.err, s.incidentErr, s.workflowErr = nil, nil, nil, nil, nil
			s.workflowFound = true
			if recovered := loadPostureEvidence(s, input); len(recovered.FailedReads) != 0 {
				t.Fatalf("new pass retained old failures: %v", recovered.FailedReads)
			}
		})
	}
}

func TestPostureEvidenceRetainsEnrichmentFailuresBeforeRecovery(t *testing.T) {
	s := &memoryPostureStore{incidents: []model.IncidentReport{{ID: "incident"}}, workflowFound: true,
		flagHealth: []string{"flag advisor verdicts"}, incidentHealth: []string{"incident advisor verdicts"}}
	initial := make([]string, 1, 4)
	initial[0] = "flags"
	in := loadPostureEvidence(s, postureInputs{FailedReads: initial})
	want := []string{"flags", "flag advisor verdicts", "incident advisor verdicts"}
	if !reflect.DeepEqual(in.FailedReads, want) || len(s.health.ReadActive) != 0 {
		t.Fatalf("same-pass enrichment failures lost: %v, current health: %+v", in.FailedReads, s.health)
	}
	if !reflect.DeepEqual(initial[:cap(initial)], []string{"flags", "", "", ""}) {
		t.Fatal("evidence reader mutated caller's failure buffer")
	}
}

func TestPostureEvidenceSharesReviewAcrossFlagsAndIncidents(t *testing.T) {
	at := time.Date(2020, 1, 1, 12, 0, 0, 0, time.UTC)
	s := &memoryPostureStore{flags: []model.Flag{{ID: "flag", Rule: readConnectRule, TS: at}},
		incidents: []model.IncidentReport{{ID: "first", FlagID: "flag"}, {ID: "second", FlagID: "flag"}},
		review:    model.ReviewRecord{ID: "review", Context: model.ReviewContext{Attribution: "stored-session"}}}
	in := loadPostureEvidence(s, postureInputs{Generated: at})
	if s.calls != 1 || s.reviewReads != 1 || s.workflowReads != 0 || len(in.FailedReads) != 0 || in.FlagReviews["flag"].ID != "review" {
		t.Fatalf("review ownership not shared: links=%d reviews=%d workflows=%d input=%+v", s.calls, s.reviewReads, s.workflowReads, in)
	}
}
