package api

import (
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
)

// findingReviewStore is the consumer's storage seam; it can be implemented by
// SQLite or by an in-memory reader without constructing an HTTP API.
type findingReviewStore interface {
	ListFindingReviewsState(string, int, string) (store.ReviewPage, error)
	FindingReviewID(string) (string, error)
	GetFindingReview(string) (model.ReviewRecord, bool, error)
}

type findingReviewIDStore interface {
	FindingReviewID(string) (string, error)
}

// Flags and snapshots share the same review linkage. Optional enrichment
// retains the store's read-health accounting without hiding the finding row.
func stampFindingReviewIDs(st findingReviewIDStore, flags []model.Flag) {
	for i := range flags {
		flags[i].ReviewID, _ = st.FindingReviewID(flags[i].ID)
	}
}

type reviewResult struct {
	record model.ReviewRecord
	found  bool
	err    error
}

// A view lives for one calculation only. Caching errors as well as successes
// preserves incomplete evidence and cannot outlive a review decision.
type findingReviewView struct {
	store   findingReviewStore
	flags   map[string]reviewResult
	reviews map[string]reviewResult
}

func newFindingReviewView(st findingReviewStore) *findingReviewView {
	return &findingReviewView{store: st, flags: map[string]reviewResult{}, reviews: map[string]reviewResult{}}
}

func (v *findingReviewView) Unreviewed() (store.ReviewPage, error) {
	page, err := v.store.ListFindingReviewsState("", 100, "unreviewed")
	if err == nil {
		for _, r := range page.Reviews {
			v.reviews[r.ID] = reviewResult{record: r, found: true}
		}
	}
	return page, err
}

func (v *findingReviewView) ForFlag(flagID string) (model.ReviewRecord, bool, error) {
	if r, ok := v.flags[flagID]; ok {
		return r.record, r.found, r.err
	}
	id, err := v.store.FindingReviewID(flagID)
	r := reviewResult{err: err}
	if err == nil && id != "" {
		var cached bool
		r, cached = v.reviews[id]
		if !cached {
			r.record, r.found, r.err = v.store.GetFindingReview(id)
			v.reviews[id] = r
		}
	}
	v.flags[flagID] = r
	return r.record, r.found, r.err
}
