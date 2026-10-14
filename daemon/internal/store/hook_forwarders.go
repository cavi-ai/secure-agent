package store

import (
	"sort"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
)

const forwarderLimit = 128
const forwarderFreshnessWindow = 2 * time.Minute

type HookForwarderSnapshot struct {
	Report     hookrun.ForwarderReport `json:"report"`
	ReceivedAt time.Time               `json:"received_at"`
	Freshness  string                  `json:"freshness"`
}

func (s *Store) NoteHookForwarder(r hookrun.ForwarderReport) {
	s.noteHookForwarder(r, time.Now().UTC())
}

func (s *Store) noteHookForwarder(r hookrun.ForwarderReport, now time.Time) {
	if r.Validate() != nil {
		s.NoteHookRejected()
		return
	}
	h := &s.hookIngestion
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.Available {
		return
	}
	if h.forwarders == nil {
		h.forwarders = make(map[string]HookForwarderSnapshot)
	}
	if old, found := h.forwarders[r.ForwarderID]; found {
		if r.Sequence <= old.Report.Sequence {
			return
		}
		if r.Harness != old.Report.Harness || r.SessionID != old.Report.SessionID || r.DeliveryFailures < old.Report.DeliveryFailures || r.Dropped < old.Report.Dropped {
			h.Rejected++
			h.LastRejectedAt = &now
			return
		}
	} else if len(h.forwarders) >= forwarderLimit {
		// Retain the most recently received instances with bounded memory.
		// Truncation remains visible for the rest of this daemon run.
		var oldest string
		for id, row := range h.forwarders {
			if oldest == "" || row.ReceivedAt.Before(h.forwarders[oldest].ReceivedAt) || (row.ReceivedAt.Equal(h.forwarders[oldest].ReceivedAt) && id < oldest) {
				oldest = id
			}
		}
		delete(h.forwarders, oldest)
		h.ForwardersTruncated = true
	}
	h.forwarders[r.ForwarderID] = HookForwarderSnapshot{Report: r, ReceivedAt: now}
}

func forwarderSnapshots(rows map[string]HookForwarderSnapshot, now time.Time) []HookForwarderSnapshot {
	out := make([]HookForwarderSnapshot, 0, len(rows))
	for _, row := range rows {
		row.Freshness = "recent"
		if now.Before(row.ReceivedAt) {
			row.Freshness = "unverified"
		} else if now.Sub(row.ReceivedAt) > forwarderFreshnessWindow {
			row.Freshness = "stale"
		} else if row.Report.TS.After(row.ReceivedAt) {
			// Waiting for the clock to catch up cannot validate old evidence.
			row.Freshness = "unverified"
		} else if now.Sub(row.Report.TS) > forwarderFreshnessWindow {
			row.Freshness = "stale"
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Report.ForwarderID < out[j].Report.ForwarderID })
	return out
}
