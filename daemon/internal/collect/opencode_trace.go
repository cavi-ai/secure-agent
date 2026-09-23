package collect

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// opencode trace collection.
//
// opencode does not write JSONL transcripts — it keeps structured state in a
// SQLite database (~/.local/share/opencode/opencode.db): a `session` table
// (id, directory, model, tokens, cost, timestamps), a `message` table, and a
// `part` table whose rows are JSON with a `type` (tool, step-finish, …). So
// the file tailers cannot see it; this collector reads the DB instead.
//
// Safety rules, because this is another application's live database:
//   - Opened READ-ONLY (mode=ro) and with a busy timeout; the daemon never
//     writes, never locks opencode out, and never creates WAL files.
//   - Polled on an interval with a watermark on time_updated, so each step is
//     read once; there is no full-table scan after the first pass.
//   - Bounded: a single poll reads at most maxOpencodeRows parts, ordered by
//     time_updated, so a huge backlog is drained in chunks across polls
//     rather than one unbounded query.
//   - Read via file: URI with immutable=0 so opencode's WAL is honored; a
//     missing DB or schema mismatch degrades to "not covered", never an
//     error loop.
//
// Trace mapping:
//   - part type "tool" → tool_call (name from the JSON `tool` field; duration
//     from state.time.start/end; status from state.status).
//   - part type "step-finish" → model_call with the step's token counts and
//     cost (opencode already computes cost).
//   - session rows → session sightings (id, directory as workspace, model).
//
// Content (tool input/output, message text) is NEVER carried into events.

const (
	opencodePollInterval = 5 * time.Second
	// maxOpencodeRows bounds parts read per poll. A backlog larger than this
	// is drained over successive polls (watermark advances each time).
	maxOpencodeRows = 500
)

// OpencodeCollector polls opencode's SQLite DB for trace events.
type OpencodeCollector struct {
	bus      *bus.Bus
	dbPath   string
	interval time.Duration

	// OnProduce, when set, fires after events are published — the coverage
	// heartbeat (a running poller that sees nothing is "silent").
	OnProduce func()
	// OnSessionSeen reports an opencode session (id, workspace, time).
	OnSessionSeen func(sessionID, harness, workspace string, at time.Time)

	// watermark: the highest part/session time_updated (unix millis) already
	// read. Persisted only in memory — a daemon restart re-reads the recent
	// tail, which is idempotent (the session spine dedupes by id).
	watermark int64

	// modelCache: session id → last-seen assistant model and provider, so
	// the per-part lookup is one bounded query per session, not per event.
	modelCache map[string]opencodeModel
}

// NewOpencodeCollector builds the poller. Empty dbPath resolves the default.
func NewOpencodeCollector(b *bus.Bus, dbPath string, interval time.Duration) *OpencodeCollector {
	if dbPath == "" {
		home, _ := os.UserHomeDir()
		dbPath = filepath.Join(home, ".local", "share", "opencode", "opencode.db")
	}
	if interval <= 0 {
		interval = opencodePollInterval
	}
	return &OpencodeCollector{bus: b, dbPath: dbPath, interval: interval}
}

// Run polls until ctx is done. Never errors the supervisor: a missing or
// unmigrated DB is a coverage gap the caller surfaces via the produce
// heartbeat, not a crash loop.
func (c *OpencodeCollector) Run(ctx context.Context) error {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	// Prime the watermark to "now" so the first poll does not replay the
	// entire history of an 18 GB database; the live tail is what matters.
	c.primeWatermark()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if n := c.pollOnce(); n > 0 && c.OnProduce != nil {
				c.OnProduce()
			}
		}
	}
}

// openReadOnly opens the DB read-only with a busy timeout, honoring WAL.
func (c *OpencodeCollector) openReadOnly() (*sql.DB, error) {
	if _, err := os.Stat(c.dbPath); err != nil {
		return nil, err
	}
	// file: URI with mode=ro keeps SQLite from writing (no WAL creation, no
	// lock upgrade). busy_timeout lets a concurrent opencode write finish.
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=busy_timeout(2000)&_pragma=query_only(true)",
		url.PathEscape(c.dbPath))
	return sql.Open("sqlite", dsn)
}

// primeWatermark sets the watermark to the current max(time_updated) so the
// first poll starts at the live edge, not the beginning of history.
func (c *OpencodeCollector) primeWatermark() {
	db, err := c.openReadOnly()
	if err != nil {
		return
	}
	defer db.Close()
	_ = db.QueryRow(`SELECT COALESCE(MAX(time_updated), 0) FROM part`).Scan(&c.watermark)
}

// pollOnce reads new parts past the watermark and publishes their events,
// returning how many events were published.
func (c *OpencodeCollector) pollOnce() int {
	db, err := c.openReadOnly()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("opencode: cannot read %s: %v", c.dbPath, err)
		}
		return 0
	}
	defer db.Close()

	// One query per poll, bounded and ordered so the watermark advances
	// monotonically. session_id + tool/step data ride in the part JSON.
	rows, err := db.Query(`
		SELECT p.time_updated, p.session_id, p.data,
		       COALESCE(s.directory, '') AS workspace
		FROM part p
		LEFT JOIN session s ON s.id = p.session_id
		WHERE p.time_updated > ?
		ORDER BY p.time_updated ASC
		LIMIT ?`, c.watermark, maxOpencodeRows)
	if err != nil {
		// Older/newer opencode schema: degrade quietly, the coverage signal
		// carries the fact that we are not seeing it.
		log.Printf("opencode: query failed (schema drift?): %v", err)
		return 0
	}
	defer rows.Close()

	published := 0
	var maxSeen int64
	for rows.Next() {
		var updated int64
		var sessionID, data, workspace string
		if err := rows.Scan(&updated, &sessionID, &data, &workspace); err != nil {
			continue
		}
		if updated > maxSeen {
			maxSeen = updated
		}
		for _, e := range OpencodePartEvents(sessionID, data, updated) {
			// Stamp the model and provider: step-finish rows otherwise carry
			// neither and land unexplained. Best-effort; empty is honest
			// when the message row has none.
			if e.Kind == event.KindModelCall && e.Model == "" {
				e.Model, e.Provider = c.modelFor(db, sessionID)
				if e.Model != "" && e.CostUSD == 0 {
					e.CostUSD = ModelCostUSD(e.Model, e.TokensIn, e.TokensOut)
				}
			}
			c.bus.Publish(e)
			published++
			if c.OnSessionSeen != nil && workspace != "" {
				c.OnSessionSeen(sessionID, "opencode", workspace, e.TS)
			}
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("opencode: cursor error (partial poll): %v", err)
	}
	if maxSeen > c.watermark {
		c.watermark = maxSeen
	}
	return published
}

// opencodeModel is a session's model id and provider id.
type opencodeModel struct{ id, provider string }

// modelFor reads the model and provider ids off a session's most recent
// assistant message (message.data JSON carries modelID and providerID).
// Bounded to one small row; a schema drift degrades to "" quietly.
func (c *OpencodeCollector) modelFor(db *sql.DB, sessionID string) (model, provider string) {
	if v, ok := c.modelCache[sessionID]; ok {
		return v.id, v.provider
	}
	var data string
	err := db.QueryRow(`
		SELECT data FROM message
		WHERE session_id = ? AND json_extract(data, '$.role') = 'assistant'
		ORDER BY time_updated DESC LIMIT 1`, sessionID).Scan(&data)
	if err != nil {
		return "", ""
	}
	// opencode's message.data has carried the ids two ways: nested
	// (model.modelID, model.providerID) on older builds and top-level
	// (modelID, providerID) on current ones. Read both; top-level wins.
	var m struct {
		ModelID    string `json:"modelID"`
		ProviderID string `json:"providerID"`
		Model      struct {
			ModelID    string `json:"modelID"`
			ProviderID string `json:"providerID"`
		} `json:"model"`
	}
	if json.Unmarshal([]byte(data), &m) != nil {
		return "", ""
	}
	v := opencodeModel{id: m.ModelID, provider: m.ProviderID}
	if v.id == "" {
		v.id = m.Model.ModelID
	}
	if v.provider == "" {
		v.provider = m.Model.ProviderID
	}
	if v.id == "" {
		return "", ""
	}
	if c.modelCache == nil {
		c.modelCache = map[string]opencodeModel{}
	}
	c.modelCache[sessionID] = v
	return v.id, v.provider
}

// OpencodePartEvents maps one opencode `part` row to trace events. Pure and
// exported for tests: the format is another app's, so it is pinned directly.
func OpencodePartEvents(sessionID, data string, updatedMillis int64) []event.Event {
	if sessionID == "" || data == "" {
		return nil
	}
	var p struct {
		Type string `json:"type"`
		// tool parts:
		Tool   string `json:"tool"`
		CallID string `json:"callID"`
		State  *struct {
			Status string `json:"status"` // pending | running | completed | error
			Time   struct {
				Start int64 `json:"start"`
				End   int64 `json:"end"`
			} `json:"time"`
		} `json:"state"`
		// step-finish parts:
		Tokens *struct {
			Input     int64 `json:"input"`
			Output    int64 `json:"output"`
			Reasoning int64 `json:"reasoning"`
		} `json:"tokens"`
		Cost float64 `json:"cost"`
	}
	if err := json.Unmarshal([]byte(data), &p); err != nil {
		return nil
	}
	ts := time.UnixMilli(updatedMillis)

	switch p.Type {
	case "tool":
		if p.Tool == "" {
			return nil
		}
		status := "running"
		var durMs int64
		if p.State != nil {
			switch p.State.Status {
			case "completed":
				status = "ok"
			case "error":
				status = "error"
			case "pending", "running":
				status = "running"
			}
			if p.State.Time.Start > 0 {
				ts = time.UnixMilli(p.State.Time.Start)
				if p.State.Time.End >= p.State.Time.Start {
					durMs = p.State.Time.End - p.State.Time.Start
				}
			}
		}
		return []event.Event{{
			Kind: event.KindToolCall, TS: ts, SessionID: sessionID,
			CallID: p.CallID, ToolName: p.Tool, ToolStatus: status, DurationMs: durMs,
		}}
	case "step-finish":
		if p.Tokens == nil {
			return nil
		}
		in := p.Tokens.Input
		out := p.Tokens.Output
		if in == 0 && out == 0 {
			return nil
		}
		// opencode computes cost itself; use it rather than re-deriving.
		return []event.Event{{
			Kind: event.KindModelCall, TS: ts, SessionID: sessionID,
			TokensIn: in, TokensOut: out, CostUSD: p.Cost,
		}}
	}
	return nil
}

// OpencodeDBAvailable reports whether opencode's DB looks readable and
// migrated (used for coverage messaging, not for the poll loop).
func OpencodeDBAvailable(path string) bool {
	if path == "" {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, ".local", "share", "opencode", "opencode.db")
	}
	if fi, err := os.Stat(path); err != nil || fi.IsDir() {
		return false
	}
	return strings.HasSuffix(path, ".db")
}
