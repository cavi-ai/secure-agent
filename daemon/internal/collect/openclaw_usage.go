package collect

import (
	"database/sql"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// openclaw model-call collection.
//
// Newer openclaw releases stop writing step tokens to lcm.db: each agent keeps
// its transcript in agents/<agent>/agent/openclaw-agent.sqlite, where every
// assistant transcript event carries the provider's usage (input, output,
// cacheRead, cacheWrite, cost.total) and the model and provider. These rows
// become model_call events (kind 14) on the transcript's session.
//
// The same safety rules as lcm.db apply: opened read-only (mode=ro,
// query_only), watermarked per database on transcript_events' rowid, bounded
// per poll, and no content column is read — json_extract reads only the
// message's model, provider and usage numbers. Rows stored compressed
// (event_json NULL, event_zstd set) are skipped. Once any agent database
// answers, lcm.db's step tokens are no longer turned into model calls, so a
// release writing both is not counted twice.

const (
	// maxOpenclawUsageRows bounds usage rows read per database per poll.
	maxOpenclawUsageRows = 500
	// openclawAgentDB is an agent's transcript database under the state dir.
	openclawAgentDB = "openclaw-agent.sqlite"
)

const openclawUsageQuery = `
SELECT rowid, session_id, created_at,
       COALESCE(json_extract(event_json, '$.message.model'), ''),
       COALESCE(json_extract(event_json, '$.message.provider'), ''),
       COALESCE(json_extract(event_json, '$.message.usage.input'), 0),
       COALESCE(json_extract(event_json, '$.message.usage.output'), 0),
       COALESCE(json_extract(event_json, '$.message.usage.cacheWrite'), 0),
       COALESCE(json_extract(event_json, '$.message.usage.cost.total'), 0)
FROM transcript_events
WHERE rowid > ? AND rowid <= ? AND message_role = 'assistant'
  AND event_json IS NOT NULL AND json_valid(event_json)
  AND json_type(event_json, '$.message.usage') = 'object'
ORDER BY rowid LIMIT ?`

// openclawAgentDBs lists the agent transcript databases under the state
// directory holding lcm.db, sorted, with each one's agent name.
func openclawAgentDBs(stateDir string) map[string]string {
	paths, _ := filepath.Glob(filepath.Join(stateDir, "agents", "*", "agent", openclawAgentDB))
	sort.Strings(paths)
	out := make(map[string]string, len(paths))
	for _, p := range paths {
		out[p] = filepath.Base(filepath.Dir(filepath.Dir(p)))
	}
	return out
}

// pollUsage reads each agent database's new usage rows and publishes their
// model calls. Returns how many events it published.
func (c *OpenclawCollector) pollUsage() int {
	published := 0
	dbs := openclawAgentDBs(filepath.Dir(c.dbPath))
	paths := make([]string, 0, len(dbs))
	for p := range dbs {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		n, ok := c.pollUsageDB(p, dbs[p])
		published += n
		if ok {
			c.usageActive = true
		}
	}
	return published
}

// pollUsageDB reads one agent database past its watermark. ok is true when
// the database answered (its transcript table exists).
func (c *OpenclawCollector) pollUsageDB(path, agent string) (published int, ok bool) {
	if _, err := os.Stat(path); err != nil {
		return 0, false
	}
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=busy_timeout(2000)&_pragma=query_only(true)", url.PathEscape(path))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return 0, false
	}
	defer db.Close()

	var top int64
	if err := db.QueryRow(`SELECT COALESCE(MAX(rowid), 0) FROM transcript_events`).Scan(&top); err != nil {
		c.noteUsageErr(path, err)
		return 0, false
	}
	wm, seen := c.usageWM[path]
	if !seen {
		cutoff := c.now().Add(-traceFirstSightWindow).UnixMilli()
		err := db.QueryRow(`SELECT rowid FROM transcript_events WHERE created_at < ? ORDER BY rowid DESC LIMIT 1`, cutoff).Scan(&wm)
		if err != nil && err != sql.ErrNoRows {
			c.noteUsageErr(path, err)
			return 0, false
		}
		c.usageWM[path] = wm
		c.saveState()
	}
	rows, err := db.Query(openclawUsageQuery, wm, top, maxOpenclawUsageRows)
	if err != nil {
		c.noteUsageErr(path, err)
		return 0, false
	}
	defer rows.Close()
	read := 0
	for rows.Next() {
		var (
			rowid               int64
			sid                 string
			created             int64
			model, provider     string
			in, out, cacheWrite int64
			cost                float64
		)
		if err := rows.Scan(&rowid, &sid, &created, &model, &provider, &in, &out, &cacheWrite, &cost); err != nil {
			c.noteUsageErr(path, err)
			return published, true
		}
		read++
		ts := time.UnixMilli(created).UTC()
		if sid != "" && (in > 0 || out > 0 || cacheWrite > 0) {
			if !c.noted[sid] {
				c.noted[sid] = true
				if c.OnSessionSeen != nil {
					c.OnSessionSeen(sid, "openclaw", "openclaw:"+agent, ts)
				}
			}
			tokensIn := in + cacheWrite
			if cost <= 0 && model != "" {
				cost = ModelCostUSD(model, tokensIn, out)
			}
			e := event.Event{Kind: event.KindModelCall, TS: ts, SessionID: sid,
				Model: model, Provider: provider, TokensIn: tokensIn, TokensOut: out, CostUSD: cost}
			if !c.bus.TryPublish(e) {
				// Retry this row on the next poll.
				return published, true
			}
			published++
		}
		c.usageWM[path] = rowid
	}
	if rows.Err() == nil && read < maxOpenclawUsageRows && c.usageWM[path] < top {
		// Every row up to top was read; the rest were not usage rows.
		c.usageWM[path] = top
	}
	if c.usageWM[path] != wm {
		c.saveState()
	}
	return published, true
}

// noteUsageErr logs one failure per database until it changes.
func (c *OpenclawCollector) noteUsageErr(path string, err error) {
	msg := err.Error()
	if c.usageErr[path] == msg {
		return
	}
	c.usageErr[path] = msg
	log.Printf("openclaw: %s: usage read failed (schema drift?): %v", path, err)
}
