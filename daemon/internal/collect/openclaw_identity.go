package collect

import (
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

func openclawAgentID(key string) string {
	parts := strings.SplitN(key, ":", 3)
	if len(parts) < 2 || parts[0] != "agent" {
		return ""
	}
	return parts[1]
}

// noteSession reads only the session header's cwd, never message content.
// Missing or unsupported metadata retains the explicit non-path agent label.
func (c *OpenclawCollector) noteSession(id, agent string, at time.Time, db *sql.DB) {
	if c.OnSessionSeen == nil {
		return
	}
	now := c.now()
	retryAt, unresolved := c.identityRetry[id]
	if c.noted[id] && (!unresolved || now.Before(retryAt)) {
		return
	}
	publish, resolved := !c.noted[id], false
	s := TraceSession{ID: id, Harness: "openclaw", Workspace: "openclaw", At: at}
	defer func() {
		if resolved {
			delete(c.identityRetry, id)
			publish = true
		} else {
			if c.identityRetry == nil {
				c.identityRetry = map[string]time.Time{}
			}
			c.identityRetry[id] = now.Add(openclawPollInterval)
		}
		c.noted[id] = true
		if publish {
			c.OnSessionSeen(s)
		}
	}()
	if agent == "" || agent == "." || agent == ".." || filepath.Base(agent) != agent || strings.ContainsAny(agent, `/\`) {
		return
	}
	s.Workspace, s.Origin = "openclaw:"+agent, agent+" (openclaw)"
	if db == nil {
		path := filepath.Join(filepath.Dir(c.dbPath), "agents", agent, "agent", openclawAgentDB)
		var err error
		db, err = sql.Open("sqlite", fmt.Sprintf("file:%s?mode=ro&_pragma=busy_timeout(2000)&_pragma=query_only(true)", url.PathEscape(path)))
		if err != nil {
			return
		}
		defer db.Close()
	}
	var cwd string
	err := db.QueryRow(`SELECT json_extract(event_json, '$.cwd') FROM transcript_events
		WHERE session_id=? AND event_json IS NOT NULL AND json_valid(event_json)
		AND json_extract(event_json, '$.type')='session' ORDER BY seq LIMIT 1`, id).Scan(&cwd)
	if err == nil && filepath.IsAbs(cwd) {
		s.Workspace = cwd
		resolved = true
	}
}
