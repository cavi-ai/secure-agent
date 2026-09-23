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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// Hermes Agent trace collection.
//
// Hermes keeps its sessions in SQLite: <root>/state.db, plus one state.db
// per named profile at <root>/profiles/<name>/state.db, where the root is
// hermes_home, else $HERMES_HOME, else ~/.hermes. sessions records the model,
// billing provider, cwd, git repo root and branch, parent session, start and
// end (REAL epoch seconds) and running token totals; messages records role,
// tool_calls JSON, tool_call_id, tool_name, token_count, finish_reason and a
// REAL epoch timestamp; session_model_usage, when present, records usage per
// model (its columns are read from PRAGMA table_info). This collector polls
// every database the way the openclaw poller reads lcm.db.
//
// Safety rules, because these are another application's live databases:
//   - Opened READ-ONLY (mode=ro, query_only) with a busy timeout; never
//     written, never locked against Hermes.
//   - Watermarked per database on messages.id (INTEGER PRIMARY KEY
//     AUTOINCREMENT) and bounded to maxHermesMessages per poll; a backlog
//     drains over polls. The watermarks persist beside the store.
//   - Content columns (messages.content and reasoning, sessions.title and
//     system_prompt, tool call arguments) are never selected: tool_calls is
//     read inside SQLite through json_each for each call's id and function
//     name only.
//   - A missing database is a silent no-op (one startup line); a schema drift
//     logs once per distinct error and degrades to "not covered".
//
// Trace mapping:
//   - session → session, harness "hermes", workspace = cwd (else the label
//     "hermes:<source>"), repo and branch from git_repo_root/git_branch,
//     parent from parent_session_id; ended at ended_at.
//   - user message → turn (kind 13).
//   - each tool_calls entry of an assistant message → tool_call (kind 12,
//     running); the tool-role message with the same tool_call_id completes
//     it — ok, or error only when its finish_reason says "error" (content is
//     never read) — with the duration between the two timestamps.
//   - model_call (kind 14): with session_model_usage, one per model per
//     session carrying the growth of its totals since the last poll; without
//     it, one per assistant message with token_count (tokens out), the
//     session's input_tokens growth as tokens in, and the session's model and
//     billing provider. Cost is the recorded cost when there is one, else
//     priced from the model id.
//   - A session first read by this daemon run whose messages began before the
//     run's starting watermark has its usage totals taken as a baseline, not
//     emitted: a restart never counts the same tokens twice.

const (
	hermesPollInterval = 5 * time.Second
	// maxHermesMessages bounds messages read per poll per database.
	maxHermesMessages = 200
	// maxHermesOpenCalls bounds the call-start memory used for durations.
	maxHermesOpenCalls = 4096
	// maxHermesLive bounds the sessions re-read each poll for their end and
	// usage; the least recently active are dropped first.
	maxHermesLive = 256
	// hermesLiveWindow drops a session from the re-read set once it has been
	// quiet this long (a crashed session never gets ended_at).
	hermesLiveWindow = 6 * time.Hour
)

// HermesSighting is a Hermes session as its state.db records it.
type HermesSighting struct {
	ID, Workspace, Repo, Branch, ParentID string
	At                                    time.Time
}

// HermesDBStatus is one polled database and its watermark.
type HermesDBStatus struct {
	Path      string `json:"path"`
	Watermark int64  `json:"watermark"`
}

// HermesStatus is the collector's state for the doctor: the root it looks
// under, the databases found there, and the last poll.
type HermesStatus struct {
	Root      string           `json:"root"`
	DBs       []HermesDBStatus `json:"dbs"`
	LastPoll  time.Time        `json:"last_poll"`
	LastError string           `json:"last_error,omitempty"`
}

// HermesCollector polls Hermes Agent's state.db files for trace events.
type HermesCollector struct {
	bus      *bus.Bus
	interval time.Duration

	// Configured is the hermes_home setting; when set it is the root.
	Configured string
	// StatePath, when set, persists the per-database watermarks across
	// daemon restarts.
	StatePath string

	// OnProduce fires after events are published (coverage heartbeat).
	OnProduce func()
	// OnSessionSeen reports a session before any of its events are published.
	OnSessionSeen func(HermesSighting)
	// OnSessionEnded reports a session Hermes recorded an ended_at for.
	OnSessionEnded func(sessionID string, at time.Time)
	// OnPoll, when set, receives the source and watermark after each poll:
	// the database and its watermark when there is one, else the root
	// (the per-database watermarks are in Status).
	OnPoll func(source string, watermark int64)

	loaded    bool
	persisted map[string]int64
	idle      bool // the "not found" line was logged
	dbs       map[string]*hermesDB

	mu     sync.Mutex // guards status, read by the API
	status HermesStatus
}

// hermesDB is the per-database read state.
type hermesDB struct {
	path      string
	watermark int64
	// startMark is the watermark this run began reading from: a session whose
	// first message is past it was born after the run started.
	startMark int64
	lastErr   string // this poll's read failure, for the doctor
	logged    string // the failure last logged; cleared by a clean poll
	noted     map[string]bool
	ended     map[string]bool
	live      map[string]time.Time // session → last activity; re-read each poll
	inputSeen map[string]int64     // session → input_tokens already attributed
	usage     map[string]hermesUsage
	callStart map[string]hermesCall
}

type hermesUsage struct {
	in, out int64
	cost    float64
}

type hermesCall struct {
	at   time.Time
	name string
}

// NewHermesCollector builds the poller.
func NewHermesCollector(b *bus.Bus, interval time.Duration) *HermesCollector {
	if interval <= 0 {
		interval = hermesPollInterval
	}
	return &HermesCollector{bus: b, interval: interval, dbs: map[string]*hermesDB{}}
}

// HermesHome picks Hermes's root: the configured path, else $HERMES_HOME,
// else ~/.hermes. "" when none is known.
func HermesHome(configured string, getenv func(string) string, home string) string {
	if configured != "" {
		return configured
	}
	if v := getenv("HERMES_HOME"); v != "" {
		return v
	}
	if home != "" {
		return filepath.Join(home, ".hermes")
	}
	return ""
}

// hermesDBPaths lists the databases under root: state.db first, then each
// profile's state.db in name order.
func hermesDBPaths(root string) []string {
	if root == "" {
		return nil
	}
	isFile := func(p string) bool {
		fi, err := os.Stat(p)
		return err == nil && !fi.IsDir()
	}
	var out []string
	if p := filepath.Join(root, "state.db"); isFile(p) {
		out = append(out, p)
	}
	profiles, _ := filepath.Glob(filepath.Join(root, "profiles", "*", "state.db"))
	sort.Strings(profiles)
	for _, p := range profiles {
		if isFile(p) {
			out = append(out, p)
		}
	}
	return out
}

// Status reports the collector's state; safe from any goroutine.
func (c *HermesCollector) Status() HermesStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.status
	st.DBs = append([]HermesDBStatus(nil), c.status.DBs...)
	return st
}

// Run polls until ctx is done. Never errors the supervisor.
func (c *HermesCollector) Run(ctx context.Context) error {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		if n := c.pollOnce(); n > 0 && c.OnProduce != nil {
			c.OnProduce()
		}
		if c.OnPoll != nil {
			st := c.Status()
			if len(st.DBs) == 1 {
				c.OnPoll(st.DBs[0].Path, st.DBs[0].Watermark)
			} else {
				c.OnPoll(st.Root, 0)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// pollOnce reads every database under the root and returns how many events
// were published. The root and its profiles are re-listed each poll: Hermes
// may be installed, or a profile added, after the daemon starts.
func (c *HermesCollector) pollOnce() int {
	if !c.loaded {
		c.loaded = true
		c.loadState()
	}
	home, _ := os.UserHomeDir()
	root := HermesHome(c.Configured, os.Getenv, home)
	paths := hermesDBPaths(root)
	if len(paths) == 0 && !c.idle {
		c.idle = true
		log.Printf("hermes: state.db not found, collector idle (%s)", root)
	}

	published := 0
	var errs []string
	dbs := make([]HermesDBStatus, 0, len(paths))
	for _, p := range paths {
		d := c.db(p)
		published += c.pollDB(d)
		if d.lastErr != "" {
			errs = append(errs, p+": "+d.lastErr)
		}
		dbs = append(dbs, HermesDBStatus{Path: p, Watermark: d.watermark})
	}
	c.mu.Lock()
	c.status = HermesStatus{Root: root, DBs: dbs, LastPoll: time.Now(), LastError: strings.Join(errs, "; ")}
	c.mu.Unlock()
	return published
}

// db returns the read state for path, created on first sight at its
// persisted watermark.
func (c *HermesCollector) db(path string) *hermesDB {
	if d, ok := c.dbs[path]; ok {
		return d
	}
	wm := c.persisted[path]
	d := &hermesDB{
		path: path, watermark: wm, startMark: wm,
		noted: map[string]bool{}, ended: map[string]bool{}, live: map[string]time.Time{},
		inputSeen: map[string]int64{}, usage: map[string]hermesUsage{}, callStart: map[string]hermesCall{},
	}
	c.dbs[path] = d
	log.Printf("hermes: polling %s from message %d", path, wm)
	return d
}

func openHermesReadOnly(path string) (*sql.DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=busy_timeout(2000)&_pragma=query_only(true)", url.PathEscape(path))
	return sql.Open("sqlite", dsn)
}

// hermesCols is a table's column set, from PRAGMA table_info.
type hermesCols map[string]bool

func hermesTableColumns(db *sql.DB, table string) (hermesCols, error) {
	rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols := hermesCols{}
	for rows.Next() {
		var name string
		if rows.Scan(&name) == nil {
			cols[name] = true
		}
	}
	return cols, rows.Err()
}

// col is alias.name when the column exists, else SQL NULL.
func (cols hermesCols) col(alias, name string) string {
	if cols[name] {
		return alias + "." + name
	}
	return "NULL"
}

// hermesRow is one message × tool-call row of a poll. No content column.
type hermesRow struct {
	msgID                int64
	sessionID, role      string
	ts                   float64
	toolCallID, toolName string
	tokens               int64
	finish               string
	callID, callName     string
}

// hermesSession is a sessions row. No content column.
type hermesSession struct {
	source, model, provider, parent string
	startedAt                       float64
	endedAt                         sql.NullFloat64
	cwd, repoRoot, branch           string
	inputTokens                     int64
	firstMsg, lastMsg               int64
}

// fail records a read failure, logging it once until a clean poll.
func (d *hermesDB) fail(what string, err error) {
	msg := what + ": " + err.Error()
	if msg != d.logged {
		log.Printf("hermes: %s: %s (schema drift?)", d.path, msg)
		d.logged = msg
	}
	d.lastErr = msg
}

// pollDB reads one database: the next batch of messages, the sessions they
// and the live set belong to, usage totals, and ends.
func (c *HermesCollector) pollDB(d *hermesDB) int {
	d.lastErr = ""
	db, err := openHermesReadOnly(d.path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			d.fail("open", err)
		}
		return 0
	}
	defer db.Close()

	msgCols, err := hermesTableColumns(db, "messages")
	if err == nil && !(msgCols["id"] && msgCols["session_id"] && msgCols["role"] && msgCols["timestamp"]) {
		err = errors.New("messages lacks id, session_id, role or timestamp")
	}
	if err != nil {
		d.fail("messages", err)
		return 0
	}
	sessCols, err := hermesTableColumns(db, "sessions")
	if err == nil && !sessCols["id"] {
		err = errors.New("sessions lacks id")
	}
	if err != nil {
		d.fail("sessions", err)
		return 0
	}
	usageCols, _ := hermesTableColumns(db, "session_model_usage")
	usageMode := usageCols["session_id"] && usageCols["model"] && (usageCols["input_tokens"] || usageCols["output_tokens"])

	rows, err := c.readMessages(db, d, msgCols)
	if err != nil {
		d.fail("messages query", err)
		return 0
	}
	// Sessions to read: those in this batch, then the live set.
	var ids []string
	inBatch := map[string]bool{}
	lastTok := map[string]int64{} // session → last assistant message with tokens
	for _, r := range rows {
		if r.sessionID != "" && !inBatch[r.sessionID] {
			inBatch[r.sessionID] = true
			ids = append(ids, r.sessionID)
		}
		if r.role == "assistant" && r.tokens > 0 {
			lastTok[r.sessionID] = r.msgID
		}
	}
	for id := range d.live {
		if !inBatch[id] {
			ids = append(ids, id)
		}
	}
	sessions, err := readHermesSessions(db, sessCols, ids)
	if err != nil {
		d.fail("sessions query", err)
		return 0
	}

	published := 0
	publish := func(e event.Event) {
		c.bus.Publish(e)
		published++
	}
	var lastMsg int64
	for _, r := range rows {
		if r.msgID > d.watermark {
			d.watermark = r.msgID
		}
		if r.sessionID == "" {
			continue
		}
		ts := hermesTime(r.ts)
		c.note(d, r.sessionID, sessions[r.sessionID], ts)
		d.live[r.sessionID] = time.Now()
		first := r.msgID != lastMsg
		lastMsg = r.msgID
		for _, e := range c.rowEvents(d, r, ts, first, usageMode, sessions[r.sessionID], lastTok[r.sessionID] == r.msgID) {
			publish(e)
		}
	}
	if usageMode {
		for _, e := range c.usageEvents(db, d, usageCols, sessions) {
			publish(e)
		}
	}
	c.endSessions(d, sessions)
	c.pruneLive(d)
	if d.lastErr == "" {
		d.logged = ""
	}
	if published > 0 || len(rows) > 0 {
		c.saveState()
	}
	return published
}

func (c *HermesCollector) readMessages(db *sql.DB, d *hermesDB, cols hermesCols) ([]hermesRow, error) {
	calls := cols.col("m", "tool_calls")
	q := fmt.Sprintf(`
SELECT m.id, COALESCE(m.session_id, ''), COALESCE(m.role, ''), COALESCE(m.timestamp, 0),
       COALESCE(%s, ''), COALESCE(%s, ''), COALESCE(%s, 0), COALESCE(%s, ''),
       COALESCE(CASE WHEN j.type = 'object' THEN COALESCE(json_extract(j.value, '$.id'), json_extract(j.value, '$.call_id')) END, ''),
       COALESCE(CASE WHEN j.type = 'object' THEN COALESCE(json_extract(j.value, '$.function.name'), json_extract(j.value, '$.name')) END, '')
FROM messages m
LEFT JOIN json_each(CASE WHEN json_valid(%[5]s) AND json_type(%[5]s) = 'array' THEN %[5]s ELSE '[]' END) j
WHERE m.id IN (SELECT id FROM messages WHERE id > ? ORDER BY id LIMIT ?)
ORDER BY m.id, j.key`,
		cols.col("m", "tool_call_id"), cols.col("m", "tool_name"), cols.col("m", "token_count"), cols.col("m", "finish_reason"), calls)
	rows, err := db.Query(q, d.watermark, maxHermesMessages)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []hermesRow
	for rows.Next() {
		var r hermesRow
		if err := rows.Scan(&r.msgID, &r.sessionID, &r.role, &r.ts, &r.toolCallID, &r.toolName,
			&r.tokens, &r.finish, &r.callID, &r.callName); err != nil {
			continue
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		log.Printf("hermes: %s: cursor error (partial poll): %v", d.path, err)
	}
	return out, nil
}

func readHermesSessions(db *sql.DB, cols hermesCols, ids []string) (map[string]hermesSession, error) {
	out := map[string]hermesSession{}
	if len(ids) == 0 {
		return out, nil
	}
	q := fmt.Sprintf(`
SELECT s.id, COALESCE(%s, ''), COALESCE(%s, ''), COALESCE(%s, ''), COALESCE(%s, ''),
       COALESCE(%s, 0), %s, COALESCE(%s, ''), COALESCE(%s, ''), COALESCE(%s, ''), COALESCE(%s, 0),
       COALESCE((SELECT MIN(id) FROM messages WHERE session_id = s.id), 0),
       COALESCE((SELECT MAX(id) FROM messages WHERE session_id = s.id), 0)
FROM sessions s WHERE s.id IN (?%s)`,
		cols.col("s", "source"), cols.col("s", "model"), cols.col("s", "billing_provider"), cols.col("s", "parent_session_id"),
		cols.col("s", "started_at"), cols.col("s", "ended_at"), cols.col("s", "cwd"), cols.col("s", "git_repo_root"),
		cols.col("s", "git_branch"), cols.col("s", "input_tokens"), strings.Repeat(", ?", len(ids)-1))
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var s hermesSession
		if rows.Scan(&id, &s.source, &s.model, &s.provider, &s.parent, &s.startedAt, &s.endedAt,
			&s.cwd, &s.repoRoot, &s.branch, &s.inputTokens, &s.firstMsg, &s.lastMsg) == nil {
			out[id] = s
		}
	}
	return out, rows.Err()
}

// note reports a session once per run, before its first event.
func (c *HermesCollector) note(d *hermesDB, id string, s hermesSession, ts time.Time) {
	if d.noted[id] {
		return
	}
	d.noted[id] = true
	if c.OnSessionSeen == nil {
		return
	}
	at := ts
	if s.startedAt > 0 {
		at = hermesTime(s.startedAt)
	}
	sg := HermesSighting{ID: id, Workspace: s.cwd, Branch: s.branch, ParentID: s.parent, At: at}
	if sg.Workspace == "" {
		sg.Workspace = "hermes"
		if s.source != "" {
			sg.Workspace = "hermes:" + s.source
		}
	}
	if s.repoRoot != "" {
		sg.Repo = filepath.Base(s.repoRoot)
	}
	c.OnSessionSeen(sg)
}

// bornThisRun reports whether a session's first message is past the
// watermark this run started from — its totals are all new to this run.
func (d *hermesDB) bornThisRun(s hermesSession) bool {
	return s.firstMsg > d.startMark
}

// rowEvents maps one message × tool-call row to trace events. first is true
// for the message's first row; lastTok marks the session's last assistant
// message with tokens in this batch, which carries its input growth.
func (c *HermesCollector) rowEvents(d *hermesDB, r hermesRow, ts time.Time, first, usageMode bool, s hermesSession, lastTok bool) []event.Event {
	var out []event.Event
	if r.role == "assistant" && r.callName != "" {
		if r.callID != "" {
			if len(d.callStart) >= maxHermesOpenCalls {
				d.callStart = map[string]hermesCall{}
			}
			d.callStart[r.sessionID+"\x00"+r.callID] = hermesCall{at: ts, name: r.callName}
		}
		out = append(out, event.Event{
			Kind: event.KindToolCall, TS: ts, SessionID: r.sessionID,
			CallID: r.callID, ToolName: r.callName, ToolStatus: "running",
		})
	}
	if !first {
		return out
	}
	switch {
	case r.role == "user":
		out = append(out, event.Event{Kind: event.KindTurn, TS: ts, SessionID: r.sessionID})
	case r.role == "tool" && r.toolCallID != "":
		status := "ok"
		if strings.EqualFold(r.finish, "error") {
			status = "error"
		}
		start, name := ts, r.toolName
		var durMs int64
		key := r.sessionID + "\x00" + r.toolCallID
		if call, ok := d.callStart[key]; ok {
			delete(d.callStart, key)
			if name == "" {
				name = call.name
			}
			if !ts.Before(call.at) {
				start, durMs = call.at, ts.Sub(call.at).Milliseconds()
			}
		}
		out = append(out, event.Event{
			Kind: event.KindToolCall, TS: start, SessionID: r.sessionID,
			CallID: r.toolCallID, ToolName: name, ToolStatus: status, DurationMs: durMs,
		})
	case r.role == "assistant" && r.tokens > 0 && !usageMode:
		var in int64
		if lastTok {
			prev, known := d.inputSeen[r.sessionID]
			if !known && !d.bornThisRun(s) {
				prev = s.inputTokens
			}
			if s.inputTokens > prev {
				in = s.inputTokens - prev
			}
			d.inputSeen[r.sessionID] = max(prev, s.inputTokens)
		}
		out = append(out, event.Event{
			Kind: event.KindModelCall, TS: ts, SessionID: r.sessionID,
			Model: s.model, Provider: s.provider, TokensIn: in, TokensOut: r.tokens,
			CostUSD: ModelCostUSD(s.model, in, r.tokens),
		})
	}
	return out
}

// usageEvents emits, per session and model, the growth of its
// session_model_usage totals since the last poll.
func (c *HermesCollector) usageEvents(db *sql.DB, d *hermesDB, cols hermesCols, sessions map[string]hermesSession) []event.Event {
	if len(sessions) == 0 {
		return nil
	}
	cost := "NULL"
	for _, name := range []string{"actual_cost_usd", "estimated_cost_usd", "cost_usd"} {
		if cols[name] {
			cost = "u." + name
			break
		}
	}
	ids := make([]string, 0, len(sessions))
	for id := range sessions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	q := fmt.Sprintf(`
SELECT u.session_id, COALESCE(u.model, ''), COALESCE(%s, ''),
       COALESCE(SUM(%s), 0), COALESCE(SUM(%s), 0), SUM(%[4]s), COUNT(%[4]s)
FROM session_model_usage u WHERE u.session_id IN (?%[5]s)
GROUP BY u.session_id, u.model ORDER BY u.session_id, u.model`,
		cols.col("u", "billing_provider"), cols.col("u", "input_tokens"), cols.col("u", "output_tokens"), cost,
		strings.Repeat(", ?", len(ids)-1))
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := db.Query(q, args...)
	if err != nil {
		d.fail("usage query", err)
		return nil
	}
	defer rows.Close()
	var out []event.Event
	for rows.Next() {
		var sid, model, provider string
		var cur hermesUsage
		var recorded sql.NullFloat64
		var costRows int64
		if rows.Scan(&sid, &model, &provider, &cur.in, &cur.out, &recorded, &costRows) != nil || model == "" {
			continue
		}
		cur.cost = recorded.Float64
		key := sid + "\x00" + model
		prev, known := d.usage[key]
		d.usage[key] = cur
		if !known && !d.bornThisRun(sessions[sid]) {
			continue // baseline: counted before this run
		}
		din, dout := max(cur.in-prev.in, 0), max(cur.out-prev.out, 0)
		dcost := cur.cost - prev.cost
		if costRows == 0 || dcost <= 0 {
			dcost = ModelCostUSD(model, din, dout)
		}
		if din == 0 && dout == 0 {
			continue
		}
		if provider == "" {
			provider = sessions[sid].provider
		}
		ts := time.Now().UTC()
		if s := sessions[sid]; s.endedAt.Valid {
			ts = hermesTime(s.endedAt.Float64)
		}
		out = append(out, event.Event{
			Kind: event.KindModelCall, TS: ts, SessionID: sid,
			Model: model, Provider: provider, TokensIn: din, TokensOut: dout, CostUSD: dcost,
		})
	}
	if err := rows.Err(); err != nil {
		log.Printf("hermes: %s: usage cursor error: %v", d.path, err)
	}
	return out
}

// endSessions ends each noted session Hermes gave an ended_at, once all of
// its messages have been read. Once per session per daemon run.
func (c *HermesCollector) endSessions(d *hermesDB, sessions map[string]hermesSession) {
	for id, s := range sessions {
		if !s.endedAt.Valid || !d.noted[id] || d.ended[id] || s.lastMsg > d.watermark {
			continue
		}
		d.ended[id] = true
		delete(d.live, id)
		if c.OnSessionEnded != nil {
			c.OnSessionEnded(id, hermesTime(s.endedAt.Float64))
		}
	}
}

// pruneLive drops sessions quiet past hermesLiveWindow, then the least
// recently active beyond maxHermesLive.
func (c *HermesCollector) pruneLive(d *hermesDB) {
	now := time.Now()
	for id, at := range d.live {
		if now.Sub(at) > hermesLiveWindow {
			delete(d.live, id)
		}
	}
	for len(d.live) > maxHermesLive {
		oldest, first := "", time.Time{}
		for id, at := range d.live {
			if oldest == "" || at.Before(first) {
				oldest, first = id, at
			}
		}
		delete(d.live, oldest)
	}
}

// hermesTime reads a REAL epoch-seconds timestamp as UTC; an unset value is
// "now" rather than 1970.
func hermesTime(sec float64) time.Time {
	if sec <= 0 {
		return time.Now().UTC()
	}
	return time.Unix(0, int64(sec*1e9)).UTC()
}

// hermesState is the persisted per-database watermarks.
type hermesState struct {
	DBs map[string]int64 `json:"dbs"`
}

func (c *HermesCollector) loadState() {
	c.persisted = map[string]int64{}
	if c.StatePath == "" {
		return
	}
	data, err := os.ReadFile(c.StatePath)
	if err != nil {
		return
	}
	var st hermesState
	if json.Unmarshal(data, &st) == nil {
		for p, wm := range st.DBs {
			if wm > 0 {
				c.persisted[p] = wm
			}
		}
	}
}

func (c *HermesCollector) saveState() {
	if c.StatePath == "" {
		return
	}
	st := hermesState{DBs: map[string]int64{}}
	for p, wm := range c.persisted {
		st.DBs[p] = wm
	}
	for p, d := range c.dbs {
		st.DBs[p] = d.watermark
	}
	data, err := json.Marshal(st)
	if err != nil {
		return
	}
	tmp := c.StatePath + ".tmp"
	if os.WriteFile(tmp, data, 0o600) == nil {
		_ = os.Rename(tmp, c.StatePath)
	}
}
