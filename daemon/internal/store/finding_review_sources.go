package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

type reviewSource struct {
	flag model.Flag
	key  string
}

// Read within the deciding/rekeying transaction so a best-effort projection
// failure cannot let an earlier revision decide changed detector evidence.
func reviewSourcesTx(tx *sql.Tx, id string) ([]reviewSource, error) {
	rows, err := tx.Query(`SELECT f.id,COALESCE(f.rule,''),COALESCE(f.severity,0),COALESCE(f.ts,''),COALESCE(f.pid,0),COALESCE(f.agent,''),COALESCE(f.session_id,''),COALESCE(f.workspace,''),COALESCE(f.evidence,'[]'),m.source_key FROM flags f JOIN finding_review_members m ON m.flag_id=f.id WHERE m.review_id=?`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []reviewSource
	for rows.Next() {
		var v reviewSource
		var ts, raw string
		f := &v.flag
		if err = rows.Scan(&f.ID, &f.Rule, &f.Severity, &ts, &f.PID, &f.Agent, &f.SessionID, &f.Workspace, &raw, &v.key); err != nil {
			return nil, err
		}
		f.TS, err = time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return nil, fmt.Errorf("invalid flag timestamp: %w", err)
		}
		if err = json.Unmarshal([]byte(raw), &f.Evidence); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
