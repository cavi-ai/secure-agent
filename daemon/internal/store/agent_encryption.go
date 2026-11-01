package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"strings"
)

var agentTables = []string{"sysagent_messages", "sysagent_plans", "sysagent_runs", "sysagent_sessions", "sysagent_memory"}

func prepareAgentSchema(db *sql.DB) error {
	for _, table := range agentTables {
		rows, err := db.Query("PRAGMA table_info(" + table + ")")
		if err != nil {
			return err
		}
		found := false
		for rows.Next() {
			var cid, notnull, pk int
			var name, typ string
			var def any
			if err = rows.Scan(&cid, &name, &typ, &notnull, &def, &pk); err != nil {
				rows.Close()
				return err
			}
			found = found || name == "meta"
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if !found {
			if _, err = db.Exec("ALTER TABLE " + table + " ADD COLUMN meta TEXT NOT NULL DEFAULT '{}'"); err != nil {
				return err
			}
		}
		// Legacy rows predate encrypted bodies. Never apply JSON functions to
		// ciphertext, nor copy message content into the metadata index.
		if table == "sysagent_messages" {
			_, err = db.Exec(`UPDATE sysagent_messages SET meta=json_object('role',json_extract(body,'$.role'),'origin',COALESCE(json_extract(body,'$.origin'),''),'review_state',COALESCE(json_extract(body,'$.review_state'),'')) WHERE meta='{}' AND json_valid(body)`)
			if err != nil {
				return err
			}
		}
	}
	_, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_sysagent_memory_scope ON sysagent_memory(json_extract(meta,'$.scope'),id)`)
	if err != nil {
		return err
	}
	return nil
}

func agentAAD(table string, id int64, meta string) []byte {
	return []byte(fmt.Sprintf("secure-agent/v1/%s/%d/%s", table, id, meta))
}
func sealAgent(a cipher.AEAD, table string, id int64, meta string, body []byte) string {
	// SealWithRandomNonce prepends its random nonce; never derive it from IDs.
	return "enc:v1:" + base64.RawStdEncoding.EncodeToString(a.Seal(nil, nil, body, agentAAD(table, id, meta)))
}
func openAgent(a cipher.AEAD, table string, id int64, meta, body string) ([]byte, error) {
	if !strings.HasPrefix(body, "enc:v1:") {
		return nil, fmt.Errorf("agent record is not encrypted")
	}
	if a == nil {
		return nil, fmt.Errorf("agent history is locked")
	}
	data, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(body, "enc:v1:"))
	if err != nil {
		return nil, err
	}
	return a.Open(nil, nil, data, agentAAD(table, id, meta))
}
func (s *Store) sealAgentRow(table string, id int64, meta string, body []byte) (string, error) {
	if s.agentLocked {
		return "", fmt.Errorf("agent history is locked")
	}
	if s.agentCipher == nil {
		return string(body), nil
	} // Non-persistent test stores.
	return sealAgent(s.agentCipher, table, id, meta, body), nil
}
func (s *Store) openAgentRow(table string, id int64, meta, body string) ([]byte, error) {
	if s.agentLocked {
		return nil, fmt.Errorf("agent history is locked")
	}
	if s.agentCipher == nil && !strings.HasPrefix(body, "enc:") {
		return []byte(body), nil
	}
	return openAgent(s.agentCipher, table, id, meta, body)
}

// LockAgentHistory prevents a keystore failure from falling back to plaintext.
func (s *Store) LockAgentHistory() {
	s.agentCryptoMu.Lock()
	defer s.agentCryptoMu.Unlock()
	s.agentLocked = true
}

// EnableAgentEncryption migrates existing redacted history atomically. Call
// before the agent is exposed. Metadata is authenticated with each record.
func (s *Store) EnableAgentEncryption(key []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agentCryptoMu.Lock()
	defer s.agentCryptoMu.Unlock()
	s.agentLocked = true
	if len(key) != 32 {
		return fmt.Errorf("history requires a 256-bit key")
	}
	s.agentIndexKey = sha256.Sum256(append([]byte("secure-agent-memory-index-v1/"), key...))
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	a, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, table := range agentTables {
		rows, err := tx.Query("SELECT id,body,meta FROM " + table)
		if err != nil {
			return err
		}
		type entry struct {
			id         int64
			body, meta string
		}
		var entries []entry
		for rows.Next() {
			var e entry
			if err = rows.Scan(&e.id, &e.body, &e.meta); err != nil {
				rows.Close()
				return err
			}
			entries = append(entries, e)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, e := range entries {
			body := []byte(e.body)
			if strings.HasPrefix(e.body, "enc:") {
				body, err = openAgent(a, table, e.id, e.meta, e.body)
				if err != nil {
					return fmt.Errorf("encrypted agent history could not be unlocked")
				}
			}
			meta := s.agentMetadata(table, body)
			if _, err = tx.Exec("UPDATE "+table+" SET body=?,meta=? WHERE id=?", sealAgent(a, table, e.id, meta, body), meta, e.id); err != nil {
				return err
			}
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.agentCipher = a
	s.agentLocked = false
	// Expunge superseded WAL frames when no reader is holding them. This is
	// not a promise of forensic erasure of backups or filesystem snapshots.
	_, err = s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	return err
}
