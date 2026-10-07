package collect

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const maxOpencodeSeen = 4096

type opencodeScan struct {
	Floor   int64
	Ceiling int64
	Time    int64
	ID      string
}

type opencodeState struct {
	Version      int
	DB           string
	Watermark    int64
	InitialFloor int64
	Scan         *opencodeScan
	Seen         map[string][sha256.Size]byte
	Order        []string
	Next         int
}

func (c *OpencodeCollector) rememberPart(id, data string) bool {
	hash := sha256.Sum256([]byte(data))
	if c.seen == nil {
		c.seen = make(map[string][sha256.Size]byte)
	}
	if old, ok := c.seen[id]; ok {
		c.seen[id] = hash
		return old != hash
	}
	if len(c.seenOrder) < maxOpencodeSeen {
		c.seenOrder = append(c.seenOrder, id)
	} else {
		delete(c.seen, c.seenOrder[c.seenNext])
		c.seenOrder[c.seenNext] = id
		c.seenNext = (c.seenNext + 1) % maxOpencodeSeen
	}
	c.seen[id] = hash
	return true
}

func (c *OpencodeCollector) loadState() bool {
	if c.StatePath == "" {
		return false
	}
	data, err := os.ReadFile(c.StatePath)
	if err != nil {
		return false
	}
	var st opencodeState
	if json.Unmarshal(data, &st) != nil || st.Version != 1 || st.DB != c.dbPath || len(st.Seen) > maxOpencodeSeen || len(st.Order) > maxOpencodeSeen || st.Next < 0 || st.Next >= maxOpencodeSeen || len(st.Seen) != len(st.Order) {
		return false
	}
	keys := make(map[string]bool, len(st.Order))
	for _, id := range st.Order {
		if _, ok := st.Seen[id]; !ok || keys[id] {
			return false
		}
		keys[id] = true
	}
	if st.Scan != nil && (st.Scan.Floor > st.Scan.Ceiling || st.Scan.Time < st.Scan.Floor || st.Scan.Time > st.Scan.Ceiling) {
		return false
	}
	c.watermark, c.initialFloor, c.scan = st.Watermark, st.InitialFloor, st.Scan
	c.seen, c.seenOrder, c.seenNext = st.Seen, st.Order, st.Next
	c.initialized = true
	return true
}

// The checkpoint carries identities and hashes, never part JSON or content.
func (c *OpencodeCollector) saveState() (err error) {
	if c.StatePath == "" {
		return nil
	}
	if c.OnCheckpointWrite != nil {
		defer func() { c.OnCheckpointWrite(err) }()
	}
	data, err := json.Marshal(opencodeState{Version: 1, DB: c.dbPath, Watermark: c.watermark, InitialFloor: c.initialFloor, Scan: c.scan, Seen: c.seen, Order: c.seenOrder, Next: c.seenNext})
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(c.StatePath), ".opencode-checkpoint-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), c.StatePath); err != nil {
		return fmt.Errorf("save opencode checkpoint: %w", err)
	}
	return nil
}
