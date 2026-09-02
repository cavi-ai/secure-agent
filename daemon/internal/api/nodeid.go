package api

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// validNodeID accepts exactly the shape LoadNodeID generates: 32 hex chars.
var validNodeID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// LoadNodeID returns the stable per-install fleet identity at path, creating a
// random 128-bit hex id (0600) if none exists yet. The id is not secret — it
// lets a fleet collector tell nodes apart — but it is generated locally and
// never shipped with the code.
func LoadNodeID(path string) string {
	if b, err := os.ReadFile(path); err == nil {
		if id := strings.TrimSpace(string(b)); validNodeID.MatchString(id) {
			NodeID = id
			return id
		}
		log.Printf("nodeid: existing file malformed; regenerating")
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		log.Printf("nodeid: random source failed; fleet id left empty: %v", err)
		return ""
	}
	id := hex.EncodeToString(buf)
	NodeID = id
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err == nil {
		if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
			log.Printf("nodeid: persist failed (id is session-only): %v", err)
		}
	}
	return id
}