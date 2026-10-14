package codex

import (
	"crypto/sha256"
	"encoding/hex"
)

// nativeHandlerID follows Codex's configured-handler identity, which may
// contain a source path. The digest is stable across executions, while raw
// native IDs stay transient. Empty IDs cannot identify a handler.
func nativeHandlerID(id string) string {
	if id == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("secure-agent:codex:handler:v1\x00" + id))
	return "codex-handler:" + hex.EncodeToString(sum[:])
}
