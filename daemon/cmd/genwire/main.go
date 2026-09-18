// genwire regenerates web_dist/wire-types.d.ts from the Go wire structs.
// Run from daemon/: go run ./cmd/genwire
package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/cavi-ai/secure-agent/daemon/internal/wiregen"
)

func main() {
	out := filepath.Join("internal", "api", "web_dist", "wire-types.d.ts")
	if err := os.WriteFile(out, []byte(wiregen.Generate()), 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %s", out)
}
