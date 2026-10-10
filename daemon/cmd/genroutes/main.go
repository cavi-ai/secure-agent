package main

import (
	"flag"
	"log"
	"os"

	"github.com/cavi-ai/secure-agent/daemon/internal/apiroutes"
	"github.com/cavi-ai/secure-agent/daemon/internal/routegen"
)

func main() {
	out := flag.String("out", "daemon/internal/api/routes_generated.go", "generated API binding path")
	flag.Parse()
	src, err := routegen.Generate(apiroutes.Table)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, src, 0o644); err != nil {
		log.Fatal(err)
	}
}
