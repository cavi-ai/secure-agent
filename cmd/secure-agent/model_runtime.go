package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/cavi-ai/secure-agent/internal/modelruntime"
)

func handleModelRuntime(args []string) {
	if len(args) != 1 || args[0] != "install" {
		fmt.Fprintln(os.Stderr, "usage: secure-agent model-runtime install")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	binary, err := modelruntime.Install(ctx, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, terminalSafe(err.Error()))
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, "Managed model runtime installed:", terminalSafe(binary))
}
