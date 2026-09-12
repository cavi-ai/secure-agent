package main

import (
	"fmt"
	"os"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

func main() {
	p := os.Getenv("HOME") + "/.config/secure-agent/config.yaml"
	d, err := config.Load(p)
	if err != nil {
		fmt.Println("load error:", err)
		return
	}
	fmt.Printf("enabled=%v endpoint=%q model=%q timeout=%v managed=%v\n",
		d.Advisor.Enabled, d.Advisor.Endpoint, d.Advisor.Model, d.Advisor.Timeout, d.Advisor.Managed)
}
