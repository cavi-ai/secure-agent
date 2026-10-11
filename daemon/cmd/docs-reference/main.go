// docs-reference exports canonical route metadata and validates documentation
// YAML examples. It does not load user configuration or contact the daemon.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/cavi-ai/secure-agent/daemon/internal/apiroutes"
	"gopkg.in/yaml.v3"
)

func main() {
	var examples []struct {
		File string `json:"file"`
		Body string `json:"body"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&examples); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, example := range examples {
		var node yaml.Node
		if err := yaml.Unmarshal([]byte(example.Body), &node); err != nil {
			fmt.Fprintf(os.Stderr, "%s: invalid YAML: %v\n", example.File, err)
			os.Exit(1)
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(apiroutes.Table); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
