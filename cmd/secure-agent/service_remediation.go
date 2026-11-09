package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func runServiceRemediation(client *http.Client, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("a service operation is required")
	}
	input := map[string]string{}
	confirm := false
	for i := 1; i < len(args); i++ {
		name := args[i]
		if name == "--confirm" {
			if confirm {
				return errors.New("duplicate confirmation argument")
			}
			confirm = true
			continue
		}
		keys := map[string]string{"--service-file": "source", "--preview-id": "id", "--preview-hash": "preview_hash", "--label": "label"}
		key, ok := keys[name]
		if !ok || i+1 >= len(args) {
			return errors.New("invalid local service remediation arguments")
		}
		i++
		if input[key] != "" {
			return errors.New("duplicate remediation argument")
		}
		input[key] = args[i]
	}
	method, path := http.MethodPost, "http://unix/local-services/remediation"
	switch args[0] {
	case "remediate":
		if confirm {
			input["action"] = "apply"
			if len(input) != 3 || input["id"] == "" || input["preview_hash"] == "" {
				return errors.New("apply requires --confirm --preview-id and --preview-hash from the displayed preview")
			}
		} else {
			input["action"] = "preview"
			if len(input) != 2 || input["source"] == "" {
				return errors.New("preview requires --service-file <absolute-plist-path>")
			}
		}
	case "rollback":
		if len(input) != 1 || input["label"] == "" || confirm {
			return errors.New("rollback requires --label <service-label>")
		}
		input["action"] = "rollback"
	case "receipt":
		if len(input) != 1 || input["label"] == "" || confirm {
			return errors.New("receipt requires --label <service-label>")
		}
		method, path = http.MethodGet, "http://unix/local-services/receipt?"+url.Values{"label": {input["label"]}}.Encode()
	default:
		return errors.New("unknown service operation")
	}
	body, _ := json.Marshal(input)
	if method == http.MethodGet {
		body = nil
	}
	bounded := *client
	bounded.Timeout = 150 * time.Second
	code, response := request(&bounded, method, path, string(body))
	if code != 200 {
		return fmt.Errorf("service remediation failed (%d): %s", code, terminalSafe(strings.TrimSpace(response)))
	}
	var value any
	if json.Unmarshal([]byte(response), &value) != nil {
		return errors.New("unreadable remediation response")
	}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
