package shellreview

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/decision"
	"github.com/cavi-ai/secure-agent/daemon/internal/loopback"
)

type answer = decision.Answer

func (s *Service) classify(parent context.Context, command, cwd string) (answer, string) {
	// Hook-reported permissions and agent rationalizations cannot establish
	// safety. Only the action and its working directory enter this model.
	state := "Working directory: " + cwd + "\nShell command:\n" + command
	body, _ := json.Marshal(map[string]any{
		"model": s.cfg.Model, "state": state,
		"questions": map[string]any{"risk": map[string]any{
			"type": "choice", "criteria": criteria,
			"instructions": policy.Instructions,
		}},
	})
	if len(body) > 32768 {
		return answer{}, "evidence_too_large"
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(s.cfg.TimeoutMS)*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(s.cfg.Endpoint, "/")+"/v1/systemone", bytes.NewReader(body))
	if err != nil {
		return answer{}, "model_unavailable"
	}
	req.Header.Set("Content-Type", "application/json")
	client := loopback.Client(time.Duration(s.cfg.TimeoutMS) * time.Millisecond)
	// Never inherit HTTP_PROXY. Pin localhost instead of trusting DNS, and
	// refuse redirects through loopback.Client.
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if strings.EqualFold(host, "localhost") {
			host = "127.0.0.1"
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return nil, &net.AddrError{Err: "non-loopback model", Addr: "[REDACTED]"}
		}
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(host, port))
	}}
	defer transport.CloseIdleConnections()
	client.Transport = transport
	resp, err := client.Do(req)
	if err != nil {
		return answer{}, "model_unavailable"
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return answer{}, "model_unavailable"
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32769))
	if err != nil || len(data) > 32768 {
		return answer{}, "invalid_response"
	}
	var output struct {
		Answers   map[string]answer `json:"answers"`
		Truncated bool              `json:"truncated"`
	}
	if json.Unmarshal(data, &output) != nil || output.Truncated || len(output.Answers) != 1 {
		return answer{}, "invalid_response"
	}
	a, ok := output.Answers["risk"]
	if !ok || !validAnswer(a) {
		return answer{}, "invalid_response"
	}
	return a, ""
}

func validAnswer(a answer) bool {
	choices := make([]string, 0, len(criteria))
	for key := range criteria {
		choices = append(choices, key)
	}
	return decision.Valid(a, choices)
}
