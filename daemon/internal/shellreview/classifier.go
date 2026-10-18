package shellreview

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/loopback"
)

type answer struct {
	Type          string              `json:"type"`
	Choice        string              `json:"choice"`
	Confidence    *float64            `json:"confidence"`
	Probabilities map[string]*float64 `json:"probabilities"`
}

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
	if a.Type != "choice" || len(a.Probabilities) != len(criteria) {
		return false
	}
	if _, ok := criteria[a.Choice]; !ok {
		return false
	}
	if a.Confidence == nil || math.IsNaN(*a.Confidence) || *a.Confidence < 0 || *a.Confidence > 1 {
		return false
	}
	selected := a.Probabilities[a.Choice]
	if selected == nil {
		return false
	}
	sum := 0.0
	for key := range criteria {
		p, ok := a.Probabilities[key]
		if !ok || p == nil || math.IsNaN(*p) || *p < 0 || *p > 1 || *p > *selected+0.000001 {
			return false
		}
		sum += *p
	}
	// System One choice confidence is normalized relative to a uniform
	// distribution, not the selected probability or a measured accuracy.
	uniform := 1 / float64(len(criteria))
	expectedConfidence := math.Max(0, (*selected-uniform)/(1-uniform))
	// Kev rounds each probability and confidence independently to two decimal
	// places. Account for that documented representation error, while still
	// rejecting invalid distributions and inconsistent confidence values.
	const roundingError = 0.005
	probabilityTolerance := float64(len(criteria))*roundingError + 0.000001
	confidenceTolerance := roundingError + roundingError/(1-uniform) + 0.000001
	return math.Abs(sum-1) <= probabilityTolerance && math.Abs(*a.Confidence-expectedConfidence) <= confidenceTolerance
}
