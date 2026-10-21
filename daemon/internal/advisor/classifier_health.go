package advisor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/loopback"
)

type ClassifierHealth struct {
	Configured  bool      `json:"configured"`
	State       string    `json:"state"`
	Model       string    `json:"model,omitempty"`
	Attempts    uint64    `json:"attempts"`
	Unavailable uint64    `json:"unavailable"`
	LastUsed    time.Time `json:"last_used,omitzero"`
	LastSuccess time.Time `json:"last_success,omitzero"`
	LastChoice  string    `json:"last_choice,omitempty"`
	DurationMS  int64     `json:"duration_ms"`
	Purpose     string    `json:"purpose"`
}

// ClassifierStatus probes model-list availability only, at most once per
// thirty seconds. It never warms the classifier or claims inference quality.
func (s *Subscriber) ClassifierStatus(ctx context.Context) ClassifierHealth {
	if s == nil {
		return ClassifierHealth{State: "off"}
	}
	s.mu.Lock()
	h := s.classifier
	h.Configured = s.cfg.ClassifierEndpoint != ""
	h.Model = s.cfg.ClassifierModel
	h.Purpose = "evidence routing; not an enforcement verdict"
	if !h.Configured {
		s.mu.Unlock()
		h.State = "off"
		return h
	}
	if time.Since(s.classifierProbe) < 30*time.Second {
		s.mu.Unlock()
		return h
	}
	s.classifierProbe = time.Now()
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(s.cfg.ClassifierEndpoint, "/")+"/v1/models", nil)
	resp, err := loopback.Client(time.Second).Do(req)
	state := "unavailable"
	if err == nil {
		defer resp.Body.Close()
		var out struct {
			Data []struct {
				ID      string
				Aliases []string
			}
			Models []struct {
				ID      string
				Aliases []string
			}
		}
		if resp.StatusCode == 200 && json.NewDecoder(io.LimitReader(resp.Body, 32768)).Decode(&out) == nil {
			model := s.cfg.ClassifierModel
			if model == "" {
				model = "kev-latest"
			}
			rows := append(out.Data, out.Models...)
			for _, m := range rows {
				if m.ID == model {
					state = "connected"
				}
				for _, alias := range m.Aliases {
					if alias == model {
						state = "connected"
					}
				}
			}
		}
	}
	s.mu.Lock()
	s.classifier.State = state
	h = s.classifier
	s.mu.Unlock()
	h.Configured = true
	h.Model = s.cfg.ClassifierModel
	h.Purpose = "evidence routing; not an enforcement verdict"
	return h
}
