package inference

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
)

const maxActiveRequests = 64

func (m *Monitor) begin(endpoint, path, model string, pid int32, sessionID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	active := 0
	for _, r := range m.requests {
		if r.EndedAt == nil {
			active++
		}
	}
	if active >= maxActiveRequests {
		return "", errors.New("local inference tracking capacity reached")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(random[:])
	execution := "unknown"
	if strings.HasSuffix(model, ":cloud") || path == "/v1/systemone" {
		execution = "cloud"
	}
	m.requests = append(m.requests, Request{ID: id, Endpoint: endpoint, Path: path, Model: bounded(model, 256), PID: pid, SessionID: bounded(sessionID, 256), State: "request_in_progress", StartedAt: time.Now().UTC(), Execution: execution})
	return id, nil
}
func (m *Monitor) streaming(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.requests {
		if m.requests[i].ID == id && m.requests[i].EndedAt == nil {
			m.requests[i].State = "streaming"
			return
		}
	}
}
func (m *Monitor) finish(id, state string, status int, usage responseObservation) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.requests {
		if m.requests[i].ID == id {
			r := &m.requests[i]
			now := time.Now().UTC()
			r.EndedAt = &now
			r.State = state
			r.HTTPStatus = status
			r.InputTokens, r.OutputTokens = usage.input, usage.output
			if r.Model == "" {
				r.Model = bounded(usage.model, 256)
			}
			if strings.HasSuffix(r.Model, ":cloud") {
				r.Execution = "cloud"
			}
			r.Parsing = "complete"
			if usage.partial {
				r.Parsing = "partial"
			}
			break
		}
	}
	recent := 0
	for _, r := range m.requests {
		if r.EndedAt != nil {
			recent++
		}
	}
	if recent > maxRequests {
		drop := recent - maxRequests
		kept := m.requests[:0]
		for _, r := range m.requests {
			if drop > 0 && r.EndedAt != nil {
				drop--
				continue
			}
			kept = append(kept, r)
		}
		m.requests = kept
	}
}

func (m *Monitor) GatewayStatus(config GatewayConfig, state string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	info := GatewayInfo{Listen: config.Listen, Upstream: config.Upstream, State: state, Protection: "gateway_authenticated_backend_not_isolated"}
	if state == "listening" {
		_, port, _ := net.SplitHostPort(config.Listen)
		number, _ := strconv.Atoi(port)
		target := "http://" + config.Listen
		m.putServer(Server{Endpoint: target, Runtime: "ollama-gateway", Port: number, Binding: "loopback", Metadata: "authentication_required", ObservedAt: time.Now().UTC(), Models: []Model{}})
	}
	for i := range m.gateways {
		if m.gateways[i].Listen == config.Listen {
			m.gateways[i] = info
			return
		}
	}
	m.gateways = append(m.gateways, info)
}
