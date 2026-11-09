package modelservice

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/loopback"
	"github.com/cavi-ai/secure-agent/internal/localservice"
)

func (m *Manager) verify(parent context.Context, p *plan) ([]string, error) {
	ctx, cancel := context.WithTimeout(parent, 90*time.Second)
	defer cancel()
	var state jobState
	var err error
	for {
		state, err = inspectJob(ctx, p.preview.Label)
		if err == nil && state.Path == p.preview.Source {
			if err = listenerOwnership(ctx, state.PID, p.preview.Change.Port); err == nil {
				break
			}
		}
		select {
		case <-ctx.Done():
			return nil, errors.New("new service listener ownership could not be verified")
		case <-time.After(500 * time.Millisecond):
		}
	}
	checks := []string{"owned_loopback_listener"}
	client := loopback.Client(75 * time.Second)
	healthPath := "/health"
	if p.preview.Change.Runtime == "ollama" {
		healthPath = "/api/version"
	}
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, p.preview.Endpoint+healthPath, nil)
		response, healthErr := client.Do(req)
		ready := false
		if healthErr == nil {
			ready = response.StatusCode == 200
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 65536))
			response.Body.Close()
		}
		if ready {
			break
		}
		select {
		case <-ctx.Done():
			return nil, errors.New("service did not become ready for authorization verification")
		case <-time.After(250 * time.Millisecond):
		}
	}
	request := func(path, credential, origin, host string) (int, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.preview.Endpoint+path, strings.NewReader(`{"messages":[{"role":"user","content":"Reply OK"}],"max_tokens":1,"stream":false,"temperature":0}`))
		if err != nil {
			return 0, err
		}
		req.Header.Set("Content-Type", "application/json")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if host != "" {
			req.Host = host
		}
		if credential == "valid" {
			if err := localservice.Authorize(req, m.keyPath(p.preview.Label)); err != nil {
				return 0, err
			}
		} else if credential != "" {
			req.Header.Set("Authorization", "Bearer "+credential)
		}
		response, err := client.Do(req)
		if err != nil {
			return 0, errors.New("service authorization verification failed")
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
		if err != nil || len(body) > 65536 {
			return 0, errors.New("service verification response exceeded its limit")
		}
		return response.StatusCode, nil
	}
	refused := func(status int, err error) bool { return err == nil && (status == 401 || status == 403) }
	if p.preview.Change.Scope == "authenticated_inference" {
		admin := "/props"
		if p.preview.Change.Runtime == "mlx" {
			admin = "/_mlx/unload"
		}
		for _, path := range []string{"/v1/chat/completions", admin} {
			if !refused(request(path, "", "", "")) {
				return nil, errors.New("anonymous inference or administrative access was not refused")
			}
			if !refused(request(path, "secure-agent-invalid-key", "", "")) {
				return nil, errors.New("incorrect inference or administrative credential was not refused")
			}
		}
		checks = append(checks, "anonymous_and_wrong_key_inference_refused", "anonymous_and_wrong_key_admin_refused")
	}
	for _, probe := range []struct{ origin, host string }{{"https://secure-agent-probe.invalid", ""}, {"null", ""}, {"", "secure-agent-probe.invalid"}} {
		if !refused(request("/v1/chat/completions", "", probe.origin, probe.host)) {
			return nil, errors.New("foreign browser Origin or Host was not refused")
		}
	}
	checks = append(checks, "foreign_origin_and_host_refused")
	if p.preview.Change.Scope == "authenticated_inference" {
		status, err := request("/v1/chat/completions", "valid", "", "")
		if err != nil || status != http.StatusOK {
			return nil, errors.New("authorized one-token inference did not succeed")
		}
		checks = append(checks, "authorized_one_token_inference")
	}
	current, err := inspectJob(ctx, p.preview.Label)
	if err != nil || current != state {
		return nil, errors.New("service process identity changed during verification")
	}
	if err := listenerOwnership(ctx, current.PID, p.preview.Change.Port); err != nil {
		return nil, err
	}
	binary, err := executableDigest(p.binary)
	if err != nil || binary != p.binarySHA {
		return nil, errors.New("original runtime changed during verification")
	}
	if p.engine != "" {
		value, err := engineIdentity(ctx, p.engine)
		if err != nil || value != p.engineSHA {
			return nil, errors.New("protected runtime changed during verification")
		}
	}
	return append(checks, "no_direct_tcp_backend"), nil
}

func listenerOwnership(ctx context.Context, root, port int) error {
	raw, err := native(ctx, nil, "/bin/ps", "-axo", "pid=,ppid=")
	if err != nil {
		return errors.New("service process family unavailable")
	}
	family := map[int]bool{root: true}
	for pass := 0; pass < 64; pass++ {
		added := false
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				continue
			}
			pid, _ := strconv.Atoi(fields[0])
			parent, _ := strconv.Atoi(fields[1])
			if family[parent] && !family[pid] {
				family[pid] = true
				added = true
			}
		}
		if len(family) > 64 {
			return errors.New("service process family exceeds verification limit")
		}
		if !added {
			break
		}
	}
	inventory := localservice.DiscoverListeners(ctx)
	if inventory.State != "available" || inventory.Truncated {
		return errors.New("listener inventory is incomplete; backend isolation is unverified")
	}
	found := false
	for _, listener := range inventory.Listeners {
		_, number, err := net.SplitHostPort(listener.Address)
		if err != nil {
			return errors.New("listener identity unavailable")
		}
		listenerPort, _ := strconv.Atoi(number)
		if family[listener.PID] {
			if listener.Binding != "loopback" || listenerPort != port {
				return errors.New("service retains an unexpected or exposed direct TCP backend")
			}
			found = true
		} else if listenerPort == port {
			return errors.New("another process owns a listener on the service port")
		}
	}
	if !found {
		return errors.New("expected owned model listener is unavailable")
	}
	return nil
}
