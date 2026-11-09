package advisor

import (
	"fmt"
	"github.com/cavi-ai/secure-agent/internal/localservice"
	"io"
	"net/http"
	"os/exec"
	"sync"
	"time"
)

// ManagedTransport owns exactly one lazily started model process. Its idle
// timer reaps that process; no model weights are loaded just by enabling it.
type ManagedTransport struct {
	mu               sync.Mutex
	spec             ManagedSpec
	process          *managedProcess
	ready            bool
	cmd              *exec.Cmd
	done             chan struct{}
	timer            *time.Timer
	active           int
	stopping, closed bool
	idle             time.Duration
}

func NewManagedTransport(spec ManagedSpec) (*ManagedTransport, error) {
	resolved, err := managedBinary(spec)
	if err != nil {
		return nil, err
	}
	return &ManagedTransport{spec: resolved, idle: 2 * time.Minute}, nil
}
func (m *ManagedTransport) loaded() bool { m.mu.Lock(); defer m.mu.Unlock(); return m.cmd != nil }

func (m *ManagedTransport) ProtectionStatus() localservice.ManagedRuntime {
	m.mu.Lock()
	defer m.mu.Unlock()
	state := "unloaded"
	if m.closed {
		state = "closed"
	} else if m.stopping {
		state = "stopping"
	} else if m.cmd != nil {
		state = "starting"
		if m.ready {
			state = "running"
		}
	}
	return localservice.ManagedRuntime{State: state, Transport: privateProtocol, Enforcement: "private_transport", Scope: "managed advisor worker only; no TCP listener; other local services are unchanged"}
}

func (m *ManagedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != "POST" || req.URL.Path != "/v1/chat/completions" {
		return nil, fmt.Errorf("managed model accepts inference only")
	}
	for {
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			return nil, fmt.Errorf("managed model is closed")
		}
		if m.stopping {
			done := m.done
			m.mu.Unlock()
			select {
			case <-done:
				continue
			case <-req.Context().Done():
				return nil, req.Context().Err()
			}
		}
		if m.timer != nil {
			m.timer.Stop()
		}
		if m.cmd == nil {
			process, err := LaunchManaged(m.spec)
			if err != nil {
				m.mu.Unlock()
				return nil, err
			}
			cmd := process.cmd
			m.cmd, m.process, m.done, m.ready = cmd, process, make(chan struct{}), false
			done := m.done
			go func() {
				_ = cmd.Wait()
				process.cleanup()
				m.mu.Lock()
				if m.cmd == cmd {
					m.cmd = nil
					m.process = nil
					m.ready = false
					m.stopping = false
				}
				close(done)
				m.mu.Unlock()
			}()
		}
		m.active++
		process := m.process
		m.mu.Unlock()
		finish := func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.active--
			if m.active == 0 && !m.closed && m.cmd != nil {
				m.timer = time.AfterFunc(m.idle, m.expire)
			}
		}
		if !process.waitReady(req.Context(), 5*time.Minute) {
			finish()
			return nil, fmt.Errorf("managed model did not become ready before the request deadline")
		}
		m.mu.Lock()
		if m.process == process {
			m.ready = true
		}
		m.mu.Unlock()
		r := req.Clone(req.Context())
		u := *req.URL
		u.Scheme, u.Host = "http", "127.0.0.1"
		r.URL, r.Host = &u, u.Host
		r.Header = req.Header.Clone()
		r.Header.Set("Content-Type", "application/json")
		resp, err := process.transport.RoundTrip(r)
		if err != nil {
			finish()
			return nil, err
		}
		if resp.Header.Get("X-MLX-Agent-Transport") != privateProtocol {
			resp.Body.Close()
			finish()
			return nil, fmt.Errorf("private model worker protocol missing")
		}
		resp.Body = &managedBody{ReadCloser: resp.Body, finish: finish}
		return resp, nil
	}
}
func (m *ManagedTransport) expire() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == 0 && m.cmd != nil && !m.stopping {
		m.stopping = true
		_ = m.cmd.Cancel()
	}
}
func (m *ManagedTransport) Close() {
	m.mu.Lock()
	m.closed = true
	if m.timer != nil {
		m.timer.Stop()
	}
	cmd, done := m.cmd, m.done
	if cmd != nil {
		_ = cmd.Cancel()
	}
	m.mu.Unlock()
	if done != nil {
		<-done
	}
}

type managedBody struct {
	io.ReadCloser
	once   sync.Once
	finish func()
}

func (b *managedBody) Close() error { err := b.ReadCloser.Close(); b.once.Do(b.finish); return err }
func (b *managedBody) Read(v []byte) (int, error) {
	n, err := b.ReadCloser.Read(v)
	if err != nil {
		b.once.Do(b.finish)
	}
	return n, err
}
