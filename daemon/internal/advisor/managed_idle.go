package advisor

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"sync"
	"time"
)

// ManagedTransport owns exactly one lazily started model process. Its idle
// timer reaps that process; no model weights are loaded just by enabling it.
type ManagedTransport struct {
	mu               sync.Mutex
	spec             ManagedSpec
	base             http.RoundTripper
	cmd              *exec.Cmd
	endpoint         string
	done             chan struct{}
	timer            *time.Timer
	active           int
	stopping, closed bool
	idle             time.Duration
}

func NewManagedTransport(spec ManagedSpec) (*ManagedTransport, error) {
	if spec.Bin == "" {
		bin, err := exec.LookPath("mlx_lm.server")
		if err != nil {
			return nil, fmt.Errorf("mlx_lm.server is not installed")
		}
		spec.Bin = bin
	}
	return &ManagedTransport{spec: spec, base: http.DefaultTransport, idle: 2 * time.Minute}, nil
}
func (m *ManagedTransport) loaded() bool { m.mu.Lock(); defer m.mu.Unlock(); return m.cmd != nil }
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
			cmd, ep, err := LaunchManaged(m.spec)
			if err != nil {
				m.mu.Unlock()
				return nil, err
			}
			m.cmd, m.endpoint, m.done = cmd, ep, make(chan struct{})
			done := m.done
			go func() {
				_ = cmd.Wait()
				m.mu.Lock()
				if m.cmd == cmd {
					m.cmd = nil
					m.endpoint = ""
					m.stopping = false
				}
				close(done)
				m.mu.Unlock()
			}()
		}
		m.active++
		ep := m.endpoint
		m.mu.Unlock()
		finish := func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.active--
			if m.active == 0 && !m.closed && m.cmd != nil {
				m.timer = time.AfterFunc(m.idle, m.expire)
			}
		}
		if !WaitReady(req.Context(), ep, 5*time.Minute) {
			finish()
			return nil, fmt.Errorf("managed model did not become ready before the request deadline")
		}
		target, _ := url.Parse(ep)
		r := req.Clone(req.Context())
		u := *req.URL
		u.Scheme, u.Host = target.Scheme, target.Host
		r.URL = &u
		r.Host = target.Host
		resp, err := m.base.RoundTrip(r)
		if err != nil {
			finish()
			return nil, err
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
