// Package localservice assesses HTTP metadata on explicitly selected local
// model endpoints. It does not authenticate, generate, configure or enforce.
package localservice

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	MaxEndpoints = 16
	probeOrigin  = "https://secure-agent-probe.invalid"
	maxBody      = 64 * 1024
)

// Report contains observations of metadata routes, never a service-wide
// authentication verdict or a successful browser attack claim.
type Report struct {
	GeneratedAt time.Time    `json:"generated_at"`
	Scope       string       `json:"scope"`
	Enforcement string       `json:"enforcement"`
	Services    []Assessment `json:"services"`
}

type Assessment struct {
	Endpoint    string   `json:"endpoint"`
	Metadata    Probe    `json:"metadata"`
	CrossOrigin Probe    `json:"cross_origin"`
	ForeignHost Probe    `json:"foreign_host"`
	Findings    []string `json:"findings"`
	Enforcement string   `json:"enforcement"`
}

// Probe retains only a response classification, status, and whether CORS
// advertises sharing with the synthetic origin. No response body is retained.
type Probe struct {
	State   string `json:"state"`
	Status  int    `json:"http_status,omitempty"`
	Sharing string `json:"sharing,omitempty"`
}

// DefaultEndpoints are candidates, not an inventory of every local listener.
func DefaultEndpoints() []string {
	return []string{"http://127.0.0.1:11434", "http://127.0.0.1:8080", "http://127.0.0.1:8799", "http://127.0.0.1:8081", "http://127.0.0.1:1234", "http://127.0.0.1:8084"}
}

// Assess checks at most 16 endpoints with four concurrent workers and a
// four-second overall deadline. All targets are validated before any request.
func Assess(ctx context.Context, endpoints []string) (Report, error) {
	report := Report{GeneratedAt: time.Now().UTC(), Scope: "selected loopback model metadata routes only; listener inventory, inference and administrative routes are not assessed", Enforcement: "not_assessed", Services: []Assessment{}}
	if len(endpoints) == 0 || len(endpoints) > MaxEndpoints {
		return report, errors.New("select between 1 and 16 loopback endpoints")
	}
	targets := []*url.URL{}
	seen := map[string]bool{}
	for _, endpoint := range endpoints {
		u, err := endpointURL(endpoint)
		if err != nil {
			return report, err
		}
		if !seen[u.String()] {
			seen[u.String()] = true
			targets = append(targets, u)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	transport := &http.Transport{DialContext: dialLoopback, DisableKeepAlives: true, MaxResponseHeaderBytes: 16 * 1024}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 500 * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	report.Services = make([]Assessment, len(targets))
	var wg sync.WaitGroup
	slots := make(chan struct{}, 4)
	for i, u := range targets {
		wg.Go(func() {
			slots <- struct{}{}
			defer func() { <-slots }()
			report.Services[i] = assess(ctx, client, u)
		})
	}
	wg.Wait()
	return report, nil
}

func endpointURL(endpoint string) (*url.URL, error) {
	u, err := url.Parse(endpoint)
	if err != nil || len(endpoint) > 2048 || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		(u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.Opaque != "" {
		return nil, errors.New("endpoint must be a loopback HTTP base URL without credentials, query or fragment")
	}
	host := strings.ToLower(u.Hostname())
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, errors.New("endpoint must use localhost or a literal loopback address")
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, errors.New("endpoint port must be between 1 and 65535")
		}
		u.Host = net.JoinHostPort(host, strconv.Itoa(n))
	} else {
		u.Host = host
		if strings.Contains(host, ":") {
			u.Host = "[" + host + "]"
		}
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u, nil
}

// No DNS lookup or environment proxy may move a probe off this machine.
// localhost tries both literal address families; neither goes through DNS.
func dialLoopback(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("invalid loopback address")
	}
	hosts := []string{host}
	if host == "localhost" {
		hosts = []string{"127.0.0.1", "::1"}
	}
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			return nil, errors.New("non-loopback dial refused")
		}
		var conn net.Conn
		conn, err = (&net.Dialer{Timeout: 300 * time.Millisecond}).DialContext(ctx, network, net.JoinHostPort(host, port))
		if err == nil {
			return conn, nil
		}
	}
	return nil, err
}

func assess(ctx context.Context, client *http.Client, endpoint *url.URL) Assessment {
	a := Assessment{Endpoint: endpoint.String(), CrossOrigin: Probe{State: "not_checked"}, ForeignHost: Probe{State: "not_checked"}, Findings: []string{}, Enforcement: "not_assessed"}
	u := *endpoint
	if strings.HasSuffix(u.Path, "/v1") {
		u.Path += "/models"
	} else {
		u.Path += "/v1/models"
	}
	a.Metadata = probe(ctx, client, &u, false, false)
	if a.Metadata.State != "model_metadata" {
		return a
	}
	a.Findings = append(a.Findings, "model metadata answered without credentials; inference and administrative authentication remain unassessed")
	a.CrossOrigin = probe(ctx, client, &u, true, false)
	if a.CrossOrigin.State == "model_metadata" && a.CrossOrigin.Sharing == "advertised" {
		a.Findings = append(a.Findings, "model metadata response advertises sharing with an unrelated web origin; browser access remains untested")
	}
	a.ForeignHost = probe(ctx, client, &u, false, true)
	if a.ForeignHost.State == "model_metadata" {
		a.Findings = append(a.Findings, "model metadata answered with an unrelated Host header; DNS rebinding remains untested")
	}
	return a
}

func probe(ctx context.Context, client *http.Client, u *url.URL, origin, foreignHost bool) Probe {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Probe{State: "unavailable"}
	}
	if origin {
		req.Header.Set("Origin", probeOrigin)
	}
	if foreignHost {
		req.Host = "secure-agent-probe.invalid"
		if u.Port() != "" {
			req.Host += ":" + u.Port()
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return Probe{State: "unavailable"}
	}
	defer resp.Body.Close()
	p := Probe{Status: resp.StatusCode, State: "non_model_response"}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		p.State = "access_refused"
		return p
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		p.State = "redirect_refused"
		return p
	}
	if resp.StatusCode != http.StatusOK {
		return p
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if len(body) > maxBody {
		p.State = "response_too_large"
		return p
	}
	if err != nil {
		p.State = "unavailable"
		return p
	}
	var envelope struct{ Data json.RawMessage }
	var models []struct{ ID string }
	if json.Unmarshal(body, &envelope) != nil || len(envelope.Data) == 0 || string(envelope.Data) == "null" || json.Unmarshal(envelope.Data, &models) != nil {
		return p
	}
	for _, model := range models {
		if model.ID == "" {
			return p
		}
	}
	p.State = "model_metadata"
	if origin {
		p.Sharing = "not_advertised"
		values := resp.Header.Values("Access-Control-Allow-Origin")
		if len(values) == 1 && (values[0] == "*" || values[0] == probeOrigin) {
			p.Sharing = "advertised"
		}
	}
	return p
}
