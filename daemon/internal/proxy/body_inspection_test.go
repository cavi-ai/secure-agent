package proxy

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/firewall"
)

// These are synthetic fixtures, not credentials.
const bodyFixture = "fixture-value-abcdefghijklmnop"

func bodyEngine(t *testing.T, mode string) *firewall.Engine {
	t.Helper()
	e := testProxyEngine(t, mode)
	e.SetFingerprints([]config.Fingerprint{{ID: "fixture", Len: len(bodyFixture), HMAC: firewall.Fingerprint([]byte("test-salt"), bodyFixture)}})
	return e
}

func zipped(t *testing.T, data string) []byte {
	t.Helper()
	var out bytes.Buffer
	z := gzip.NewWriter(&out)
	if _, err := z.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestInspectionFindsSecretsBeyondPrefixAndAcrossReads(t *testing.T) {
	prefix := strings.Repeat(" ", (1<<20)+123)
	jsonEncoded := ""
	urlEncoded := ""
	for _, c := range bodyFixture {
		jsonEncoded += fmt.Sprintf(`\u%04x`, c)
		urlEncoded += fmt.Sprintf("%%%02X", c)
	}
	for _, tc := range []struct{ name, payload, encoding string }{
		{"registered", bodyFixture, ""},
		{"base64", base64.StdEncoding.EncodeToString([]byte(bodyFixture)), ""},
		{"url", urlEncoded, ""},
		{"json", jsonEncoded, ""},
		{"typed", "Bearer fixture-token-abcdefghijklmnop", ""},
		{"typed-base64", base64.StdEncoding.EncodeToString([]byte("Bearer fixture-token-abcdefghijklmnop")), ""},
		{"gzip", bodyFixture, "gzip"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(prefix + tc.payload + " ")
			if tc.encoding == "gzip" {
				data = zipped(t, string(data))
			}
			b := bus.New(64)
			defer b.Close()
			ps := NewProxyServer(0, b, nil, bodyEngine(t, "block"))
			r := httptest.NewRequest("POST", "http://unknown.invalid/upload", nil)
			r.Body = io.NopCloser(&shortReads{Reader: bytes.NewReader(data), size: 7})
			r.ContentLength = -1
			r.Header.Set("Content-Encoding", tc.encoding)
			blocked, _ := ps.inspectRequest(r, "unknown.invalid")
			defer r.Body.Close()
			if !blocked {
				t.Fatal("secret beyond the prefix passed inspection")
			}
		})
	}
}

type shortReads struct {
	io.Reader
	size int
}

func (r *shortReads) Read(p []byte) (int, error) { return r.Reader.Read(p[:min(len(p), r.size)]) }

func TestMonitorReplaysLargeBodyUnchangedAndReportsOnce(t *testing.T) {
	data := []byte(strings.Repeat(" ", (1<<20)+123) + bodyFixture + " ")
	b := bus.New(64)
	defer b.Close()
	events := b.Subscribe()
	ps := NewProxyServer(0, b, nil, bodyEngine(t, "monitor"))
	r := httptest.NewRequest("POST", "http://unknown.invalid/upload", bytes.NewReader(data))
	blocked, _ := ps.inspectRequest(r, "unknown.invalid")
	defer r.Body.Close()
	if blocked {
		t.Fatal("monitor request blocked")
	}
	got, err := io.ReadAll(r.Body)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("replayed body changed")
	}
	count := 0
	for {
		select {
		case e := <-events:
			if e.Detail == "proxy-inspection-incomplete:body-window" {
				continue
			}
			if e.Detail != "proxy-secret-leak:fixture" {
				t.Fatalf("unexpected finding: %s", e.Detail)
			}
			count++
		default:
			if count != 1 {
				t.Fatalf("got %d leak events, want 1", count)
			}
			if ps.engine.Stats()["fixture"].WouldBlock != 1 {
				t.Fatal("overlapping scans inflated rule statistics")
			}
			return
		}
	}
}

func TestSuffixSecretIsBlockedBeforeUpstreamReceivesRequest(t *testing.T) {
	called := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(200) }))
	defer backend.Close()
	b := bus.New(64)
	defer b.Close()
	ps := NewProxyServer(0, b, nil, bodyEngine(t, "block"))
	r := httptest.NewRequest("POST", backend.URL, strings.NewReader(strings.Repeat(" ", (1<<20)+123)+bodyFixture+" "))
	w := httptest.NewRecorder()
	ps.inspectAndForwardHTTP(w, r)
	defer r.Body.Close()
	if w.Code != http.StatusForbidden || called {
		t.Fatalf("status=%d, upstream called=%v", w.Code, called)
	}
}

func TestReplayStorageIsEncryptedAuthenticatedAndReleased(t *testing.T) {
	s := &bodySpool{}
	defer s.Close()
	data := []byte(strings.Repeat(" ", 1<<20) + bodyFixture)
	if _, err := s.Write(data); err != nil {
		t.Fatal(err)
	}
	if s.file == nil {
		t.Fatal("large request was not spooled")
	}
	if _, err := os.Stat(s.file.Name()); !os.IsNotExist(err) {
		t.Fatal("temporary file remains visible")
	}
	stored, err := io.ReadAll(io.NewSectionReader(s.file, 0, 2<<20))
	if err != nil || bytes.Contains(stored, []byte(bodyFixture)) {
		t.Fatal("plaintext leaked into replay storage")
	}
	got, err := io.ReadAll(s.reader())
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("encrypted replay changed the body")
	}
	stored[len(stored)-1] ^= 1
	if _, err := s.file.WriteAt(stored, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(s.reader()); err == nil {
		t.Fatal("replay accepted corrupted ciphertext")
	}
	if err := s.file.Truncate(0); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(s.reader()); err == nil {
		t.Fatal("replay accepted truncated ciphertext")
	}

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.file.Stat(); err == nil {
		t.Fatal("spool descriptor still open")
	}
}

func TestUnavailableReplayStoragePreservesUninspectedTail(t *testing.T) {
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	data := []byte(strings.Repeat(" ", (1<<20)+123) + bodyFixture + " ")
	b := bus.New(64)
	defer b.Close()
	events := b.Subscribe()
	ps := NewProxyServer(0, b, nil, bodyEngine(t, "monitor"))
	r := httptest.NewRequest("POST", "http://unknown.invalid/upload", bytes.NewReader(data))
	ps.inspectRequest(r, "unknown.invalid")
	defer r.Body.Close()
	got, err := io.ReadAll(r.Body)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("storage failure lost request bytes")
	}
	found := false
	for {
		select {
		case e := <-events:
			if e.Detail == "proxy-inspection-incomplete:body-buffer" {
				found = true
			}
		default:
			if !found {
				t.Fatal("storage coverage gap was silent")
			}
			return
		}
	}
}

func TestTruncatedGzipReportsIncompleteInspectionAndPreservesBody(t *testing.T) {
	data := zipped(t, "ordinary fixture payload")
	data = data[:len(data)-3]
	b := bus.New(64)
	defer b.Close()
	events := b.Subscribe()
	ps := NewProxyServer(0, b, nil, bodyEngine(t, "monitor"))
	r := httptest.NewRequest("POST", "http://unknown.invalid/upload", bytes.NewReader(data))
	r.Header.Set("Content-Encoding", "gzip")
	ps.inspectRequest(r, "unknown.invalid")
	defer r.Body.Close()
	got, err := io.ReadAll(r.Body)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("decode failure changed original bytes")
	}
	select {
	case e := <-events:
		if e.Detail != "proxy-inspection-incomplete:body-decode" {
			t.Fatal(e.Detail)
		}
	default:
		t.Fatal("gzip truncation silently reported full coverage")
	}
}

func TestInspectionDoesNotMatchFingerprintAtArtificialTokenBoundary(t *testing.T) {
	data := strings.Repeat("x", (1<<20)+123) + bodyFixture + " "
	b := bus.New(64)
	defer b.Close()
	ps := NewProxyServer(0, b, nil, bodyEngine(t, "block"))
	r := httptest.NewRequest("POST", "http://unknown.invalid/upload", strings.NewReader(data))
	blocked, _ := ps.inspectRequest(r, "unknown.invalid")
	defer r.Body.Close()
	if blocked {
		t.Fatal("sliced token fabricated a registered-secret match")
	}
}

func TestInspectionFindsEncodedSecretAcrossScanWindow(t *testing.T) {
	for _, payload := range []string{bodyFixture, base64.StdEncoding.EncodeToString([]byte(bodyFixture))} {
		data := strings.Repeat(" ", (1<<20)-10) + payload + " "
		b := bus.New(64)
		ps := NewProxyServer(0, b, nil, bodyEngine(t, "block"))
		r := httptest.NewRequest("POST", "http://unknown.invalid/upload", strings.NewReader(data))
		blocked, _ := ps.inspectRequest(r, "unknown.invalid")
		r.Body.Close()
		b.Close()
		if !blocked {
			t.Fatal("scan window split lost the secret")
		}
	}
}

type repeatedByte struct{ b byte }

func (r repeatedByte) Read(p []byte) (int, error) {
	for j := range p {
		p[j] = r.b
	}
	return len(p), nil
}

type spaceVerifier struct{ n int64 }

func (w *spaceVerifier) Write(p []byte) (int, error) {
	for _, b := range p {
		if b != ' ' {
			return 0, fmt.Errorf("request byte changed")
		}
	}
	w.n += int64(len(p))
	return len(p), nil
}

func TestInspectionBudgetPreservesFullUploadAndReportsGap(t *testing.T) {
	const size = (64 << 20) + 17
	b := bus.New(64)
	defer b.Close()
	events := b.Subscribe()
	ps := NewProxyServer(0, b, nil, bodyEngine(t, "monitor"))
	r := httptest.NewRequest("POST", "http://unknown.invalid/upload", io.LimitReader(repeatedByte{' '}, size))
	ps.inspectRequest(r, "unknown.invalid")
	defer r.Body.Close()
	w := &spaceVerifier{}
	if _, err := io.Copy(w, r.Body); err != nil || w.n != size {
		t.Fatalf("forwarded %d bytes: %v", w.n, err)
	}
	found := false
	for {
		select {
		case e := <-events:
			if e.Detail == "proxy-inspection-incomplete:body-limit" {
				found = true
			}
		default:
			if !found {
				t.Fatal("body limit was silent")
			}
			return
		}
	}
}

func TestGzipExpansionBudgetIsVisible(t *testing.T) {
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := io.Copy(gz, io.LimitReader(repeatedByte{' '}, (64<<20)+17)); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	b := bus.New(64)
	defer b.Close()
	events := b.Subscribe()
	ps := NewProxyServer(0, b, nil, bodyEngine(t, "monitor"))
	r := httptest.NewRequest("POST", "http://unknown.invalid/upload", bytes.NewReader(compressed.Bytes()))
	r.Header.Set("Content-Encoding", "gzip")
	ps.inspectRequest(r, "unknown.invalid")
	defer r.Body.Close()
	found := false
	for {
		select {
		case e := <-events:
			if e.Detail == "proxy-inspection-incomplete:body-limit" {
				found = true
			}
		default:
			if !found {
				t.Fatal("gzip expansion budget was silent")
			}
			return
		}
	}
}

func TestMonitorHTTPForwardsOriginalBodyAndClosesSpool(t *testing.T) {
	data := []byte(strings.Repeat(" ", (1<<20)+123) + bodyFixture + " ")
	received := make(chan []byte, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ := io.ReadAll(r.Body)
		received <- got
		w.WriteHeader(204)
	}))
	defer backend.Close()
	b := bus.New(64)
	defer b.Close()
	ps := NewProxyServer(0, b, nil, bodyEngine(t, "monitor"))
	defer ps.plainHTTPClient.CloseIdleConnections()
	r := httptest.NewRequest("POST", backend.URL, bytes.NewReader(data))
	w := httptest.NewRecorder()
	ps.inspectAndForwardHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("status=%d", w.Code)
	}
	if !bytes.Equal(<-received, data) {
		t.Fatal("upstream received different body bytes")
	}
	if _, err := r.Body.(*inspectionBody).spool.file.Stat(); err == nil {
		t.Fatal("handler leaked spool descriptor")
	}
}

func TestWindowBoundariesDoNotFabricateAnchoredPatternMatches(t *testing.T) {
	for _, tc := range []struct{ name, pattern, data string }{
		{"start", `^anchor-fixture`, strings.Repeat(" ", (1<<20)-(64<<10)+1) + "anchor-fixture " + strings.Repeat(" ", 100000)},
		{"end", `anchor-fixture\s*$`, strings.Repeat(" ", (1<<20)-30) + "anchor-fixture " + strings.Repeat(" ", 100000) + "tail"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, err := firewall.NewEngine(config.FirewallConfig{Mode: "block", Patterns: []config.PatternConfig{{ID: "anchored", Re: tc.pattern, Mode: "block"}}}, []byte("test-salt"))
			if err != nil {
				t.Fatal(err)
			}
			b := bus.New(64)
			defer b.Close()
			ps := NewProxyServer(0, b, nil, e)
			r := httptest.NewRequest("POST", "http://unknown.invalid/upload", strings.NewReader(tc.data))
			blocked, _ := ps.inspectRequest(r, "unknown.invalid")
			defer r.Body.Close()
			if blocked {
				t.Fatal("artificial window boundary changed an anchored pattern's meaning")
			}
		})
	}
}

func TestHTTPSBlocksSuffixSecretAndReusesDrainedTunnel(t *testing.T) {
	ps, tok, caPath := startRouteProxy(t)
	ps.SetInspectHosts([]string{"127.0.0.1"})
	ps.engine.SetFingerprints([]config.Fingerprint{{ID: "fixture", Len: len(bodyFixture), HMAC: firewall.Fingerprint([]byte("test-salt"), bodyFixture)}})
	ps.engine.SetRuleMode("fixture", firewall.ModeBlock)
	pem, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("blocked request reached upstream") }))
	defer backend.Close()
	proxyURL, _ := url.Parse(fmt.Sprintf("http://inspect:%s@127.0.0.1:%d", tok, ps.Port()))
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots}, MaxIdleConnsPerHost: 1}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	for _, data := range []string{strings.Repeat(" ", (1<<20)+123) + bodyFixture + " ", bodyFixture} {
		resp, err := client.Post(backend.URL, "text/plain", strings.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("status=%d, want forbidden before upstream dial", resp.StatusCode)
		}
	}
	if _, decrypted := ps.RouteStats(); decrypted != 1 {
		t.Fatalf("drained CONNECT tunnel was not reused: %d", decrypted)
	}
}
