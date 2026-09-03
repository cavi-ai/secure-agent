// Package collector receives secure-agent fleet webhooks, verifies their HMAC
// signatures, stores envelopes as JSONL, and serves a merged multi-node
// rollup. It is a reference implementation of the fleet contract documented
// in docs/API.md — small enough to read in one sitting, complete enough to
// prove the node → collector path end to end.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

// Envelope mirrors the fleet webhook body (daemon/internal/fleet).
type Envelope struct {
	NodeID  string          `json:"node_id"`
	Kind    string          `json:"kind"` // flag | incident | guard
	TS      string          `json:"ts"`
	Version string          `json:"version"`
	Payload json.RawMessage `json:"payload"`
}

// knownKinds bounds accepted kinds — unknown kinds are stored but never
// counted in the rollup, so a future node version cannot corrupt rollups.
var knownKinds = map[string]bool{"flag": true, "incident": true, "guard": true}

// Config is the collector's runtime configuration.
type Config struct {
	Addr     string            // listen address (default 127.0.0.1:9445)
	StoreDir string            // JSONL store directory (default ~/.local/state/secure-agent-collector)
	Secrets  map[string]string // node_id -> webhook secret
}

func loadConfig() Config {
	cfg := Config{Addr: "127.0.0.1:9445"}
	home, _ := os.UserHomeDir()
	cfg.StoreDir = strings.TrimSuffix(home, "/") + "/.local/state/secure-agent-collector"

	var cfgPath string
	flag.StringVar(&cfgPath, "config", "", "path to collector.yaml (flags override)")
	flag.StringVar(&cfg.Addr, "addr", cfg.Addr, "listen address")
	flag.StringVar(&cfg.StoreDir, "store", cfg.StoreDir, "JSONL store directory")
	var secretsRaw string
	flag.StringVar(&secretsRaw, "secrets", "", "node_id=secret pairs, comma-separated (e.g. n1=s3cret,n2=s3cret2)")
	flag.Parse()

	// Minimal YAML: node secrets as "node_id: secret" lines under "secrets:".
	// Stdlib-only collector: no YAML dependency, so we accept a flat file of
	// "node_id=secret" lines OR the comma list. YAML support can come later
	// without changing the wire contract.
	if cfgPath != "" {
		if pairs, err := parseSecretsFile(cfgPath); err == nil {
			cfg.Secrets = pairs
		} else {
			log.Printf("collector: secrets file: %v", err)
		}
	}
	if secretsRaw != "" {
		if cfg.Secrets == nil {
			cfg.Secrets = map[string]string{}
		}
		for _, kv := range strings.Split(secretsRaw, ",") {
			if k, v, ok := strings.Cut(strings.TrimSpace(kv), "="); ok {
				cfg.Secrets[k] = v
			}
		}
	}
	return cfg
}

// parseSecretsFile reads "node_id=secret" lines (# comments allowed).
func parseSecretsFile(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pairs := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("malformed line %q (want node_id=secret)", line)
		}
		pairs[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	if len(pairs) == 0 {
		return nil, errors.New("no node secrets configured")
	}
	return pairs, nil
}

// Collector wires config, store, and handlers.
type Collector struct {
	cfg   Config
	store *Store
}

func main() {
	cfg := loadConfig()
	if err := os.MkdirAll(cfg.StoreDir, 0o700); err != nil {
		log.Fatalf("store dir: %v", err)
	}
	if len(cfg.Secrets) == 0 {
		log.Fatal("collector: no node secrets configured — use -secrets n1=secret,n2=secret or a secrets file")
	}

	c := &Collector{cfg: cfg, store: NewStore(cfg.StoreDir)}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /hooks/secure-agent", c.handleHook)
	mux.HandleFunc("GET /fleet", c.handleFleet)
	mux.HandleFunc("GET /nodes/", c.handleNodeEvents)
	mux.HandleFunc("GET /", c.handleOverview)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	})

	log.Printf("secure-agent-collector listening on http://%s (nodes: %d)", cfg.Addr, len(cfg.Secrets))
	srv := &http.Server{Addr: cfg.Addr, Handler: mux}
	log.Fatal(srv.ListenAndServe())
}

// verifySignature does a constant-time compare of the X-SecureAgent-Signature
// header against HMAC-SHA256(secret, body).
func verifySignature(header string, body []byte, secret string) error {
	if header == "" {
		return errors.New("missing X-SecureAgent-Signature")
	}
	sig, ok := strings.CutPrefix(header, "sha256=")
	if !ok {
		return errors.New("signature must be 'sha256=<hex>'")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(want)) {
		return errors.New("signature mismatch")
	}
	return nil
}

// handleHook receives, verifies, and stores one envelope.
func (c *Collector) handleHook(w http.ResponseWriter, r *http.Request) {
	body := http.MaxBytesReader(w, r.Body, 2<<20)
	raw, err := io.ReadAll(body)
	if err != nil {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}

	nodeID := r.Header.Get("X-SecureAgent-Node")
	secret, ok := c.cfg.Secrets[nodeID]
	if !ok {
		// Unknown node: 401 without leaking whether the id exists at all.
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := verifySignature(r.Header.Get("X-SecureAgent-Signature"), raw, secret); err != nil {
		log.Printf("hook: node %s rejected: %v", nodeID, err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		http.Error(w, "malformed envelope", http.StatusBadRequest)
		return
	}
	// Envelope node_id must agree with the attested header — a signed payload
	// claiming another node would poison that node's rollup.
	if env.NodeID != nodeID {
		http.Error(w, "node mismatch", http.StatusBadRequest)
		return
	}
	if !knownKinds[env.Kind] {
		http.Error(w, "unknown kind", http.StatusBadRequest)
		return
	}

	if err := c.store.Append(env); err != nil {
		log.Printf("hook: store failed for node %s: %v", nodeID, err)
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	log.Printf("hook: node %s %s accepted", nodeID, env.Kind)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// handleFleet serves the merged multi-node rollup, oldest-node-first for
// stable rendering.
func (c *Collector) handleFleet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	nodes := c.store.Rollup()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(nodes)
}

// handleNodeEvents replays one node's stored envelopes (newest first).
func (c *Collector) handleNodeEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	nodeID := strings.TrimPrefix(r.URL.Path, "/nodes/")
	nodeID = strings.TrimSuffix(nodeID, "/events")
	if _, known := c.cfg.Secrets[nodeID]; !known {
		http.Error(w, "unknown node", http.StatusNotFound)
		return
	}
	kinds := map[string]bool{}
	if k := r.URL.Query().Get("kind"); k != "" {
		kinds[k] = true
	}
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
	}
	events := c.store.Query(nodeID, kinds, limit)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(events)
}
