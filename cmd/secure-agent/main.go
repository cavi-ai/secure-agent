package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func getSocketPath() string {
	// Same override the hooks honor; required for multi-node testing and
	// pointing the CLI at a remote tunneled socket.
	if p := os.Getenv("SECURE_AGENT_SOCK"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "secure-agent", "daemon.sock")
}

func unixClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
		Timeout: 5 * time.Second,
	}
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(0)
	}

	cmd := os.Args[1]
	sockPath := getSocketPath()
	client := unixClient(sockPath)

	switch cmd {
	case "status":
		handleStatus(client)
	case "flags":
		handleFlags(client)
	case "incidents":
		handleIncidents(client)
	case "kill":
		handleKill(client)
	case "fleet":
		handleFleet(client)
	case "fingerprint":
		handleFingerprint(client)
	case "events":
		handleEvents(client)
	case "audit":
		handleAudit(client)
	case "guard":
		handleGuard(client, os.Args[2:])
	case "firewall":
		handleFirewall(client, os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("secure-agent — CLI for secure-agent daemon")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  secure-agent status                      Show daemon running status and active agents")
	fmt.Println("  secure-agent flags                       List recent security correlation alerts")
	fmt.Println("  secure-agent incidents                   Display incident reports and remediation checklists")
	fmt.Println("  secure-agent events [--limit N]          List recent raw system events")
	fmt.Println("  secure-agent audit [--limit N]           List the policy audit trail")
	fmt.Println("  secure-agent kill <PID>                  Terminate an agent process tree by PID")
	fmt.Println("  secure-agent fleet                       Show fleet remote node telemetry")
	fmt.Println("  secure-agent guard list                  List cached guard decisions")
	fmt.Println("  secure-agent guard revoke <agent> <rule> Revoke a cached guard decision (forces a new prompt)")
	fmt.Println("  secure-agent firewall mode <rule> <mode> Set a firewall rule mode (monitor|block)")
	fmt.Println("  secure-agent firewall sources            List fingerprint ingest sources")
	fmt.Println("  secure-agent fingerprint                 Scan configured sources and register secret fingerprints (HMAC only)")
}

// queryFlag parses a "--name value" pair from args; returns def when absent.
func queryFlag(args []string, name string, def string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return def
}

// request is the shared HTTP doer: every subcommand funnels through here so
// error reporting and non-200 handling stay uniform.
func request(client *http.Client, method, path, body string) (int, string) {
	var (
		resp *http.Response
		err  error
	)
	if body == "" {
		resp, err = client.Do(mustRequest(method, path))
	} else {
		resp, err = client.Post(path, "application/json", strings.NewReader(body))
		if err == nil && method != http.MethodPost {
			resp.Body.Close()
			return 0, "method mismatch"
		}
	}
	if err != nil {
		fmt.Printf("Error connecting to secure-agentd: %v\nIs secure-agentd running?\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func mustRequest(method, path string) *http.Request {
	req, err := http.NewRequest(method, path, nil)
	if err != nil {
		fmt.Printf("bad request: %v\n", err)
		os.Exit(1)
	}
	return req
}

func handleEvents(client *http.Client) {
	args := os.Args[2:]
	limit := queryFlag(args, "--limit", "50")
	code, body := request(client, http.MethodGet, "http://unix/events?limit="+limit, "")
	if code != 200 {
		fmt.Printf("events failed (%d): %s\n", code, strings.TrimSpace(body))
		os.Exit(1)
	}
	fmt.Println(body)
}

func handleAudit(client *http.Client) {
	args := os.Args[2:]
	limit := queryFlag(args, "--limit", "100")
	code, body := request(client, http.MethodGet, "http://unix/audit?limit="+limit, "")
	if code != 200 {
		fmt.Printf("audit failed (%d): %s\n", code, strings.TrimSpace(body))
		os.Exit(1)
	}
	fmt.Println(body)
}

func handleGuard(client *http.Client, args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: secure-agent guard list | guard revoke <agent> <rule_id>")
		os.Exit(1)
	}
	switch args[0] {
	case "list":
		code, body := request(client, http.MethodGet, "http://unix/guard/rules", "")
		if code != 200 {
			fmt.Printf("guard list failed (%d): %s\n", code, strings.TrimSpace(body))
			os.Exit(1)
		}
		fmt.Println(body)
	case "revoke":
		if len(args) < 3 {
			fmt.Println("Usage: secure-agent guard revoke <agent> <rule_id>")
			os.Exit(1)
		}
		path := fmt.Sprintf("http://unix/guard/rules?agent=%s&rule_id=%s", args[1], args[2])
		req, err := http.NewRequest(http.MethodDelete, path, nil)
		if err != nil {
			fmt.Printf("bad request: %v\n", err)
			os.Exit(1)
		}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("Error connecting to secure-agentd: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 {
			fmt.Printf("revoke failed (%d): %s\n", resp.StatusCode, strings.TrimSpace(string(b)))
			os.Exit(1)
		}
		fmt.Println(string(b))
	default:
		fmt.Printf("Unknown guard subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func handleFirewall(client *http.Client, args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: secure-agent firewall mode <rule> <monitor|block> | firewall sources")
		os.Exit(1)
	}
	switch args[0] {
	case "mode":
		if len(args) < 3 || (args[2] != "monitor" && args[2] != "block") {
			fmt.Println("Usage: secure-agent firewall mode <rule> <monitor|block>")
			os.Exit(1)
		}
		payload, _ := json.Marshal(map[string]string{"rule": args[1], "mode": args[2]})
		code, body := request(client, http.MethodPost, "http://unix/firewall/mode", string(payload))
		if code != 200 {
			fmt.Printf("firewall mode failed (%d): %s\n", code, strings.TrimSpace(body))
			os.Exit(1)
		}
		fmt.Println(string(body))
	case "sources":
		code, body := request(client, http.MethodGet, "http://unix/firewall/sources", "")
		if code != 200 {
			fmt.Printf("firewall sources failed (%d): %s\n", code, strings.TrimSpace(body))
			os.Exit(1)
		}
		fmt.Println(body)
	default:
		fmt.Printf("Unknown firewall subcommand: %s\n", args[0])
		os.Exit(1)
	}
}

func handleFingerprint(client *http.Client) {
	resp, err := client.Post("http://unix/firewall/fingerprints/ingest", "application/json", nil)
	if err != nil {
		fmt.Printf("Error connecting to secure-agentd: %v\nIs secure-agentd running?\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Fingerprint scan failed (%d): %s\n", resp.StatusCode, strings.TrimSpace(string(body)))
		os.Exit(1)
	}

	var out struct {
		Registered []string `json:"registered"`
	}
	if json.Unmarshal(body, &out) != nil || len(out.Registered) == 0 {
		fmt.Println("No secrets found in the configured ingest sources.")
		fmt.Println("Add paths under firewall.registry.ingest_sources in ~/.config/secure-agent/config.yaml, then re-run.")
		return
	}

	fmt.Printf("Registered %d secret fingerprint(s) — HMAC only, no plaintext stored:\n", len(out.Registered))
	for _, label := range out.Registered {
		fmt.Printf("  • %s\n", label)
	}
	fmt.Println("Applied to the running daemon.")
}

func handleStatus(client *http.Client) {
	resp, err := client.Get("http://unix/status")
	if err != nil {
		fmt.Printf("Error connecting to secure-agentd: %v\nIs secure-agentd running?\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
}

func handleFlags(client *http.Client) {
	resp, err := client.Get("http://unix/flags?limit=20")
	if err != nil {
		fmt.Printf("Error fetching flags: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
}

func handleIncidents(client *http.Client) {
	resp, err := client.Get("http://unix/incidents?limit=10")
	if err != nil {
		fmt.Printf("Error fetching incidents: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
}

func handleKill(client *http.Client) {
	if len(os.Args) < 3 {
		fmt.Println("Error: PID required. Usage: secure-agent kill <PID>")
		os.Exit(1)
	}

	pid, err := strconv.Atoi(os.Args[2])
	if err != nil || pid <= 0 {
		fmt.Printf("Invalid PID: %s\n", os.Args[2])
		os.Exit(1)
	}

	payload := map[string]int{"pid": pid}
	data, _ := json.Marshal(payload)

	resp, err := client.Post("http://unix/kill", "application/json", bytes.NewReader(data))
	if err != nil {
		fmt.Printf("Error killing PID %d: %v\n", pid, err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
}

func handleFleet(client *http.Client) {
	resp, err := client.Get("http://unix/fleet")
	if err != nil {
		fmt.Printf("Error fetching fleet node telemetry: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println(strings.TrimSpace(string(body)))
}
