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
	case "rotate":
		handleRotate(client)
	case "kill":
		handleKill(client)
	case "fleet":
		handleFleet(client)
	case "fingerprint":
		handleFingerprint(client)
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
	fmt.Println("  secure-agent rotate --incident ID --item ID Auto-rotate a compromised secret")
	fmt.Println("  secure-agent kill <PID>                  Terminate an agent process tree by PID")
	fmt.Println("  secure-agent fleet                       Show fleet remote node telemetry")
	fmt.Println("  secure-agent fingerprint                 Scan configured sources and register secret fingerprints (HMAC only)")
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

func handleRotate(client *http.Client) {
	var incID, itemID string
	for i := 2; i < len(os.Args); i++ {
		if (os.Args[i] == "--incident" || os.Args[i] == "-i") && i+1 < len(os.Args) {
			incID = os.Args[i+1]
			i++
		} else if (os.Args[i] == "--item" || os.Args[i] == "-t") && i+1 < len(os.Args) {
			itemID = os.Args[i+1]
			i++
		}
	}

	if incID == "" || itemID == "" {
		fmt.Println("Error: --incident and --item parameters are required.")
		fmt.Println("Example: secure-agent rotate --incident inc-123 --item rot-456")
		os.Exit(1)
	}

	payload := map[string]string{
		"incident_id": incID,
		"item_id":     itemID,
	}
	data, _ := json.Marshal(payload)

	resp, err := client.Post("http://unix/rotate", "application/json", bytes.NewReader(data))
	if err != nil {
		fmt.Printf("Error executing rotation: %v\n", err)
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
