package main

// `secure-agent canary plant <file>` — writes decoy credentials nothing
// legitimate uses and registers the file as a fingerprint source, so a copy
// leaving in inspected traffic or showing up in a transcript is a
// registered-secret finding, encoded or not.

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	canaryUpper    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	canaryAlnum    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	canaryAWSKey   = canaryAlnum + "/+"
	canaryKeyChars = canaryAlnum + "_-"
)

// canaryTemplate: the decoy lines, each value in its provider's shape.
var canaryTemplate = []struct {
	key, prefix, alphabet string
	n                     int
}{
	{"AWS_ACCESS_KEY_ID", "AKIA", canaryUpper, 16},
	{"AWS_SECRET_ACCESS_KEY", "", canaryAWSKey, 40},
	{"GITHUB_TOKEN", "ghp_", canaryAlnum, 36},
	{"OPENAI_API_KEY", "sk-proj-", canaryKeyChars, 48},
	{"ANTHROPIC_API_KEY", "sk-ant-api03-", canaryKeyChars, 95},
	{"STRIPE_SECRET_KEY", "sk_live_", canaryAlnum, 24},
}

func handleCanary(client *http.Client, args []string) {
	if len(args) != 2 || args[0] != "plant" {
		fmt.Println("Usage: secure-agent canary plant <file>")
		os.Exit(1)
	}
	path, err := filepath.Abs(args[1])
	if err != nil {
		fmt.Printf("canary: %v\n", err)
		os.Exit(1)
	}
	os.Exit(canaryPlant(os.Stdout, path, rand.Reader, client))
}

// canaryPlant creates path (never overwriting) with decoy credentials, adds it
// as a fingerprint ingest source and registers its fingerprints. A file whose
// registration fails is removed, so no decoy is left unwatched.
func canaryPlant(w io.Writer, path string, random io.Reader, client *http.Client) int {
	var lines []string
	for _, c := range canaryTemplate {
		v, err := canaryValue(random, c.alphabet, c.n)
		if err != nil {
			fmt.Fprintf(w, "canary: %v\n", err)
			return 1
		}
		lines = append(lines, c.key+"="+c.prefix+v)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fmt.Fprintf(w, "canary: %v (choose a file that does not exist)\n", err)
		return 1
	}
	_, werr := f.WriteString(strings.Join(lines, "\n") + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(path)
		fmt.Fprintf(w, "canary: write %s: %v\n", path, werr)
		return 1
	}
	body, _ := json.Marshal(map[string]string{"source": path, "op": "add"})
	if code, out := request(client, http.MethodPost, "http://unix/firewall/sources", string(body)); code != http.StatusOK {
		os.Remove(path)
		fmt.Fprintf(w, "canary: adding %s as a fingerprint source failed (%d): %s\n", path, code, strings.TrimSpace(out))
		return 1
	}
	code, out := request(client, http.MethodPost, "http://unix/firewall/fingerprints/ingest", "")
	var reg struct {
		Registered []string `json:"registered"`
	}
	if code != http.StatusOK || json.Unmarshal([]byte(out), &reg) != nil || len(reg.Registered) == 0 {
		fmt.Fprintf(w, "canary: %s is a fingerprint source, but registering it failed (%d): %s\nRun secure-agent fingerprint to retry.\n", path, code, strings.TrimSpace(out))
		return 1
	}
	fmt.Fprintf(w, "Planted %d decoy credentials in %s (0600) and registered the file's fingerprints:\n", len(lines), path)
	for _, label := range reg.Registered {
		fmt.Fprintf(w, "  • %s\n", label)
	}
	fmt.Fprintln(w, "Nothing legitimate uses these values: any copy in inspected traffic or a transcript is a finding.")
	return 0
}

func canaryValue(random io.Reader, alphabet string, n int) (string, error) {
	var b strings.Builder
	max := big.NewInt(int64(len(alphabet)))
	for i := 0; i < n; i++ {
		k, err := rand.Int(random, max)
		if err != nil {
			return "", err
		}
		b.WriteByte(alphabet[k.Int64()])
	}
	return b.String(), nil
}
