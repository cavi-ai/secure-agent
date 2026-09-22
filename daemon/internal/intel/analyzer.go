package intel

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// attributionWindow bounds how far from the flag time an event may be and still
// count as part of the same incident.
const attributionWindow = 5 * time.Minute

type Analyzer struct{}

func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

var (
	connSubjectRe = regexp.MustCompile(`connected to ([^\s]+)`)
	fileSubjectRe = regexp.MustCompile(`\bread (\S+?) (?:at|then)\b`)
)

// SubjectForFlag derives the aggregation subject from a flag's evidence:
// the connected host for egress rules, the touched path for file rules.
// Empty when nothing extractable — aggregation then keys on rule+session
// alone, which is still one incident per rule per session.
func SubjectForFlag(flag model.Flag) string {
	// Structured items need no string work.
	for _, ev := range flag.Evidence {
		if ev.Kind == "connect" && ev.Label != "" {
			return ev.Label
		}
	}
	for _, ev := range flag.Evidence {
		if (ev.Kind == "read" || ev.Kind == "keychain") && ev.Label != "" {
			return ev.Label
		}
	}
	// Legacy rows decode as kind "text".
	for _, ev := range flag.Evidence {
		if ev.Kind != "text" {
			continue
		}
		s := ev.Text
		for _, prefix := range []string{"conn:", "net:"} {
			if strings.HasPrefix(s, prefix) {
				return strings.TrimSpace(strings.TrimPrefix(s, prefix))
			}
		}
		if strings.HasPrefix(s, "file:") {
			return strings.TrimSpace(strings.TrimPrefix(s, "file:"))
		}
	}
	for _, ev := range flag.Evidence {
		if ev.Kind != "text" {
			continue
		}
		if m := connSubjectRe.FindStringSubmatch(ev.Text); m != nil {
			return m[1]
		}
	}
	for _, ev := range flag.Evidence {
		if ev.Kind != "text" {
			continue
		}
		if m := fileSubjectRe.FindStringSubmatch(ev.Text); m != nil {
			return m[1]
		}
	}
	return ""
}

func (a *Analyzer) Analyze(flag model.Flag, events []event.Event) model.IncidentReport {
	// inc-<unix-second>-<pid> collided for two flags on the same pid within one
	// second (INSERT OR REPLACE then silently overwrote the first incident's
	// evidence). Include the flag's unique ID so every report gets its own row.
	incID := fmt.Sprintf("inc-%d-%d-%s", flag.TS.Unix(), flag.PID, flag.ID)

	summary := fmt.Sprintf("Security rule '%s' triggered by agent '%s' (PID %d). Evidence: %s",
		flag.Rule, flag.Agent, flag.PID, strings.Join(flag.EvidenceStrings(), ", "))

	report := model.IncidentReport{
		ID:           incID,
		FlagID:       flag.ID,
		PID:          flag.PID,
		Agent:        flag.Agent,
		Timestamp:    flag.TS,
		Rule:         flag.Rule,
		Summary:      summary,
		Risk:         model.RiskMedium,
		TouchedFiles: make([]string, 0),
		Connections:  make([]string, 0),
		RotateList:   make([]model.RotateItem, 0),
	}

	filesSeen := make(map[string]bool)
	connsSeen := make(map[string]bool)

	for _, ev := range events {
		// Attribute only this agent's activity near the incident. When the flag
		// carries a PID, an event must share it: a zero-PID event cannot be
		// attributed and must not widen the blast radius to every process.
		if flag.PID != 0 && ev.PID != flag.PID {
			continue
		}
		// And only events within the attribution window of the flag, not stale
		// rows the ring buffer happens to still hold.
		if !ev.TS.IsZero() && (ev.TS.Before(flag.TS.Add(-attributionWindow)) || ev.TS.After(flag.TS.Add(attributionWindow))) {
			continue
		}

		if ev.Path != "" && !filesSeen[ev.Path] {
			filesSeen[ev.Path] = true
			report.TouchedFiles = append(report.TouchedFiles, ev.Path)
			item := a.classifyPath(ev.Path)
			if item != nil {
				report.RotateList = append(report.RotateList, *item)
			}
		}

		if ev.RemoteHost != "" && !connsSeen[ev.RemoteHost] {
			connStr := fmt.Sprintf("%s:%d", ev.RemoteHost, ev.RemotePort)
			connsSeen[ev.RemoteHost] = true
			report.Connections = append(report.Connections, connStr)
		}
	}

	// Extract files & connections from evidence; kind "text" keeps the legacy
	// string parsing.
	for _, item := range flag.Evidence {
		addFile := func(p string) {
			p = strings.TrimSpace(p)
			if p != "" && !filesSeen[p] {
				filesSeen[p] = true
				report.TouchedFiles = append(report.TouchedFiles, p)
				if it := a.classifyPath(p); it != nil {
					report.RotateList = append(report.RotateList, *it)
				}
			}
		}
		addConn := func(c string) {
			c = strings.TrimSpace(c)
			if c != "" && !connsSeen[c] {
				connsSeen[c] = true
				report.Connections = append(report.Connections, c)
			}
		}
		switch item.Kind {
		case "read", "keychain":
			addFile(item.Label)
		case "connect":
			addConn(item.Label)
		case "text":
			evStr := item.Text
			if strings.HasPrefix(evStr, "file:") {
				addFile(strings.TrimPrefix(evStr, "file:"))
			} else if strings.HasPrefix(evStr, "conn:") || strings.HasPrefix(evStr, "net:") {
				c := strings.TrimPrefix(evStr, "conn:")
				c = strings.TrimPrefix(c, "net:")
				addConn(c)
			} else {
				// Extract file paths and connections formatted in evidence text
				if idx := strings.Index(evStr, " read "); idx != -1 {
					rest := evStr[idx+len(" read "):]
					if atIdx := strings.LastIndex(rest, " at "); atIdx != -1 {
						addFile(rest[:atIdx])
					}
				} else if idx := strings.Index(evStr, " accessed keychain file "); idx != -1 {
					rest := evStr[idx+len(" accessed keychain file "):]
					if atIdx := strings.LastIndex(rest, " at "); atIdx != -1 {
						addFile(rest[:atIdx])
					}
				} else if idx := strings.Index(evStr, " connected to "); idx != -1 {
					rest := evStr[idx+len(" connected to "):]
					if atIdx := strings.LastIndex(rest, " at "); atIdx != -1 {
						addConn(rest[:atIdx])
					}
				}
			}
		}
	}

	// Calculate overall risk
	maxRisk := model.RiskLow
	if flag.Severity >= 2 {
		maxRisk = model.RiskCritical
	} else if flag.Severity == 1 {
		maxRisk = model.RiskHigh
	}

	for _, rot := range report.RotateList {
		if rot.Risk == model.RiskCritical {
			maxRisk = model.RiskCritical
			break
		} else if rot.Risk == model.RiskHigh && maxRisk != model.RiskCritical {
			maxRisk = model.RiskHigh
		}
	}

	report.Risk = maxRisk
	return report
}

// isSSHPrivateKey reports whether a basename looks like an SSH private key,
// excluding public keys and non-key files under ~/.ssh (config, known_hosts).
func isSSHPrivateKey(base string) bool {
	if strings.HasSuffix(base, ".pub") {
		return false
	}
	if strings.HasPrefix(base, "id_") {
		return true
	}
	for _, suf := range []string{"_rsa", "_dsa", "_ecdsa", "_ed25519"} {
		if strings.HasSuffix(base, suf) {
			return true
		}
	}
	return false
}

func (a *Analyzer) classifyPath(path string) *model.RotateItem {
	cleanPath := strings.ToLower(filepath.Clean(path))
	baseName := filepath.Base(cleanPath)

	if strings.Contains(baseName, ".env") {
		return &model.RotateItem{
			ID:          fmt.Sprintf("rot-env-%s", baseName),
			Category:    model.CategoryEnvSecrets,
			Name:        fmt.Sprintf("Environment File: %s", filepath.Base(path)),
			Path:        path,
			Risk:        model.RiskCritical,
			Description: "Environment variable secret file was accessed prior to foreign network connection.",
			Action:      fmt.Sprintf("Inspect %s and immediately rotate all API keys, DB passwords, and tokens defined within.", path),
		}
	}

	// AWS only within an .aws directory (covers both credentials and config
	// there). A bare basename of "config"/"credentials" is not AWS — it matches
	// ~/.ssh/config, .git/config, and countless app files.
	if strings.Contains(cleanPath, "/.aws/") {
		return &model.RotateItem{
			ID:          "rot-aws-creds",
			Category:    model.CategoryCloudCreds,
			Name:        "AWS Cloud Credentials",
			Path:        path,
			Risk:        model.RiskCritical,
			Description: "An AWS credentials/config file (~/.aws/) was read by an unverified agent process.",
			Action:      "Rotate the affected AWS access keys in the IAM console: create a replacement, update your local config, then deactivate and delete the exposed key.",
		}
	}

	// SSH: only actual private keys (id_* or *_rsa/_dsa/_ecdsa/_ed25519, not
	// .pub) — not ~/.ssh/config or known_hosts.
	if isSSHPrivateKey(baseName) {
		return &model.RotateItem{
			ID:          fmt.Sprintf("rot-ssh-%s", baseName),
			Category:    model.CategorySSHKeys,
			Name:        fmt.Sprintf("SSH Private Key: %s", filepath.Base(path)),
			Path:        path,
			Risk:        model.RiskCritical,
			Description: "A private SSH key file was read by an agent process.",
			Action:      "Generate a new keypair (`ssh-keygen -t ed25519`), replace the old public key in every `authorized_keys`/host that trusts it, then remove the old key.",
		}
	}

	// System trust store: reading it is normal for cert-chain evaluation —
	// any app doing TLS or code-signing touches these files. There is
	// nothing to rotate (trust anchors are public), and calling it CRITICAL
	// teaches the operator to ignore alerts.
	if strings.Contains(cleanPath, "systemtrustsettings.plist") ||
		strings.Contains(cleanPath, "/system/library/keychains/") {
		return &model.RotateItem{
			ID:          "info-keychain-system-trust",
			Category:    model.CategoryKeychain,
			Name:        "macOS System Trust Store",
			Path:        path,
			Risk:        model.RiskLow,
			Description: "The agent read the macOS system trust store. Every app that validates a certificate chain (TLS, code signing, package verification) reads this file — it contains public root-CA certificates, not secrets.",
			Action:      "No action needed. Only flag for review if the agent also attempted outbound connections to unknown hosts immediately after.",
		}
	}

	// Keychain: only real USER keychain files, not the system trust store.
	if strings.HasSuffix(cleanPath, ".keychain-db") || strings.HasSuffix(cleanPath, ".keychain") || strings.Contains(cleanPath, "/library/keychains/") {
		return &model.RotateItem{
			ID:          "rot-keychain-db",
			Category:    model.CategoryKeychain,
			Name:        "macOS User Keychain",
			Path:        path,
			Risk:        model.RiskHigh,
			Description: "A macOS user keychain file was accessed. Reading the file alone does not expose secrets — items are encrypted with the user's password — but it is unusual for an agent and worth confirming the access pattern.",
			Action:      "Check what the agent did with the access: Keychain Access → filter items modified around the access time. Rotation is warranted only if the agent also wrote to the keychain or read item secrets via the security CLI.",
		}
	}

	if strings.Contains(cleanPath, ".config/gh/hosts.yml") || baseName == ".git-credentials" {
		return &model.RotateItem{
			ID:          "rot-gh-token",
			Category:    model.CategorySourceControl,
			Name:        "GitHub Host Credentials",
			Path:        path,
			Risk:        model.RiskCritical,
			Description: "GitHub CLI authentication hosts file was accessed.",
			Action:      "Run `gh auth logout` and re-authenticate via `gh auth login`, or revoke Personal Access Tokens on GitHub.",
		}
	}

	if baseName == ".zshrc" || baseName == ".zshenv" || baseName == ".zprofile" || path == "/etc/paths" {
		return &model.RotateItem{
			ID:          fmt.Sprintf("rot-shell-%s", baseName),
			Category:    model.CategorySystemConfig,
			Name:        fmt.Sprintf("Shell Configuration: %s", baseName),
			Path:        path,
			Risk:        model.RiskHigh,
			Description: "Shell initialization script was read or targeted for mutation.",
			Action:      fmt.Sprintf("Inspect %s for unauthorized exports, aliases, or injected execution hooks.", path),
		}
	}

	return nil
}

func (a *Analyzer) GenerateMarkdown(report model.IncidentReport) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# 🚨 Incident Containment & Rotation Report: %s\n\n", report.ID))
	sb.WriteString(fmt.Sprintf("- **Incident ID**: `%s`\n", report.ID))
	sb.WriteString(fmt.Sprintf("- **Timestamp**: %s\n", report.Timestamp.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("- **Severity Risk**: **%s**\n", report.Risk))
	sb.WriteString(fmt.Sprintf("- **Agent**: `%s` (PID: %d)\n", report.Agent, report.PID))
	sb.WriteString(fmt.Sprintf("- **Trigger Rule**: `%s`\n", report.Rule))
	sb.WriteString(fmt.Sprintf("- **Summary**: %s\n\n", report.Summary))

	sb.WriteString("## 📋 Priority \"Rotate-This\" Remediation Checklist\n\n")
	if len(report.RotateList) == 0 {
		sb.WriteString("_No high-risk credentials directly detected for automatic rotation._\n\n")
	} else {
		for i, rot := range report.RotateList {
			sb.WriteString(fmt.Sprintf("### %d. %s [%s]\n", i+1, rot.Name, rot.Risk))
			sb.WriteString(fmt.Sprintf("- **Category**: `%s`\n", rot.Category))
			if rot.Path != "" {
				sb.WriteString(fmt.Sprintf("- **Path**: `%s`\n", rot.Path))
			}
			sb.WriteString(fmt.Sprintf("- **Description**: %s\n", rot.Description))
			sb.WriteString(fmt.Sprintf("- **Action Required**: `%s`\n\n", rot.Action))
		}
	}

	sb.WriteString("## 🔍 Blast Radius Activity\n\n")

	sb.WriteString("### Accessed Files\n")
	if len(report.TouchedFiles) == 0 {
		sb.WriteString("_No specific files recorded._\n\n")
	} else {
		for _, f := range report.TouchedFiles {
			sb.WriteString(fmt.Sprintf("- `%s`\n", f))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("### Egress Connections\n")
	if len(report.Connections) == 0 {
		sb.WriteString("_No outbound connections recorded._\n\n")
	} else {
		for _, c := range report.Connections {
			sb.WriteString(fmt.Sprintf("- `%s`\n", c))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}
