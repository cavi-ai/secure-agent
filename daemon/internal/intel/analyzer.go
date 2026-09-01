package intel

import (
	"fmt"
	"path/filepath"
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

func (a *Analyzer) Analyze(flag model.Flag, events []event.Event) model.IncidentReport {
	incID := fmt.Sprintf("inc-%d-%d", flag.TS.Unix(), flag.PID)

	summary := fmt.Sprintf("Security rule '%s' triggered by agent '%s' (PID %d). Evidence: %s",
		flag.Rule, flag.Agent, flag.PID, strings.Join(flag.Evidence, ", "))

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

	// Always parse evidence strings from flag to extract target files & connections
	for _, evStr := range flag.Evidence {
		if strings.HasPrefix(evStr, "file:") {
			p := strings.TrimPrefix(evStr, "file:")
			p = strings.TrimSpace(p)
			if p != "" && !filesSeen[p] {
				filesSeen[p] = true
				report.TouchedFiles = append(report.TouchedFiles, p)
				item := a.classifyPath(p)
				if item != nil {
					report.RotateList = append(report.RotateList, *item)
				}
			}
		} else if strings.HasPrefix(evStr, "conn:") || strings.HasPrefix(evStr, "net:") {
			c := strings.TrimPrefix(evStr, "conn:")
			c = strings.TrimPrefix(c, "net:")
			c = strings.TrimSpace(c)
			if c != "" && !connsSeen[c] {
				connsSeen[c] = true
				report.Connections = append(report.Connections, c)
			}
		} else {
			// Extract file paths and connections formatted in evidence text
			if idx := strings.Index(evStr, " read "); idx != -1 {
				rest := evStr[idx+len(" read "):]
				if atIdx := strings.LastIndex(rest, " at "); atIdx != -1 {
					p := strings.TrimSpace(rest[:atIdx])
					if p != "" && !filesSeen[p] {
						filesSeen[p] = true
						report.TouchedFiles = append(report.TouchedFiles, p)
						item := a.classifyPath(p)
						if item != nil {
							report.RotateList = append(report.RotateList, *item)
						}
					}
				}
			} else if idx := strings.Index(evStr, " accessed keychain file "); idx != -1 {
				rest := evStr[idx+len(" accessed keychain file "):]
				if atIdx := strings.LastIndex(rest, " at "); atIdx != -1 {
					p := strings.TrimSpace(rest[:atIdx])
					if p != "" && !filesSeen[p] {
						filesSeen[p] = true
						report.TouchedFiles = append(report.TouchedFiles, p)
						item := a.classifyPath(p)
						if item != nil {
							report.RotateList = append(report.RotateList, *item)
						}
					}
				}
			} else if idx := strings.Index(evStr, " connected to "); idx != -1 {
				rest := evStr[idx+len(" connected to "):]
				if atIdx := strings.LastIndex(rest, " at "); atIdx != -1 {
					c := strings.TrimSpace(rest[:atIdx])
					if c != "" && !connsSeen[c] {
						connsSeen[c] = true
						report.Connections = append(report.Connections, c)
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

	// Keychain: only real keychain files, not any path containing "keychain".
	if strings.HasSuffix(cleanPath, ".keychain-db") || strings.HasSuffix(cleanPath, ".keychain") || strings.Contains(cleanPath, "/library/keychains/") {
		return &model.RotateItem{
			ID:          "rot-keychain-db",
			Category:    model.CategoryKeychain,
			Name:        "macOS Keychain Database",
			Path:        path,
			Risk:        model.RiskCritical,
			Description: "A macOS Keychain file was accessed.",
			Action:      "Enumerate the affected items with Keychain Access (or `security dump-keychain`), keyed on the (service, account) pair — not service alone, which only shows the first match — and change the passwords/tokens stored in them.",
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
