package intel

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

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
		if flag.PID != 0 && ev.PID != 0 && ev.PID != flag.PID {
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

	if strings.Contains(cleanPath, "/.aws/") || baseName == "credentials" || baseName == "config" {
		return &model.RotateItem{
			ID:          "rot-aws-creds",
			Category:    model.CategoryCloudCreds,
			Name:        "AWS Cloud Credentials",
			Path:        path,
			Risk:        model.RiskCritical,
			Description: "AWS credentials file (~/.aws/credentials) was read by an unverified agent process.",
			Action:      "Run `aws iam create-access-key` and deactivate old AWS Access Key IDs via AWS IAM Console.",
		}
	}

	if strings.Contains(cleanPath, "/.ssh/") || strings.HasPrefix(baseName, "id_") {
		return &model.RotateItem{
			ID:          fmt.Sprintf("rot-ssh-%s", baseName),
			Category:    model.CategorySSHKeys,
			Name:        fmt.Sprintf("SSH Keypair: %s", filepath.Base(path)),
			Path:        path,
			Risk:        model.RiskCritical,
			Description: "Private SSH key file was read by agent process.",
			Action:      "Revoke corresponding public key from `authorized_keys` and generate a new keypair via `ssh-keygen -t ed25519`.",
		}
	}

	if strings.Contains(cleanPath, "keychain") || strings.HasSuffix(cleanPath, ".keychain-db") {
		return &model.RotateItem{
			ID:          "rot-keychain-db",
			Category:    model.CategoryKeychain,
			Name:        "macOS Keychain Database",
			Path:        path,
			Risk:        model.RiskCritical,
			Description: "macOS Keychain file or Keychain CLI subcommand was accessed.",
			Action:      "Audit Keychain items via Keychain Access app; change passwords/tokens stored in the affected Keychain.",
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
