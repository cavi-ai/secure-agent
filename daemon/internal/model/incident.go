package model

import "time"

type RiskLevel string

const (
	RiskCritical RiskLevel = "CRITICAL"
	RiskHigh     RiskLevel = "HIGH"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskLow      RiskLevel = "LOW"
)

type SecretCategory string

const (
	CategoryKeychain      SecretCategory = "KEYCHAIN"
	CategoryCloudCreds    SecretCategory = "CLOUD_CREDENTIALS"
	CategorySSHKeys       SecretCategory = "SSH_KEYS"
	CategoryEnvSecrets    SecretCategory = "ENV_SECRETS"
	CategorySourceControl SecretCategory = "SOURCE_CONTROL"
	CategorySystemConfig  SecretCategory = "SYSTEM_CONFIG"
	CategoryOther         SecretCategory = "OTHER"
)

type RotateItem struct {
	ID          string         `json:"id"`
	Category    SecretCategory `json:"category"`
	Name        string         `json:"name"`
	Path        string         `json:"path,omitempty"`
	Risk        RiskLevel      `json:"risk"`
	Description string         `json:"description"`
	Action      string         `json:"action"`
}

type IncidentReport struct {
	ID           string       `json:"id"`
	FlagID       string       `json:"flag_id"`
	PID          int32        `json:"pid"`
	Agent        string       `json:"agent"`
	Timestamp    time.Time    `json:"timestamp"`
	Rule         string       `json:"rule"`
	Summary      string       `json:"summary"`
	Risk         RiskLevel    `json:"risk"`
	TouchedFiles []string     `json:"touched_files"`
	Connections  []string     `json:"connections"`
	RotateList   []RotateItem `json:"rotate_list"`
}
