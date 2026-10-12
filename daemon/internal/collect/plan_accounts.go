package collect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// AccountPlans projects durable per-home observations onto current logins.
// Identity comes from Codex's account_id, never matching percentages, plan
// names, or reset times. Unidentified logins remain separate. Removed and
// API-key logins cannot carry a current ChatGPT subscription quota.
func AccountPlans() []PlanSnapshot {
	return accountPlans(Plans(), codexPlanIdentity)
}

// inactive is true only when the login was removed or explicitly uses an
// API key. Other read failures do not prove that a login was removed.
func codexPlanIdentity(home string) (key string, inactive bool) {
	f, err := os.Open(filepath.Join(home, "auth.json"))
	if err != nil {
		return "", os.IsNotExist(err)
	}
	defer f.Close()
	var auth struct {
		Mode   string `json:"auth_mode"`
		APIKey string `json:"OPENAI_API_KEY"`
		Tokens struct {
			AccountID string `json:"account_id"`
		} `json:"tokens"`
	}
	// Credential content is neither logged nor returned. Bound malformed files.
	if err := json.NewDecoder(io.LimitReader(f, 64<<10)).Decode(&auth); err != nil {
		return "", false
	}
	if auth.Mode == "apikey" || (auth.APIKey != "" && auth.Tokens.AccountID == "") {
		return "", true
	}
	if auth.Tokens.AccountID == "" {
		return "", false
	}
	sum := sha256.Sum256([]byte(auth.Tokens.AccountID))
	return hex.EncodeToString(sum[:]), false
}

func accountPlans(snapshots []PlanSnapshot, identity func(string) (string, bool)) []PlanSnapshot {
	groups := make(map[string]int)
	out := make([]PlanSnapshot, 0, len(snapshots))
	for _, p := range snapshots {
		account := ""
		if p.Harness == "codex" {
			var inactive bool
			account, inactive = identity(p.HomePath)
			if inactive {
				continue
			}
			// A login change must not reassign an earlier account's quota.
			if p.AccountKey != "" && p.AccountKey != account {
				continue
			}
		}
		p.AccountKey = account
		key := "home:" + p.HomePath
		if account != "" {
			key = p.Harness + ":" + account + ":" + p.LimitID
		}
		if i, ok := groups[key]; ok {
			homes := append(out[i].Homes, p.Home)
			if p.SeenAt.After(out[i].SeenAt) {
				out[i] = p
			}
			out[i].Homes = homes
		} else {
			groups[key] = len(out)
			p.Homes = []string{p.Home}
			out = append(out, p)
		}
	}
	for i := range out {
		slices.Sort(out[i].Homes)
		if len(out[i].Homes) > 1 {
			out[i].Home = "shared account"
		}
	}
	slices.SortFunc(out, func(a, b PlanSnapshot) int {
		return strings.Compare(a.Harness+":"+a.Home+":"+a.AccountKey+":"+a.LimitID+":"+a.HomePath,
			b.Harness+":"+b.Home+":"+b.AccountKey+":"+b.LimitID+":"+b.HomePath)
	})
	return out
}
