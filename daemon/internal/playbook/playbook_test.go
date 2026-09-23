package playbook

import (
	"slices"
	"testing"
)

var correlatorRules = []string{
	"keychain-access", "keychain-security-cli", "proxy-payload-inspection", "proxy-prompt-injection",
	"proxy-secret-leak", "secret-in-transcript", "sensitive-read-then-connect", "tcc-tamper",
}

var servedActions = []string{"allow-host", "allow-path", "mute-rule-host", "mute-class", "open-incident", "dismiss", "kill"}

var stepKinds = []string{"guard-rule", "config", "secret-hygiene", "agent-instruction", "workflow"}

// Every rule the correlator emits has a complete playbook whose actions are
// served action ids and whose prevention steps have a known kind.
func TestEveryRuleHasAPlaybook(t *testing.T) {
	if got := Rules(); !slices.Equal(got, correlatorRules) {
		t.Fatalf("Rules() = %v, want %v", got, correlatorRules)
	}
	for _, r := range append(correlatorRules, "not-a-rule") {
		p := For(r)
		if p.Title == "" || p.Why == "" || len(p.Now) == 0 || len(p.Prevent) == 0 || len(p.Actions) == 0 {
			t.Errorf("%s: incomplete playbook %+v", r, p)
		}
		for _, s := range p.Prevent {
			if !slices.Contains(stepKinds, s.Kind) || s.Step == "" || s.Detail == "" {
				t.Errorf("%s: bad step %+v", r, s)
			}
		}
		for _, a := range p.Actions {
			if !slices.Contains(servedActions, a) {
				t.Errorf("%s: action %q is not served", r, a)
			}
		}
	}
	if p := For("not-a-rule"); p.Rule != "not-a-rule" || p.Title != "Finding" {
		t.Fatalf("unknown rule playbook = %+v", p)
	}
}

// A playbook is a value: changing a returned slice never changes the next
// caller's playbook.
func TestPlaybookIsACopy(t *testing.T) {
	p := For("secret-in-transcript")
	p.Now[0] = "changed"
	p.Prevent[0].Step = "changed"
	if q := For("secret-in-transcript"); q.Now[0] == "changed" || q.Prevent[0].Step == "changed" {
		t.Fatal("For returned shared slices")
	}
}
