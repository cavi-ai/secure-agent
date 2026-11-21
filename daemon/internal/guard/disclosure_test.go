package guard

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestDisclosureSentences(t *testing.T) {
	const (
		fileTail = "Executable signatures are not verified. File approval does not authorize network access. Revoke under Protection → Rules & permissions."
		sendTail = "Executable signatures are not verified. Other sends still ask. Revoke under Protection → Rules & permissions."
		kindTail = "Executable signatures are not verified. Other kinds of send still ask. Revoke under Protection → Rules & permissions."
		facts    = "Agent: claude\nOperation: Read\nResource: /work/.env\nWorkspace: /work\nExecutable path: /bin/claude\nSession: sess"
	)
	dialog := func(effect, tail string) string {
		return effect + ".\n\n" + facts + "\n\n" + tail
	}
	base := ConfirmFacts{Agent: "claude", Operation: "Read", Resource: "/work/.env", Workspace: "/work", Executable: "/bin/claude", Session: "sess"}
	file := base
	file.RuleID = "env-files"
	egress := base
	egress.RuleID = model.EgressRule
	two := egress
	two.Categories = []string{"git-push", "gh-write"}
	three := egress
	three.Categories = []string{"git-push", "gh-write", "network-send"}
	none := egress

	tests := []struct {
		name    string
		facts   ConfirmFacts
		choice  model.ScopeChoice
		verdict string
		terms   string
		confirm string
	}{
		{
			name: "file session", facts: file, choice: model.ScopeChoice{Kind: "session"}, verdict: "allow",
			terms:   "Allows this file and tool until this session ends. " + fileTail,
			confirm: dialog("allow this file and tool until this session ends", fileTail),
		},
		{
			name: "file exact 24h", facts: file, choice: model.ScopeChoice{Kind: "exact", Expiry: "24h"}, verdict: "allow",
			terms:   "Allows this file and tool for 24 hours. " + fileTail,
			confirm: dialog("allow this file and tool for 24 hours", fileTail),
		},
		{
			name: "file exact 7d", facts: file, choice: model.ScopeChoice{Kind: "exact", Expiry: "7d"}, verdict: "allow",
			terms:   "Allows this file and tool for 7 days. " + fileTail,
			confirm: dialog("allow this file and tool for 7 days", fileTail),
		},
		{
			name: "egress session", facts: egress, choice: model.ScopeChoice{Kind: "session"}, verdict: "allow",
			terms:   "Allows these sends from this tool until this session ends. " + sendTail,
			confirm: dialog("allow these sends from this tool until this session ends", sendTail),
		},
		{
			name: "egress category two kinds", facts: two, choice: model.ScopeChoice{Kind: "session", Category: true}, verdict: "allow",
			terms:   "Allows all git pushes and GitHub writes (gh) from this tool in this workspace until this session ends. " + kindTail,
			confirm: dialog("allow all git pushes and GitHub writes (gh) from this tool in this workspace until this session ends", kindTail),
		},
		{
			name: "egress category three kinds", facts: three, choice: model.ScopeChoice{Kind: "session", Category: true}, verdict: "allow",
			terms:   "Allows all git pushes, GitHub writes (gh) and network sends from this tool in this workspace until this session ends. " + kindTail,
			confirm: dialog("allow all git pushes and GitHub writes (gh) and network sends from this tool in this workspace until this session ends", kindTail),
		},
		{
			name: "standing", facts: egress, choice: model.ScopeChoice{Kind: "standing"}, verdict: "allow",
			terms:   "Allows these sends from this tool until you revoke it. " + sendTail,
			confirm: dialog("allow these sends from this tool until revoked", sendTail),
		},
		{
			name: "once", facts: file, choice: model.ScopeChoice{Kind: "once"}, verdict: "allow",
			confirm: dialog("allow this file and tool for 24 hours", fileTail),
		},
		{
			name: "unknown", facts: file, choice: model.ScopeChoice{Kind: "future"}, verdict: "allow",
			confirm: dialog("allow this file and tool for 24 hours", fileTail),
		},
		{
			name: "category without kinds", facts: none, choice: model.ScopeChoice{Kind: "session", Category: true}, verdict: "allow",
			confirm: dialog("allow all  from this tool in this workspace until this session ends", kindTail),
		},
		{
			name: "always", facts: file, choice: model.ScopeChoice{Kind: "always"}, verdict: "allow",
			confirm: dialog("allow every future path matched by rule env-files", fileTail),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ButtonTerms(tc.facts.RuleID, tc.facts.Categories, tc.choice); got != tc.terms {
				t.Fatalf("ButtonTerms\n got %q\nwant %q", got, tc.terms)
			}
			if got := Confirm(tc.facts, tc.verdict, tc.choice); got != tc.confirm {
				t.Fatalf("Confirm\n got %q\nwant %q", got, tc.confirm)
			}
			disclosed := Disclose(tc.facts.RuleID, tc.facts.Categories, tc.choice)
			if tc.choice.Kind == "once" {
				if disclosed.Terms != "" || disclosed.Effect != "" || disclosed.Tail != "" {
					t.Fatalf("Disclose %+v", disclosed)
				}
				return
			}
			if disclosed.Terms != tc.terms || disclosed.Tail == "" {
				t.Fatalf("Disclose %+v", disclosed)
			}
			effect := disclosed.Effect
			if tc.choice.Kind == "always" {
				effect = tc.verdict + " " + effect
			}
			if !strings.HasPrefix(tc.confirm, effect+".\n\n") || !strings.HasSuffix(tc.confirm, disclosed.Tail) {
				t.Fatalf("effect %q tail %q do not frame %q", disclosed.Effect, disclosed.Tail, tc.confirm)
			}
		})
	}

	empty := Confirm(ConfirmFacts{}, "deny", model.ScopeChoice{Kind: "always"})
	if !strings.HasPrefix(empty, "deny every future path matched by rule unavailable.\n\nAgent: Unknown\nOperation: Unknown\nResource: Unknown\nWorkspace: Unknown\nExecutable path: Unknown\nSession: Unknown\n\n") {
		t.Fatalf("empty facts: %q", empty)
	}
}

func TestDiscloseOmitsEmptyButtonTerms(t *testing.T) {
	once := Disclose("env-files", nil, model.ScopeChoice{Kind: "once"})
	if once.Terms != "" || once.Effect != "" || once.Tail != "" {
		t.Fatalf("%+v", once)
	}
	raw, err := json.Marshal(once)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"terms"`, `"effect"`, `"tail"`} {
		if strings.Contains(string(raw), field) {
			t.Fatalf("once encoded %s: %s", field, raw)
		}
	}
	session := Disclose("env-files", nil, model.ScopeChoice{Kind: "session"})
	if session.Terms == "" || session.Effect == "" || session.Tail == "" {
		t.Fatalf("%+v", session)
	}
}
