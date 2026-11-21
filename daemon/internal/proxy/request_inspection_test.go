package proxy

import "testing"

func TestCoveragePostureIncompleteInspection(t *testing.T) {
	incomplete := InspectionResult{Err: errInspectionLimit}
	if incomplete.Refuses(CoverageRecordAndForward) {
		t.Fatal("incomplete inspection refused under record-and-forward")
	}
	if !incomplete.Refuses(CoverageRefuse) {
		t.Fatal("incomplete inspection forwarded under coverage refuse")
	}
}

func TestClassifyProxyHitRules(t *testing.T) {
	cases := []struct {
		detail   string
		rule     string
		sub      string
		severity int
	}{
		{"proxy-untrusted-egress: paste.example.net after untrusted content", "proxy-untrusted-egress", "untrusted-egress", 3},
		{"proxy-untrusted-egress-monitored: 127.0.0.1 after untrusted content", "proxy-untrusted-egress-monitored", "untrusted-egress", 2},
		{"proxy-secret-leak", "proxy-secret-leak", "payload inspection", 3},
		{"proxy-secret-leak:aws-key", "proxy-secret-leak", "payload inspection", 3},
		{"proxy-prompt-injection", "proxy-prompt-injection", "payload inspection", 3},
		{"proxy-prompt-injection:ignore-previous", "proxy-prompt-injection", "payload inspection", 3},
		{"proxy-inspection-incomplete:body-limit", "proxy-inspection-incomplete", "payload inspection", 2},
		{"other", "proxy-payload-inspection", "payload inspection", 3},
	}
	for _, tc := range cases {
		rule, sub, severity := ClassifyProxyHit(tc.detail)
		if rule != tc.rule || sub != tc.sub || severity != tc.severity {
			t.Fatalf("%q: got %s %q %d, want %s %q %d", tc.detail, rule, sub, severity, tc.rule, tc.sub, tc.severity)
		}
	}
}
