package posture

import "testing"

func TestHumanFlagTitleSecretInTranscript(t *testing.T) {
	if got := HumanFlagTitle("secret-in-transcript"); got != "Secret appeared in an agent transcript" {
		t.Fatalf("humanFlagTitle(secret-in-transcript) = %q", got)
	}
}
