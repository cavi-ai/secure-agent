package sensitive

import (
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

func classifier(t *testing.T) Classifier {
	c, err := config.Load("/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	return New(c)
}

func TestClassify(t *testing.T) {
	cl := classifier(t)
	cases := []struct {
		path string
		want bool
	}{
		{"/Users/x/project/.env", true},
		{"/Users/x/project/.env.local", true},
		{"/Users/x/.ssh/id_ed25519", true},
		{"/Users/x/.aws/credentials", true},
		{"/Users/x/Library/Keychains/login.keychain-db", true},
		{"/Users/x/project/main.go", false},
		{"/Users/x/project/README.md", false},
	}
	for _, tc := range cases {
		cat, got := cl.Classify(tc.path)
		if got != tc.want {
			t.Errorf("Classify(%q) sensitive=%v (cat=%v), want %v", tc.path, got, cat, tc.want)
		}
	}
}
