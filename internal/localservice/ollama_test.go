package localservice

import (
	"strings"
	"testing"
)

func TestOllamaLoopbackAndProfileSettings(t *testing.T) {
	host, port, err := OllamaLoopback("")
	if err != nil || host != "127.0.0.1:11434" || port != 11434 {
		t.Fatalf("default loopback = %q port %d err %v", host, port, err)
	}
	kept, keptPort, err := OllamaLoopback("127.0.0.1:19001")
	if err != nil || kept != "127.0.0.1:19001" || keptPort != 19001 {
		t.Fatalf("explicit port = %q port %d err %v", kept, keptPort, err)
	}

	var profile Hardening
	found := false
	for _, item := range HardeningProfiles() {
		if item.Runtime == "ollama" {
			profile = item
			found = true
			break
		}
	}
	if !found {
		t.Fatal("ollama hardening profile missing")
	}
	if profile.Settings != OllamaSettings(host) {
		t.Fatalf("ollama settings = %q, want %q", profile.Settings, OllamaSettings(host))
	}
	if profile.Support != "browser_hardening_only" {
		t.Fatalf("ollama support = %q", profile.Support)
	}
	if !strings.HasSuffix(profile.Settings, "\nOLLAMA_ORIGINS=") {
		t.Fatalf("empty origins value missing from %q", profile.Settings)
	}
}
