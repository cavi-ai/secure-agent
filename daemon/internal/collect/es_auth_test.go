package collect

import (
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/sensitive"
)

func TestESAuthCollector_EvaluateAuthOpen(t *testing.T) {
	cfg := config.Config{
		KeychainMarkers: []string{"library/keychains", "login.keychain"},
	}
	classifier := sensitive.New(cfg)
	b := bus.New(100)
	sub := b.Subscribe()

	collector := NewESAuthCollector(b, classifier)

	// Test 1: Keychain path -> DENIED (false)
	keychainPath := "/Users/test/Library/Keychains/login.keychain-db"
	allow := collector.EvaluateAuthOpen(1234, "/usr/bin/python3", keychainPath)
	if allow {
		t.Fatalf("EvaluateAuthOpen(%q) = true, want false (DENY)", keychainPath)
	}

	select {
	case ev := <-sub:
		if ev.Kind != event.KindFileOpen || ev.PID != 1234 {
			t.Fatalf("unexpected event published: %+v", ev)
		}
	default:
		t.Fatal("expected event published to bus on DENY")
	}

	// Test 2: Normal path -> ALLOWED (true)
	normalPath := "/Users/test/workspace/readme.txt"
	allow = collector.EvaluateAuthOpen(1234, "/usr/bin/python3", normalPath)
	if !allow {
		t.Fatalf("EvaluateAuthOpen(%q) = false, want true (ALLOW)", normalPath)
	}
}
