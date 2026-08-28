package firewall

import (
	"encoding/base64"
	"strings"
	"testing"
)

func containsView(views []string, needle string) bool {
	for _, v := range views {
		if strings.Contains(v, needle) {
			return true
		}
	}
	return false
}

func TestNormalizeRawAlwaysPresent(t *testing.T) {
	if !containsView(Normalize([]byte("AKIAIOSFODNN7EXAMPLE")), "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("raw view must always be present")
	}
}

func TestNormalizeBase64(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	enc := base64.StdEncoding.EncodeToString([]byte(secret))
	if !containsView(Normalize([]byte(enc)), secret) {
		t.Fatal("base64-encoded secret should be revealed by Normalize")
	}
}

func TestNormalizeURLEncoded(t *testing.T) {
	if !containsView(Normalize([]byte("key%3DAKIAIOSFODNN7EXAMPLE")), "AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("url-encoded secret should be revealed")
	}
}
