package proxy

import (
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestCAKeyPersists0600AndStable(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "ca.crt")
	key := filepath.Join(dir, "ca.key")
	a, err := NewCAManager(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(key)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("CA key perms = %o, want 0600", fi.Mode().Perm())
	}
	b, err := NewCAManager(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if a.caCert.SerialNumber.Cmp(b.caCert.SerialNumber) != 0 {
		t.Fatal("reloading a 0600 CA must keep the same cert")
	}
}

func TestCAKeyInsecurePermsRegenerates(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "ca.crt")
	key := filepath.Join(dir, "ca.key")
	a, err := NewCAManager(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	old := a.caCert.SerialNumber.String()
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := NewCAManager(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if b.caCert.SerialNumber.String() == old {
		t.Fatal("world-readable CA key must be regenerated, not reused")
	}
	fi, err := os.Stat(key)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("regenerated CA key perms = %o, want 0600", fi.Mode().Perm())
	}
}

func TestGetCertificateForHostDNSAndIP(t *testing.T) {
	dir := t.TempDir()
	cm, err := NewCAManager(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := cm.GetCertificateForHost("example.test")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.DNSNames) != 1 || parsed.DNSNames[0] != "example.test" {
		t.Fatalf("DNS SAN = %v", parsed.DNSNames)
	}
	ipLeaf, err := cm.GetCertificateForHost("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	ipParsed, err := x509.ParseCertificate(ipLeaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(ipParsed.IPAddresses) != 1 || !ipParsed.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("IP SAN = %v", ipParsed.IPAddresses)
	}
}
