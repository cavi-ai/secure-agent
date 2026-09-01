package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// maxCertCacheEntries bounds the leaf-cert cache so a client connecting to
// unbounded distinct hosts can't grow it without limit.
const maxCertCacheEntries = 1024

type cacheEntry struct {
	cert     *tls.Certificate
	notAfter time.Time
}

type CAManager struct {
	caCert  *x509.Certificate
	caKey   *rsa.PrivateKey
	tlsCert tls.Certificate

	mu        sync.Mutex
	certCache map[string]*cacheEntry
}

func NewCAManager(certPath, keyPath string) (*CAManager, error) {
	if certPath == "" || keyPath == "" {
		home, _ := os.UserHomeDir()
		certPath = filepath.Join(home, ".config", "secure-agent", "ca.crt")
		keyPath = filepath.Join(home, ".config", "secure-agent", "ca.key")
	}

	caCert, caKey, err := loadOrCreateCA(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load/create CA: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caKey)}))
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA tls.Certificate: %w", err)
	}

	return &CAManager{
		caCert:    caCert,
		caKey:     caKey,
		tlsCert:   tlsCert,
		certCache: make(map[string]*cacheEntry),
	}, nil
}

func loadOrCreateCA(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey, error) {
	if err := os.MkdirAll(filepath.Dir(certPath), 0700); err != nil {
		return nil, nil, err
	}

	certBytes, certErr := os.ReadFile(certPath)
	keyBytes, keyErr := os.ReadFile(keyPath)

	if certErr == nil && keyErr == nil {
		// Refuse to load a CA key that is group/other-accessible: any local user
		// could read the trust anchor and MITM every agent that trusts this CA.
		// A too-permissive key is already compromised, so regenerate a fresh one.
		secure := true
		if fi, err := os.Stat(keyPath); err == nil && fi.Mode().Perm()&0o077 != 0 {
			log.Printf("proxy: WARNING: CA key %s has insecure permissions %#o (group/other-accessible); regenerating a fresh CA", keyPath, fi.Mode().Perm())
			secure = false
		}
		if secure {
			certBlock, _ := pem.Decode(certBytes)
			keyBlock, _ := pem.Decode(keyBytes)
			if certBlock != nil && keyBlock != nil {
				parsedCert, err1 := x509.ParseCertificate(certBlock.Bytes)
				parsedKey, err2 := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
				if err1 == nil && err2 == nil {
					return parsedCert, parsedKey, nil
				}
			}
		}
	}

	// Create Root CA
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"SecureAgent Local CA"},
			CommonName:   "SecureAgent Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDer, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	parsedCert, err := x509.ParseCertificate(certDer)
	if err != nil {
		return nil, nil, err
	}

	// Persist. The key must land at 0600; a write failure is fatal to this call
	// so the daemon never silently runs with a non-persisted CA that regenerates
	// on every start (invalidating the CA path already exported to agents).
	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDer})
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	if err := os.WriteFile(keyPath, keyPem, 0o600); err != nil {
		return nil, nil, fmt.Errorf("failed to persist CA key: %w", err)
	}
	if err := os.WriteFile(certPath, certPem, 0o644); err != nil {
		return nil, nil, fmt.Errorf("failed to persist CA cert: %w", err)
	}

	return parsedCert, key, nil
}

func (cm *CAManager) GetCertificateForHost(host string) (*tls.Certificate, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Serve a cached leaf only while it is comfortably before expiry, so a
	// long-running daemon never hands out an expired cert.
	if e, ok := cm.certCache[host]; ok && time.Now().Before(e.notAfter.Add(-24*time.Hour)) {
		return e.cert, nil
	}

	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := time.Now().Add(365 * 24 * time.Hour)
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	certDer, err := x509.CreateCertificate(rand.Reader, template, cm.caCert, &cm.caKey.PublicKey, cm.caKey)
	if err != nil {
		return nil, err
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDer, cm.caCert.Raw},
		PrivateKey:  cm.caKey,
	}

	// Bound the cache: on overflow, drop it wholesale (simple, correct; the certs
	// are cheap to re-mint) rather than growing without limit.
	if len(cm.certCache) >= maxCertCacheEntries {
		cm.certCache = make(map[string]*cacheEntry)
	}
	cm.certCache[host] = &cacheEntry{cert: tlsCert, notAfter: notAfter}
	return tlsCert, nil
}
