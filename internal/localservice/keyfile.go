package localservice

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

var errKeyFile = errors.New("model API key unavailable; use an absolute path to an owned, owner-only regular file containing one 32-256 character URL-safe key")

// CreateKeyFile creates one random credential with exclusive creation. It does
// not print the key, create parent directories or replace an existing file.
func CreateKeyFile(path string) error {
	if !filepath.IsAbs(path) {
		return errKeyFile
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return errKeyFile
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return errors.New("model API key creation failed; parent directory must exist and destination must not exist")
	}
	_, writeErr := io.WriteString(f, base64.RawURLEncoding.EncodeToString(random)+"\n")
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return errKeyFile
	}
	return nil
}

// Authorize adds a model credential only after validating a local destination
// and a bounded private file. Callers must refuse the request on error and
// use a transport pinned to loopback and refuse redirects.
// Assessment probes never call this function.
func Authorize(req *http.Request, path string) error {
	if path == "" {
		return nil
	}
	if req == nil || req.URL == nil || !filepath.IsAbs(path) {
		return errKeyFile
	}
	if _, err := endpointURL(req.URL.String()); err != nil {
		return errKeyFile
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return errKeyFile
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errKeyFile
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() || stat.Nlink != 1 {
		return errKeyFile
	}
	data, err := io.ReadAll(io.LimitReader(f, 513))
	key := strings.TrimSpace(string(data))
	if err != nil || len(data) > 512 || len(key) < 32 || len(key) > 256 {
		return errKeyFile
	}
	for _, c := range key {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return errKeyFile
		}
	}
	req.Header.Set("Authorization", "Bearer "+key)
	return nil
}
