package firewall

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const maxNormalizedBytes = 1 << 20 // 1 MiB per view

var base64Chunk = regexp.MustCompile(`[A-Za-z0-9+/]{16,}={0,2}`)

// Normalize returns text views of data in which an embedded secret may become
// visible: the raw bytes, a URL-decoded view, a JSON-unescaped view, base64
// segments decoded, and a gzip-inflated view. Decoding is one level deep and
// each view is capped at maxNormalizedBytes.
func Normalize(data []byte) []string {
	if len(data) > maxNormalizedBytes {
		data = data[:maxNormalizedBytes]
	}
	raw := string(data)
	views := []string{raw}

	if dec, err := url.QueryUnescape(raw); err == nil && dec != raw {
		views = append(views, capView(dec))
	}
	if unq, err := strconv.Unquote(`"` + strings.ReplaceAll(raw, `"`, `\"`) + `"`); err == nil && unq != raw {
		views = append(views, capView(unq))
	}
	if gz, err := gzip.NewReader(bytes.NewReader(data)); err == nil {
		if out, err := io.ReadAll(io.LimitReader(gz, maxNormalizedBytes)); err == nil && len(out) > 0 {
			views = append(views, string(out))
		}
	}
	for _, chunk := range base64Chunk.FindAllString(raw, -1) {
		if dec, err := base64.StdEncoding.DecodeString(chunk); err == nil && len(dec) > 0 {
			views = append(views, capView(string(dec)))
		}
	}
	return views
}

func capView(s string) string {
	if len(s) > maxNormalizedBytes {
		return s[:maxNormalizedBytes]
	}
	return s
}
