package firewall

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const maxNormalizedBytes = 1 << 20 // 1 MiB per view

var (
	base64Chunk = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)
	// byteList is at least eight comma-separated byte values, decimal or 0x:
	// a file's bytes written into source code or a request.
	byteList = regexp.MustCompile(`(?:(?:0[xX][0-9a-fA-F]{1,2}|[0-9]{1,3})\s*,\s*){7,}(?:0[xX][0-9a-fA-F]{1,2}|[0-9]{1,3})`)
	hexRun   = regexp.MustCompile(`[0-9a-fA-F]{32,}`)
)

// base64Encodings: standard, unpadded, URL-safe and unpadded URL-safe.
var base64Encodings = []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding}

// Normalize returns text views of data in which an embedded secret may become
// visible: the raw bytes, a URL-decoded view, a JSON-unescaped view, base64
// segments decoded (any of the four alphabets and paddings), byte lists and
// hex runs decoded, and a gzip-inflated view. Decoding is one level deep and
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
		for _, enc := range base64Encodings {
			if dec, err := enc.DecodeString(chunk); err == nil && len(dec) > 0 {
				views = append(views, capView(string(dec)))
				break
			}
		}
	}
	for _, list := range byteList.FindAllString(raw, -1) {
		if dec, ok := decodeByteList(list); ok {
			views = append(views, capView(dec))
		}
	}
	for _, run := range hexRun.FindAllString(raw, -1) {
		if dec, err := hex.DecodeString(run[:len(run)&^1]); err == nil {
			views = append(views, capView(string(dec)))
		}
	}
	return views
}

// decodeByteList turns "65, 0x4b, …" into the bytes it spells; a value over
// 255 means the list is not bytes.
func decodeByteList(list string) (string, bool) {
	parts := strings.Split(list, ",")
	out := make([]byte, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		base := 10
		if len(p) > 2 && (p[:2] == "0x" || p[:2] == "0X") {
			p, base = p[2:], 16
		}
		v, err := strconv.ParseUint(p, base, 8)
		if err != nil {
			return "", false
		}
		out = append(out, byte(v))
	}
	return string(out), true
}

func capView(s string) string {
	if len(s) > maxNormalizedBytes {
		return s[:maxNormalizedBytes]
	}
	return s
}
