package collect

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
)

// eslogger writes every process as a full object (audit tokens, code
// signing, a stat of the executable) and every file with its stat: about
// ten times the fields ParseESLine reads. The privileged collector keeps
// only those fields before a line reaches the spool, so the spool's disk
// writes and the daemon's decoding scale with what the daemon uses.

// esShape is the fields of one JSON object a compact line keeps: a nil
// value keeps the field's value as it is, a shape keeps the named fields of
// an object value.
type esShape map[string]esShape

// esKeep is the shape of esEnvelope: every field ParseESLine decodes.
var esKeep = shapeOf(reflect.TypeFor[esEnvelope]())

// field looks up a quoted object key the way json.Unmarshal matches struct
// fields: without regard to ASCII case, after unescaping.
func (s esShape) field(quoted []byte) (esShape, bool) {
	raw := quoted[1 : len(quoted)-1]
	if bytes.IndexByte(raw, '\\') >= 0 {
		var k string
		if json.Unmarshal(quoted, &k) != nil {
			return nil, false
		}
		raw = []byte(k)
	}
	var buf [64]byte
	if len(raw) > len(buf) {
		return nil, false
	}
	for i, c := range raw {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		buf[i] = c
	}
	child, ok := s[string(buf[:len(raw)])]
	return child, ok
}

var rawMessageType = reflect.TypeFor[json.RawMessage]()

func shapeOf(t reflect.Type) esShape {
	s := esShape{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		name = strings.ToLower(name)
		ft := f.Type
		for ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if f.Anonymous && name == "" && ft.Kind() == reflect.Struct {
			for k, v := range shapeOf(ft) {
				s[k] = v
			}
			continue
		}
		if name == "" || name == "-" {
			continue
		}
		if ft.Kind() == reflect.Struct && ft != rawMessageType {
			s[name] = shapeOf(ft)
		} else {
			s[name] = nil
		}
	}
	return s
}

// CompactESLine appends to dst the eslogger line reduced to the fields
// ParseESLine reads, which decodes to the same event. ok is false, and dst
// unchanged, when line is not one JSON object: the caller keeps it as it is.
func CompactESLine(dst, line []byte) (out []byte, ok bool) {
	b := bytes.TrimSpace(line)
	start := len(dst)
	end, out, ok := compactObject(dst, b, 0, esKeep)
	if !ok || skipSpace(b, end) != len(b) {
		return dst[:start], false
	}
	return out, true
}

// compactObject appends the object at b[i] reduced to shape and returns the
// index past it.
func compactObject(dst, b []byte, i int, shape esShape) (int, []byte, bool) {
	i = skipSpace(b, i)
	if i >= len(b) || b[i] != '{' {
		return 0, dst, false
	}
	dst = append(dst, '{')
	first := true
	i = skipSpace(b, i+1)
	if i < len(b) && b[i] == '}' {
		return i + 1, append(dst, '}'), true
	}
	for {
		i = skipSpace(b, i)
		if i >= len(b) || b[i] != '"' {
			return 0, dst, false
		}
		keyEnd, ok := skipString(b, i)
		if !ok {
			return 0, dst, false
		}
		key := b[i:keyEnd] // with its quotes
		i = skipSpace(b, keyEnd)
		if i >= len(b) || b[i] != ':' {
			return 0, dst, false
		}
		i = skipSpace(b, i+1)
		child, keep := shape.field(key)
		if keep {
			if !first {
				dst = append(dst, ',')
			}
			first = false
			dst = append(dst, key...)
			dst = append(dst, ':')
		}
		if keep && child != nil && i < len(b) && b[i] == '{' {
			var ok bool
			if i, dst, ok = compactObject(dst, b, i, child); !ok {
				return 0, dst, false
			}
		} else {
			end, ok := skipValue(b, i)
			if !ok {
				return 0, dst, false
			}
			if keep {
				dst = append(dst, b[i:end]...)
			}
			i = end
		}
		i = skipSpace(b, i)
		if i >= len(b) {
			return 0, dst, false
		}
		switch b[i] {
		case ',':
			i++
		case '}':
			return i + 1, append(dst, '}'), true
		default:
			return 0, dst, false
		}
	}
}

func skipSpace(b []byte, i int) int {
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	return i
}

// skipString returns the index past the JSON string starting at b[i].
func skipString(b []byte, i int) (int, bool) {
	for k := i + 1; k < len(b); k++ {
		switch b[k] {
		case '\\':
			k++
		case '"':
			return k + 1, true
		}
	}
	return 0, false
}

// skipValue returns the index past the JSON value starting at b[i]. Only
// strings and nesting are checked; json.Unmarshal of the compact line
// rejects anything else that is malformed, as it would the original.
func skipValue(b []byte, i int) (int, bool) {
	if i >= len(b) {
		return 0, false
	}
	switch b[i] {
	case '"':
		return skipString(b, i)
	case '{', '[':
		depth := 0
		for k := i; k < len(b); k++ {
			switch b[k] {
			case '"':
				end, ok := skipString(b, k)
				if !ok {
					return 0, false
				}
				k = end - 1
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return k + 1, true
				}
			}
		}
		return 0, false
	}
	k := i
	for k < len(b) && b[k] != ',' && b[k] != '}' && b[k] != ']' && b[k] != ' ' && b[k] != '\t' && b[k] != '\n' && b[k] != '\r' {
		k++
	}
	return k, k > i
}
