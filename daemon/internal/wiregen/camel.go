package wiregen

import "strings"

// lowerCamel converts a snake_case JSON key to the lowerCamelCase property
// name a Swift mirror would use (e.g. "session_id" → "sessionId").
func lowerCamel(s string) string {
	parts := strings.Split(s, "_")
	for i := 1; i < len(parts); i++ {
		if parts[i] == "" {
			continue
		}
		parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
	}
	return strings.Join(parts, "")
}
