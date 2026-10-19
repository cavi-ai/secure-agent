package wiregen

import (
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	"github.com/cavi-ai/secure-agent/daemon/internal/api"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// The console and the menu bar validate daemon payloads against named copies
// of daemon enumerations. Each copy must equal its Go source, so adding a
// harness, bucket or item kind in Go fails here until the clients follow.

var quotedRe = regexp.MustCompile(`["']([a-z_]+)["']`)

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// literal returns the quoted words on the line that defines name.
func literal(t *testing.T, src, file, pattern string) []string {
	t.Helper()
	line := regexp.MustCompile(`(?m)^.*` + pattern + `.*$`).FindString(src)
	if line == "" {
		t.Fatalf("%s: no definition matching %q", file, pattern)
	}
	var out []string
	for _, m := range quotedRe.FindAllStringSubmatch(line, -1) {
		out = append(out, m[1])
	}
	return out
}

func pairs(words []string) map[string]string {
	out := map[string]string{}
	for i := 0; i+1 < len(words); i += 2 {
		out[words[i]] = words[i+1]
	}
	return out
}

func TestClientEnumerationsMatchTheDaemon(t *testing.T) {
	lib := readRepoFile(t, "daemon/internal/api/web_dist/lib.js")
	workbench := readRepoFile(t, "daemon/internal/api/web_dist/session-workbench.js")
	swift := readRepoFile(t, "menubar/Sources/SecureAgentMenubar/Models.swift")

	if got := literal(t, workbench, "session-workbench.js", `^const HOOK_HARNESSES = `); !slices.Equal(got, model.HookHarnesses) {
		t.Errorf("HOOK_HARNESSES = %v, want model.HookHarnesses %v", got, model.HookHarnesses)
	}
	for file, src := range map[string]string{"lib.js": lib, "Models.swift": swift} {
		bucketDef, kindsDef := `^const ATTENTION_BUCKETS = `, `^const POSTURE_ITEM_ATTENTION_KINDS = `
		if file == "Models.swift" {
			bucketDef, kindsDef = `static let attentionBuckets = `, `static let postureItemAttentionKinds = `
		}
		if got := literal(t, src, file, bucketDef); !slices.Equal(got, api.AttentionBuckets) {
			t.Errorf("%s attention buckets = %v, want api.AttentionBuckets %v", file, got, api.AttentionBuckets)
		}
		if got := pairs(literal(t, src, file, kindsDef)); !maps.Equal(got, api.PostureItemAttentionKinds) {
			t.Errorf("%s posture item kinds = %v, want api.PostureItemAttentionKinds %v", file, got, api.PostureItemAttentionKinds)
		}
	}
	// One named copy per client: no stray literal list left behind.
	if n := regexp.MustCompile(`\['claude', ?'codex'`).FindAllStringIndex(workbench, -1); len(n) != 1 {
		t.Errorf("session-workbench.js has %d harness list literals, want only HOOK_HARNESSES", len(n))
	}
}
