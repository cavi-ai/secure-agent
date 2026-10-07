package config

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// liveFields are the Config fields the config watcher applies without a
// restart, each with the watcher test that proves it.
var liveFields = map[string]string{
	"Agents":          "TestWatchConfigAppliesDisabledAgents",
	"DisabledAgents":  "TestWatchConfigAppliesDisabledAgents",
	"Advisor":         "TestWatchAdvisorConfigHotSwaps",
	"Fleet":           "TestWatchConfigHotSwapsFleet",
	"Pricing":         "TestWatchConfigAppliesPricingLive",
	"PricingSkipped":  "TestWatchConfigAppliesPricingLive",
	"ResourceControl": "TestWatchConfigHotSwapsResourcePolicy",
	"SystemAgent":     "TestWatchConfigAppliesSystemAgent",
	"Worktrees":       "TestWatchConfigAppliesWorktrees",
}

// Every live field names a watcher test that exists.
func TestLiveFieldsHaveWatcherTests(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "daemon", "advisor_watch_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	for field, test := range liveFields {
		if !strings.Contains(string(src), "func "+test+"(") {
			t.Errorf("live field %s names %s, which advisor_watch_test.go does not define", field, test)
		}
	}
}

// Every Config field is either applied live or listed as start-only, so a
// new field cannot silently go unreported when it changes.
func TestEveryConfigFieldIsClassified(t *testing.T) {
	ty := reflect.TypeOf(Config{})
	startOnlyFields := 0
	for i := 0; i < ty.NumField(); i++ {
		name := ty.Field(i).Name
		if _, live := liveFields[name]; live {
			continue
		}
		var a, b Config
		f := reflect.ValueOf(&b).Elem().Field(i)
		f.Set(nonZero(t, f.Type()))
		if len(RestartSettings(a, b)) != 1 {
			t.Errorf("Config.%s is neither live nor start-only", name)
		}
		startOnlyFields++
	}
	if startOnlyFields != len(startOnly) {
		t.Errorf("%d start-only fields, %d listed", startOnlyFields, len(startOnly))
	}
}

// nonZero returns a non-zero value of ty.
func nonZero(t *testing.T, ty reflect.Type) reflect.Value {
	t.Helper()
	v := reflect.New(ty).Elem()
	switch ty.Kind() {
	case reflect.String:
		v.SetString("x")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int64:
		v.SetInt(1)
	case reflect.Slice:
		v.Set(reflect.MakeSlice(ty, 1, 1))
	case reflect.Map:
		v.Set(reflect.MakeMap(ty))
		v.SetMapIndex(reflect.New(ty.Key()).Elem(), reflect.New(ty.Elem()).Elem())
	case reflect.Struct:
		for i := 0; i < ty.NumField(); i++ {
			if f := v.Field(i); f.CanSet() {
				f.Set(nonZero(t, f.Type()))
				return v
			}
		}
		t.Fatalf("struct %s has no settable field", ty)
	default:
		t.Fatalf("no non-zero value for %s", ty)
	}
	return v
}

func TestRestartSettingsNamesChangedStartOnlyKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	load := func(overlay string) Config {
		t.Helper()
		if err := os.WriteFile(path, []byte(overlay), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := LoadStrict(path)
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	running := load("advisor:\n  enabled: false\n")
	if got := RestartSettings(running, load("advisor:\n  enabled: false\n")); len(got) != 0 {
		t.Fatalf("unchanged file: %v", got)
	}
	if got := RestartSettings(running, load("advisor:\n  enabled: false\ndisabled_agents: [claude]\nworktrees:\n  stale_days: 9\n")); len(got) != 0 {
		t.Fatalf("live settings only: %v", got)
	}
	got := RestartSettings(running, load("firewall:\n  mode: block\nproxy_port: 9555\n"))
	if !slices.Equal(got, []string{"proxy_port", "firewall"}) {
		t.Fatalf("start-only changes: %v, want [proxy_port firewall]", got)
	}
}
