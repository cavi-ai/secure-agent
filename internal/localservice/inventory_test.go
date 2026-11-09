package localservice

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func TestListenerInventoryKeepsBindingsWithoutReadingArguments(t *testing.T) {
	raw := "p42\ncPython\nf7\ntIPv4\nn127.0.0.1:23456\nf8\ntIPv6\nn[::1]:23456\np43\ncollama\nf9\ntIPv4\nn*:11434\np44\ncllama-server\nf10\ntIPv4\nn192.0.2.2:8080\n"
	got := parseListeners([]byte(raw))
	if got.State != "available" || len(got.Listeners) != 4 {
		t.Fatalf("inventory: %+v", got)
	}
	if got.Listeners[0].Endpoint != "http://127.0.0.1:23456" || got.Listeners[1].Endpoint != "http://[::1]:23456" || got.Listeners[2].Binding != "wildcard" || got.Listeners[2].Runtime != "ollama" || got.Listeners[3].Endpoint != "" || got.Listeners[3].Binding != "non_loopback" {
		t.Fatalf("binding evidence lost: %+v", got.Listeners)
	}
	if got.Listeners[0].Runtime != "unknown" {
		t.Fatal("a Python process name cannot identify an MLX server")
	}
}

func TestInventoryCapsListenerCountAndCommandOutput(t *testing.T) {
	var raw strings.Builder
	for port := 10000; port < 10200; port++ {
		fmt.Fprintf(&raw, "p42\ncserver\nf7\ntIPv4\nn127.0.0.1:%d\n", port)
	}
	got := parseListeners([]byte(raw.String()))
	if got.State != "partial" || !got.Truncated || len(got.Listeners) != maxListeners {
		t.Fatalf("unbounded inventory: %s %t %d", got.State, got.Truncated, len(got.Listeners))
	}
	output := &boundedOutput{}
	_, _ = output.Write([]byte(strings.Repeat("x", maxBody+1000)))
	_, _ = output.Write([]byte("ignored"))
	if len(output.data) != maxBody || !output.full {
		t.Fatal("native command output grew past its limit")
	}
}

func TestInventoryBoundsAndSelectionRemainExplicit(t *testing.T) {
	got := parseListeners([]byte(strings.Repeat("p42\ncserver\nf7\ntIPv4\nn127.0.0.1:2222\n", 2)))
	if len(got.Listeners) != 1 {
		t.Fatalf("duplicate listener retained: %+v", got)
	}
	got = parseListeners([]byte("p42\ncserver\nf7\ntIPv4\nninvalid\n"))
	if got.State != "partial" {
		t.Fatal("malformed inventory claimed complete")
	}
	var candidates []string
	for i := 0; i < 24; i++ {
		candidates = append(candidates, "http://127.0.0.1:"+strconv.Itoa(20000+i))
	}
	selected, omitted, err := selectEndpoints(candidates, Inventory{Listeners: []Listener{{Endpoint: "http://127.0.0.1:5555", Runtime: "ollama"}}})
	if err != nil || len(selected) != MaxEndpoints || selected[0] != candidates[0] || omitted < 9 {
		t.Fatalf("selection priority/bounds: %v %d %v", selected, omitted, err)
	}
	if _, _, err := selectEndpoints([]string{"http://example.com"}, Inventory{}); err == nil {
		t.Fatal("configured non-loopback endpoint accepted")
	}
}
