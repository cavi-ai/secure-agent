package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/collect"
	"github.com/cavi-ai/secure-agent/daemon/internal/config"
)

// esTestLine renders a synthetic eslogger line in its compact layout:
// process first, then the event object keyed by its type.
func esTestLine(kind string, body map[string]any) string {
	b, err := json.Marshal(map[string]any{kind: body})
	if err != nil {
		panic(err)
	}
	return `{"process":{"audit_token":{"pid":4242},"executable":{"path":"/usr/bin/python3"},"is_platform_binary":true},` +
		`"event":` + string(b) + `,"time":"2026-09-25T12:00:00.000000000Z","event_type":10}`
}

func esOpenTestLine(path string) string {
	// json.Marshal sorts map keys, which is eslogger's own order here:
	// fflag before file, path first inside file.
	return esTestLine("open", map[string]any{"file": map[string]any{"path": path, "path_truncated": false}, "fflag": 1})
}

func TestKeepESLine(t *testing.T) {
	cases := []struct {
		name string
		line string
		want bool
	}{
		{"system dylib open", esOpenTestLine("/usr/lib/libSystem.B.dylib"), false},
		{"framework open", esOpenTestLine("/System/Library/Frameworks/Foundation.framework/Foundation"), false},
		{"dyld cache open", esOpenTestLine("/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e"), false},
		{"app bundle resource open", esOpenTestLine("/Applications/Tool.app/Contents/Frameworks/Lib.dylib"), false},
		{"package library open", esOpenTestLine("/opt/homebrew/Cellar/python@3.13/3.13.7/lib/python3.13/os.py"), false},
		{"command line tools sdk open", esOpenTestLine("/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/stdio.h"), false},
		{"dev null open", esOpenTestLine("/dev/null"), false},
		{"dtrace helper open", esOpenTestLine("/dev/dtracehelper"), false},
		{"spool self-read open", esOpenTestLine("/private/var/db/secure-agent/es-spool.jsonl"), false},
		{"user cache open", esOpenTestLine("/Users/dev/Library/Caches/com.example.tool/cache.db"), false},
		{"root dir open", esOpenTestLine("/"), false},
		{"escaped system path open", strings.Replace(esOpenTestLine("/usr/lib/libz.1.dylib"), `"/usr/lib/libz.1.dylib"`, `"\/usr\/lib\/libz.1.dylib"`, 1), false},
		{"spaced layout system open", `{"process": {"pid": 7}, "event": {"open": {"file": {"path": "/usr/lib/libz.1.dylib"}}}}`, false},

		{"aws credentials open", esOpenTestLine("/Users/dev/.aws/credentials"), true},
		{"ssh key open", esOpenTestLine("/Users/dev/.ssh/id_ed25519"), true},
		{"user keychain open", esOpenTestLine("/Users/dev/Library/Keychains/login.keychain-db"), true},
		{"system keychain open", esOpenTestLine("/Library/Keychains/System.keychain"), true},
		{"system trust store open", esOpenTestLine("/System/Library/Keychains/SystemRootCertificates.keychain"), true},
		{"env file in app bundle", esOpenTestLine("/Applications/Tool.app/Contents/Resources/.env"), true},
		{"env file in user cache", esOpenTestLine("/Users/dev/Library/Caches/tool/.env.local"), true},
		{"data volume user file", esOpenTestLine("/System/Volumes/Data/Users/dev/work/app/main.go"), true},
		{"workspace file open", esOpenTestLine("/Users/dev/work/app/main.go"), true},
		{"user account db open", esOpenTestLine("/private/var/db/dslocal/nodes/Default/users/dev.plist"), true},
		{"raw disk open", esOpenTestLine("/dev/disk3"), true},
		{"usr local open", esOpenTestLine("/usr/local/etc/tool.conf"), true},
		{"exec of system binary", esTestLine("exec", map[string]any{"target": map[string]any{"executable": map[string]any{"path": "/usr/bin/git"}}}), true},
		{"unlink under system prefix", esTestLine("unlink", map[string]any{"target": map[string]any{"path": "/usr/lib/libz.1.dylib"}}), true},
		{"rename", esTestLine("rename", map[string]any{"destination": map[string]any{"existing_file": map[string]any{"path": "/opt/homebrew/Cellar/x"}}}), true},
		{"tcc modify", esTestLine("tcc_modify", map[string]any{"service": "kTCCServiceSystemPolicyAllFiles"}), true},
		{"truncated open line", `{"process":{"pid":7},"event":{"open":{"fflag":1,"file":{"path":"/usr/lib/libSyst`, true},
		{"malformed line", `not json at all`, true},
		{"truncated envelope", `{"process":{"pid":7},"event":`, true},
	}
	for _, c := range cases {
		if got := keepESLine([]byte(c.line)); got != c.want {
			t.Errorf("%s: keepESLine = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestKeepESLineNeverDropsConfiguredSensitivePaths places every compiled-in
// sensitive glob and path (home-anchored ones under a neutral home) under
// every dropped prefix and requires the open to be kept.
func TestKeepESLineNeverDropsConfiguredSensitivePaths(t *testing.T) {
	cfg, err := config.Load(os.DevNull)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	home, _ := os.UserHomeDir()
	sample := func(pattern string) string {
		if home != "" {
			if rest, ok := strings.CutPrefix(pattern, home+"/"); ok {
				pattern = "/Users/dev/" + rest
			}
		}
		pattern = strings.TrimPrefix(pattern, "**/")
		pattern = strings.ReplaceAll(pattern, "**", "x")
		return strings.ReplaceAll(pattern, "*", "x")
	}
	var samples []string
	for _, g := range append(append([]string{}, cfg.SensitiveGlobs...), cfg.SensitivePaths...) {
		s := sample(g)
		if strings.HasPrefix(s, "/") {
			samples = append(samples, s) // anchored: checked where it lives
			continue
		}
		for _, p := range append(append([]string{}, esNoisePrefixes...),
			"/Applications/Tool.app/Contents/", "/Users/dev/Library/Caches/") {
			samples = append(samples, p+"pkg/"+s)
		}
	}
	for _, m := range cfg.KeychainMarkers {
		samples = append(samples, "/System/Volumes/Preboot/x/"+m+"/x")
	}
	if len(samples) < 20 {
		t.Fatalf("only %d samples built from the config", len(samples))
	}
	for _, s := range samples {
		if !keepESLine([]byte(esOpenTestLine(s))) {
			t.Errorf("open of configured sensitive path %q was dropped", s)
		}
	}
}

func TestPumpToSpoolDropsSystemOpensOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spool.jsonl")
	kept := []string{
		esOpenTestLine("/Users/dev/.aws/credentials"),
		esTestLine("exec", map[string]any{"target": map[string]any{"executable": map[string]any{"path": "/usr/bin/git"}}}),
		`not json at all`,
		esOpenTestLine("/Library/Keychains/System.keychain"),
	}
	dropped := []string{
		esOpenTestLine("/usr/lib/libSystem.B.dylib"),
		esOpenTestLine("/System/Library/Frameworks/Foundation.framework/Foundation"),
		esOpenTestLine("/dev/null"),
	}
	stream := dropped[0] + "\n" + kept[0] + "\n" + dropped[1] + "\n" + kept[1] + "\n" + kept[2] + "\n" + dropped[2] + "\n" + kept[3] + "\n"
	half := len(stream) / 2
	if err := pumpToSpoolAt(&chunkReader{chunks: []string{stream[:half], stream[half:]}}, path); err != nil {
		t.Fatalf("pumpToSpoolAt: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read spool: %v", err)
	}
	if want := strings.Join(kept, "\n") + "\n"; string(got) != want {
		t.Fatalf("spool =\n%s\nwant\n%s", got, want)
	}
	for _, d := range dropped {
		if bytes.Contains(got, []byte(d)) {
			t.Fatalf("dropped line reached the spool: %s", d)
		}
	}
}

func TestESFilterStatsReportsOncePerMinute(t *testing.T) {
	var s esFilterStats
	t0 := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	if _, ok := s.report(t0); ok {
		t.Fatal("reported at the start of the interval")
	}
	s.kept, s.dropped = 30, 70
	if _, ok := s.report(t0.Add(59 * time.Second)); ok {
		t.Fatal("reported before a minute passed")
	}
	msg, ok := s.report(t0.Add(time.Minute))
	if !ok || msg != "es-collector: dropped 70 of 100 lines (system-path opens) in the last 1m0s" {
		t.Fatalf("report = %q, %v", msg, ok)
	}
	if s.kept != 0 || s.dropped != 0 || !s.since.Equal(t0.Add(time.Minute)) {
		t.Fatalf("counters not reset: %+v", s)
	}
}

// BenchmarkESSpoolReplay replays a captured spool (SA_ES_REPLAY=<file>)
// through the daemon's per-line tail work — bufio.Scanner, ParseESLine, bus
// publish to a draining subscriber — for every captured line ("all") and for
// the lines keepESLine keeps ("kept"); "filter" is keepESLine's own cost in
// the helper over every line. cpu-ms/op is process user+system time.
func BenchmarkESSpoolReplay(b *testing.B) {
	path := os.Getenv("SA_ES_REPLAY")
	if path == "" {
		b.Skip("SA_ES_REPLAY unset")
	}
	all, err := os.ReadFile(path)
	if err != nil {
		b.Fatal(err)
	}
	var kept []byte
	for line := range bytes.Lines(all) {
		if keepESLine(bytes.TrimSuffix(line, []byte("\n"))) {
			kept = append(kept, line...)
		}
	}
	cpu := func() time.Duration {
		var ru syscall.Rusage
		_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
		return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
	}
	tail := func(data []byte, bs *bus.Bus) (lines, parsed int) {
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			lines++
			if e, ok := collect.ParseESLine(sc.Bytes()); ok {
				bs.Publish(e)
				parsed++
			}
		}
		return lines, parsed
	}
	for _, c := range []struct {
		name string
		data []byte
	}{{"all", all}, {"kept", kept}} {
		b.Run(c.name, func(b *testing.B) {
			bs := bus.New(4096)
			ch := bs.Subscribe()
			done := make(chan struct{})
			go func() {
				for range ch {
				}
				close(done)
			}()
			b.SetBytes(int64(len(c.data)))
			var lines, parsed int
			start := cpu()
			for b.Loop() {
				lines, parsed = tail(c.data, bs)
			}
			used := cpu() - start
			bs.Close()
			<-done
			b.ReportMetric(float64(used.Milliseconds())/float64(b.N), "cpu-ms/op")
			b.ReportMetric(float64(lines), "lines/op")
			b.ReportMetric(float64(parsed), "parsed/op")
			b.ReportMetric(float64(len(c.data))/1e6, "MB/op")
		})
	}
	b.Run("filter", func(b *testing.B) {
		b.SetBytes(int64(len(all)))
		start := cpu()
		for b.Loop() {
			for line := range bytes.Lines(all) {
				keepESLine(bytes.TrimSuffix(line, []byte("\n")))
			}
		}
		b.ReportMetric(float64((cpu()-start).Milliseconds())/float64(b.N), "cpu-ms/op")
	})
}
