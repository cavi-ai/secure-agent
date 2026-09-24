package clutter

import (
	"os/exec"
	"path/filepath"
	"runtime"
)

var runtimeGOOS = runtime.GOOS

// toolCache is one developer tool's cache: where it lives and the tool's
// own clean command. Without a command (or with the tool not installed) the
// directory itself goes to the Trash; listOnly entries are never cleared
// from here (their contents are downloads a user chose, not a cache).
type toolCache struct {
	name     string
	path     string
	command  []string
	listOnly bool
	note     string
}

// toolCaches lists the known caches for this OS under home.
func toolCaches(home, goos string) []toolCache {
	lib := filepath.Join(home, "Library", "Caches")
	xdg := filepath.Join(home, ".cache")
	byOS := func(darwin, other string) string {
		if goos == "darwin" {
			return darwin
		}
		return other
	}
	return []toolCache{
		{name: "npm", path: filepath.Join(home, ".npm", "_cacache"), command: []string{"npm", "cache", "clean", "--force"}},
		{name: "yarn", path: byOS(filepath.Join(lib, "Yarn"), filepath.Join(xdg, "yarn")), command: []string{"yarn", "cache", "clean"}},
		{name: "pnpm", path: byOS(filepath.Join(home, "Library", "pnpm", "store"), filepath.Join(home, ".local", "share", "pnpm", "store")), command: []string{"pnpm", "store", "prune"}},
		{name: "go build", path: byOS(filepath.Join(lib, "go-build"), filepath.Join(xdg, "go-build")), command: []string{"go", "clean", "-cache"}},
		{name: "go modules", path: filepath.Join(home, "go", "pkg", "mod"), command: []string{"go", "clean", "-modcache"}, note: "modules download again on the next build"},
		{name: "pip", path: byOS(filepath.Join(lib, "pip"), filepath.Join(xdg, "pip")), command: []string{"pip3", "cache", "purge"}},
		{name: "uv", path: filepath.Join(xdg, "uv"), command: []string{"uv", "cache", "clean"}},
		{name: "Homebrew", path: byOS(filepath.Join(lib, "Homebrew"), filepath.Join(xdg, "Homebrew")), command: []string{"brew", "cleanup", "--prune=all"}},
		{name: "cargo registry", path: filepath.Join(home, ".cargo", "registry", "cache"), note: "crates download again on the next build"},
		{name: "Gradle", path: filepath.Join(home, ".gradle", "caches")},
		{name: "Playwright browsers", path: byOS(filepath.Join(lib, "ms-playwright"), filepath.Join(xdg, "ms-playwright")), note: "browsers download again on the next test run"},
		{name: "Xcode DerivedData", path: filepath.Join(home, "Library", "Developer", "Xcode", "DerivedData"), note: "Xcode rebuilds on the next build"},
		{name: "Hugging Face models", path: filepath.Join(xdg, "huggingface"), listOnly: true, note: "downloaded models: remove per model"},
	}
}

// appCacheRoots are the directories whose children are per-app caches.
func appCacheRoots(home, goos string) []string {
	if goos == "darwin" {
		return []string{filepath.Join(home, "Library", "Caches"), filepath.Join(home, ".cache")}
	}
	return []string{filepath.Join(home, ".cache")}
}

// toolDirs are where developer tools install outside launchd's PATH.
func toolDirs(home string) []string {
	return []string{
		"/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin",
		filepath.Join(home, ".local", "bin"), filepath.Join(home, ".cargo", "bin"),
		filepath.Join(home, "go", "bin"), filepath.Join(home, ".volta", "bin"),
		filepath.Join(home, ".bun", "bin"), filepath.Join(home, "Library", "pnpm"),
	}
}

// lookTool resolves a tool binary: the daemon's PATH first, then dirs (the
// usual install directories). "" when not installed.
func lookTool(name string, dirs []string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, d := range dirs {
		p := filepath.Join(d, name)
		if st, err := exec.LookPath(p); err == nil {
			return st
		}
	}
	return ""
}
