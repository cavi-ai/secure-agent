// Package clutter inventories what can be cleared on the machine besides
// worktrees: .tmp and .quarantine directories in and around repositories,
// regenerable build output inside repositories, developer tool caches and
// per-app caches. Each item carries its size, when it was last touched and
// the project it belongs to; clearing moves it to the Trash or runs the
// tool's own clean command, and the cleanup ledger books the bytes.
//
// Invariants:
//   - Nothing is deleted outright: items go to the Trash on their own
//     volume, or the owning tool clears its cache.
//   - An action applies only to a path in the current inventory, re-checked
//     at request time (exists, not a symlink, still that kind).
//   - A place with a live agent session is never cleared.
package clutter

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/diskusage"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
	"github.com/cavi-ai/secure-agent/daemon/internal/toolpath"
)

// ClutterItem kinds.
const (
	KindTmp        = "tmp"        // .tmp directories: scratch files and evidence
	KindQuarantine = "quarantine" // .quarantine directories: set aside to delete
	KindRepoCache  = "repo-cache" // regenerable build output inside a repository
	KindToolCache  = "tool-cache" // a developer tool's download or build cache
	KindAppCache   = "app-cache"  // one application's cache directory
)

// Actions an item offers.
const (
	ActionTrash = "trash" // move the directory to the Trash on its volume
	ActionClean = "clean" // run the owning tool's clean command
	ActionNone  = "none"  // listed only
)

// ClutterItem is one clearable directory.
type ClutterItem struct {
	ID          string     `json:"id"`
	Kind        string     `json:"kind"`
	Name        string     `json:"name"`
	Path        string     `json:"path"`
	Project     string     `json:"project,omitempty"`  // repository main path, when inside one
	Worktree    string     `json:"worktree,omitempty"` // linked worktree path, when inside one
	SizeBytes   int64      `json:"size_bytes,omitempty"`
	Files       int        `json:"files,omitempty"`
	SizePartial bool       `json:"size_partial,omitempty"`
	LastTouched *time.Time `json:"last_touched,omitempty"`
	IdleDays    int        `json:"idle_days"`
	Action      string     `json:"action"`
	Command     string     `json:"command,omitempty"` // the clean command, for display
	Note        string     `json:"note,omitempty"`
}

// ClutterKindTotal sums one kind.
type ClutterKindTotal struct {
	Kind  string `json:"kind"`
	Bytes int64  `json:"bytes"`
	Count int    `json:"count"`
}

// ClutterProjectTotal sums one project's items.
type ClutterProjectTotal struct {
	Project string `json:"project"`
	Bytes   int64  `json:"bytes"`
	Count   int    `json:"count"`
}

// ClutterReport is one inventory.
type ClutterReport struct {
	GeneratedAt time.Time             `json:"generated_at"`
	Sizing      bool                  `json:"sizing,omitempty"`
	Items       []ClutterItem         `json:"items"`
	Kinds       []ClutterKindTotal    `json:"kinds"`
	Projects    []ClutterProjectTotal `json:"projects"`
	Volumes     []diskusage.Volume    `json:"volumes,omitempty"`
	Reclaimed   *model.CleanupTotals  `json:"reclaimed,omitempty"` // the API fills it
	// Advice is the local advisor's plan per project ("machine" for
	// machine-wide caches); the API fills it.
	Advice map[string]model.AdvisorVerdict `json:"advice,omitempty"`
}

// Place is a directory the inventory searches: a repository's main
// worktree or a linked worktree.
type Place struct {
	Path     string
	Project  string
	Worktree string // set for linked worktrees
}

// Store is what the inventory records into. *store.Store satisfies it.
type Store interface {
	PutCleanup(model.CleanupEntry)
	WorkspaceActivity() []model.WorkspaceActivity
}

const (
	// cacheTTL is how long an inventory answers without a rebuild.
	cacheTTL = 10 * time.Minute
	// sizeTTL is how long a measured size answers without a new walk.
	sizeTTL = time.Hour
	// sizerWorkers bounds concurrent walks.
	sizerWorkers = 2
	// searchDepth bounds the search for .tmp/.quarantine/build output
	// inside a place: packages/<name>/node_modules sits three levels down.
	searchDepth = 3
	// ancestorDepth is how many directories above a repository are checked
	// for workspace-level .tmp and .quarantine directories.
	ancestorDepth = 3
)

// Clutter owns inventories, sizes and actions.
type Clutter struct {
	st     Store
	home   string
	places func(context.Context) []Place
	now    func() time.Time
	goos   string
	// binDirs are searched for tool binaries after the daemon's PATH.
	binDirs []string

	mu       sync.Mutex
	cached   *ClutterReport
	cachedAt time.Time

	scanMu sync.Mutex

	sizeMu sync.Mutex
	sizes  map[string]sizeEntry
	sizing bool
	sizeWG sync.WaitGroup
}

type sizeEntry struct {
	u  diskusage.Usage
	at time.Time
}

// New builds the inventory. places lists the repositories and worktrees to
// search (the worktree hunter's report); home "" resolves to the user's home.
func New(st Store, home string, places func(context.Context) []Place) *Clutter {
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	return &Clutter{st: st, home: home, places: places, now: time.Now, goos: runtimeGOOS,
		binDirs: toolpath.Dirs(home), sizes: map[string]sizeEntry{}}
}

// Report returns the inventory with sizes laid over it; items not measured
// yet are queued for the background sizer and the report says Sizing.
func (c *Clutter) Report(ctx context.Context, refresh bool) ClutterReport {
	return c.withSizes(c.inventory(ctx, refresh))
}

func (c *Clutter) inventory(ctx context.Context, refresh bool) ClutterReport {
	c.mu.Lock()
	if c.cached != nil && !refresh && c.now().Sub(c.cachedAt) < cacheTTL {
		r := *c.cached
		c.mu.Unlock()
		return r
	}
	c.mu.Unlock()
	c.scanMu.Lock()
	defer c.scanMu.Unlock()
	rep := ClutterReport{GeneratedAt: c.now().UTC(), Items: c.collect(ctx)}
	c.mu.Lock()
	c.cached, c.cachedAt = &rep, c.now()
	c.mu.Unlock()
	return rep
}

func (c *Clutter) invalidate() {
	c.mu.Lock()
	c.cached = nil
	c.mu.Unlock()
}

// collect gathers every item: per place, around places, then the machine's
// tool and app caches.
func (c *Clutter) collect(ctx context.Context) []ClutterItem {
	places := c.places(ctx)
	placeSet := map[string]bool{}
	for _, p := range places {
		placeSet[p.Path] = true
	}
	live := livePlaces(places, c.st.WorkspaceActivity())
	seen := map[string]bool{}
	var items []ClutterItem
	add := func(it ClutterItem) {
		if seen[it.Path] {
			return
		}
		seen[it.Path] = true
		it.ID = it.Kind + ":" + it.Path
		items = append(items, it)
	}
	for _, p := range places {
		hits := search(p.Path, placeSet)
		paths := make([]string, len(hits))
		for i, h := range hits {
			paths[i] = h.path
		}
		ok := disposable(ctx, p.Path, paths)
		for _, found := range hits {
			it := ClutterItem{Kind: found.kind, Name: filepath.Base(found.path), Path: found.path,
				Project: p.Project, Worktree: p.Worktree, Action: ActionTrash}
			switch {
			case live[p.Path]:
				it.Action, it.Note = ActionNone, "an agent session is live here"
			case !ok[found.path]:
				it.Action, it.Note = ActionNone, "not ignored by git, or holds tracked files: not a cache"
			}
			add(it)
		}
	}
	for _, p := range places {
		if p.Worktree != "" {
			continue
		}
		dir := p.Path
		for i := 0; i < ancestorDepth; i++ {
			dir = filepath.Dir(dir)
			if dir == c.home || dir == filepath.Dir(dir) || strings.Count(dir, "/") < 3 {
				break
			}
			for name, kind := range map[string]string{".tmp": KindTmp, ".quarantine": KindQuarantine} {
				d := filepath.Join(dir, name)
				if isDir(d) {
					add(ClutterItem{Kind: kind, Name: name, Path: d, Action: ActionTrash, Note: "workspace-level, outside any repository"})
				}
			}
		}
	}
	claimed := map[string]bool{}
	for _, tc := range toolCaches(c.home, c.goos) {
		if !isDir(tc.path) {
			continue
		}
		claimed[tc.path] = true
		it := ClutterItem{Kind: KindToolCache, Name: tc.name, Path: tc.path, Action: ActionTrash, Note: tc.note}
		switch {
		case tc.listOnly:
			it.Action = ActionNone
		case len(tc.command) > 0:
			if bin := toolpath.Look(tc.command[0], c.binDirs); bin != "" {
				it.Action, it.Command = ActionClean, strings.Join(tc.command, " ")
			}
		}
		add(it)
	}
	for _, root := range appCacheRoots(c.home, c.goos) {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			p := filepath.Join(root, e.Name())
			if !e.IsDir() || claimed[p] || claimsParent(claimed, p) {
				continue
			}
			add(ClutterItem{Kind: KindAppCache, Name: e.Name(), Path: p, Action: ActionTrash, Note: "quit the app first"})
		}
	}
	return items
}

// livePlaces marks each place holding a live agent session: the session's
// workspace is the place or under it, and not under a deeper place (a live
// session in a linked worktree does not freeze the repository around it).
func livePlaces(places []Place, activity []model.WorkspaceActivity) map[string]bool {
	out := map[string]bool{}
	for _, a := range activity {
		if !a.Live {
			continue
		}
		best := ""
		for _, p := range places {
			if (a.Workspace == p.Path || strings.HasPrefix(a.Workspace, p.Path+"/")) && len(p.Path) > len(best) {
				best = p.Path
			}
		}
		if best != "" {
			out[best] = true
		}
	}
	return out
}

// claimsParent reports whether a claimed tool cache lives inside p (p is a
// parent directory, like ~/.cache holding ~/.cache/uv).
func claimsParent(claimed map[string]bool, p string) bool {
	for c := range claimed {
		if strings.HasPrefix(c, p+"/") {
			return true
		}
	}
	return false
}

type found struct{ kind, path string }

// repoCaches are regenerable build output and dependency trees.
var repoCaches = map[string]bool{
	"node_modules": true, ".next": true, ".nuxt": true, ".turbo": true, ".parcel-cache": true,
	"dist": true, "build": true, "target": true, ".venv": true, "venv": true, "__pycache__": true,
	".pytest_cache": true, ".mypy_cache": true, ".ruff_cache": true, ".gradle": true, "DerivedData": true,
	".build": true, ".swiftpm": true,
}

// search finds .tmp, .quarantine and build output under root down to
// searchDepth, without descending into what it found, into .git, or into
// another place (a nested worktree is its own place).
func search(root string, places map[string]bool) []found {
	var out []found
	var walk func(dir string, level int)
	walk = func(dir string, level int) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			p := filepath.Join(dir, name)
			switch {
			case name == ".git" || places[p]:
				continue
			case name == ".tmp":
				out = append(out, found{KindTmp, p})
				continue
			case name == ".quarantine":
				out = append(out, found{KindQuarantine, p})
				continue
			case repoCaches[name]:
				out = append(out, found{KindRepoCache, p})
				continue
			}
			if level+1 < searchDepth && !strings.HasPrefix(name, ".") {
				walk(p, level+1)
			}
		}
	}
	walk(root, 0)
	return out
}

func isDir(p string) bool {
	st, err := os.Lstat(p)
	return err == nil && st.IsDir()
}

// withSizes copies rep and lays cached sizes, idle days and totals over it;
// items without a fresh size go to the background sizer.
func (c *Clutter) withSizes(rep ClutterReport) ClutterReport {
	items := append([]ClutterItem(nil), rep.Items...)
	now := c.now()
	var pending []string
	kinds := map[string]*ClutterKindTotal{}
	projects := map[string]*ClutterProjectTotal{}
	var vols []string
	for i := range items {
		it := &items[i]
		e, ok := c.cachedSize(it.Path)
		if !ok {
			pending = append(pending, it.Path)
		} else {
			it.SizeBytes, it.Files, it.SizePartial = e.u.Bytes, e.u.Files, e.u.Partial
			if !e.u.Newest.IsZero() {
				t := e.u.Newest.UTC()
				it.LastTouched = &t
				it.IdleDays = int(now.Sub(t).Hours() / 24)
			}
		}
		k := kinds[it.Kind]
		if k == nil {
			k = &ClutterKindTotal{Kind: it.Kind}
			kinds[it.Kind] = k
		}
		k.Bytes += it.SizeBytes
		k.Count++
		proj := it.Project
		if proj == "" {
			proj = "machine"
		}
		pt := projects[proj]
		if pt == nil {
			pt = &ClutterProjectTotal{Project: proj}
			projects[proj] = pt
		}
		pt.Bytes += it.SizeBytes
		pt.Count++
		vols = append(vols, it.Path)
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].SizeBytes > items[j].SizeBytes })
	rep.Items = items
	rep.Kinds = nil
	for _, k := range []string{KindTmp, KindQuarantine, KindRepoCache, KindToolCache, KindAppCache} {
		if t := kinds[k]; t != nil {
			rep.Kinds = append(rep.Kinds, *t)
		}
	}
	rep.Projects = nil
	for _, p := range projects {
		rep.Projects = append(rep.Projects, *p)
	}
	sort.Slice(rep.Projects, func(i, j int) bool { return rep.Projects[i].Bytes > rep.Projects[j].Bytes })
	rep.Sizing = len(pending) > 0
	rep.Volumes = diskusage.Volumes(uniqueRoots(vols))
	c.startSizing(pending)
	return rep
}

// uniqueRoots keeps one path per top-level directory: enough for Volumes
// to find every filesystem without a statfs per item.
func uniqueRoots(paths []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		parts := strings.SplitN(strings.TrimPrefix(p, "/"), "/", 3)
		key := "/" + parts[0]
		if len(parts) > 1 {
			key += "/" + parts[1]
		}
		if !seen[key] {
			seen[key] = true
			out = append(out, p)
		}
	}
	return out
}

func (c *Clutter) cachedSize(p string) (sizeEntry, bool) {
	c.sizeMu.Lock()
	defer c.sizeMu.Unlock()
	e, ok := c.sizes[p]
	if !ok || c.now().Sub(e.at) > sizeTTL {
		return sizeEntry{}, false
	}
	return e, true
}

func (c *Clutter) putSize(p string, u diskusage.Usage) {
	c.sizeMu.Lock()
	defer c.sizeMu.Unlock()
	c.sizes[p] = sizeEntry{u: u, at: c.now()}
}

func (c *Clutter) forgetSize(p string) {
	c.sizeMu.Lock()
	defer c.sizeMu.Unlock()
	delete(c.sizes, p)
}

// startSizing measures paths in the background unless a pass is running.
func (c *Clutter) startSizing(paths []string) {
	c.sizeMu.Lock()
	if c.sizing || len(paths) == 0 {
		c.sizeMu.Unlock()
		return
	}
	c.sizing = true
	c.sizeWG.Add(1)
	c.sizeMu.Unlock()
	go func() {
		defer c.sizeWG.Done()
		defer func() {
			c.sizeMu.Lock()
			c.sizing = false
			c.sizeMu.Unlock()
		}()
		ch := make(chan string)
		var wg sync.WaitGroup
		for i := 0; i < sizerWorkers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for p := range ch {
					c.putSize(p, diskusage.Dir(context.Background(), p, nil))
				}
			}()
		}
		for _, p := range paths {
			ch <- p
		}
		close(ch)
		wg.Wait()
	}()
}
