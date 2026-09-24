// Package diskusage measures directories and volumes: allocated bytes, the
// newest modification time under a tree, and each volume's capacity and
// free space. Walks are bounded and never follow symlinks.
package diskusage

import (
	"context"
	"io/fs"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// WalkTimeout bounds one directory walk; a walk that hits it (or MaxEntries)
// reports a partial, lower-bound result.
const WalkTimeout = 30 * time.Second

// MaxEntries bounds the entries one walk visits.
const MaxEntries = 1_000_000

// Usage is one directory's measurement.
type Usage struct {
	Bytes   int64     // allocated bytes (st_blocks × 512)
	Files   int       // regular files and symlinks counted
	Newest  time.Time // newest modification time seen, the directory's own included
	Partial bool      // the walk stopped at a bound or ctx ended
}

// Dir walks root and sums allocated bytes. It never follows symlinks and
// does not descend into skip (for example other worktrees nested inside).
func Dir(ctx context.Context, root string, skip map[string]bool) Usage {
	return DirLimit(ctx, root, skip, MaxEntries)
}

// DirLimit is Dir with an explicit entry bound.
func DirLimit(ctx context.Context, root string, skip map[string]bool, limit int) Usage {
	ctx, cancel := context.WithTimeout(ctx, WalkTimeout)
	defer cancel()
	var u Usage
	entries := 0
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		entries++
		if entries > limit || (entries%4096 == 0 && ctx.Err() != nil) {
			u.Partial = true
			return filepath.SkipAll
		}
		if d.IsDir() && p != root && skip[p] {
			return filepath.SkipDir
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.ModTime().After(u.Newest) {
			u.Newest = info.ModTime()
		}
		if d.IsDir() {
			return nil
		}
		u.Files++
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			u.Bytes += st.Blocks * 512
		} else {
			u.Bytes += info.Size()
		}
		return nil
	})
	return u
}

// Volume is one mounted volume.
type Volume struct {
	Mount      string `json:"mount"`
	TotalBytes uint64 `json:"total_bytes"`
	FreeBytes  uint64 `json:"free_bytes"`
}

// Volumes reads capacity and free space once per filesystem holding paths.
// Volumes reporting the same capacity and free space (APFS volumes in one
// container) are one row with their mounts joined.
func Volumes(paths []string) []Volume {
	seen := map[[2]int32]bool{}
	var out []Volume
	for _, p := range paths {
		var st unix.Statfs_t
		if unix.Statfs(p, &st) != nil {
			continue
		}
		key := [2]int32{int32(st.Fsid.Val[0]), int32(st.Fsid.Val[1])}
		if seen[key] {
			continue
		}
		seen[key] = true
		mount := mountPoint(&st)
		if mount == "" {
			mount = Root(p)
		}
		out = append(out, Volume{
			Mount:      mount,
			TotalBytes: uint64(st.Blocks) * uint64(st.Bsize),
			FreeBytes:  uint64(st.Bavail) * uint64(st.Bsize),
		})
	}
	return mergeShared(out)
}

func mergeShared(vs []Volume) []Volume {
	var out []Volume
	for _, v := range vs {
		merged := false
		for i := range out {
			if out[i].TotalBytes == v.TotalBytes && out[i].FreeBytes == v.FreeBytes {
				out[i].Mount += " + " + v.Mount
				merged = true
				break
			}
		}
		if !merged {
			out = append(out, v)
		}
	}
	return out
}

// Root walks up from p while the device stays the same: the mount point.
func Root(p string) string {
	var st unix.Stat_t
	if unix.Stat(p, &st) != nil {
		return p
	}
	dev := st.Dev
	for {
		parent := filepath.Dir(p)
		if parent == p {
			return p
		}
		if unix.Stat(parent, &st) != nil || st.Dev != dev {
			return p
		}
		p = parent
	}
}

// SameDevice reports whether a and b sit on one filesystem.
func SameDevice(a, b string) bool {
	var sa, sb unix.Stat_t
	return unix.Stat(a, &sa) == nil && unix.Stat(b, &sb) == nil && sa.Dev == sb.Dev
}
