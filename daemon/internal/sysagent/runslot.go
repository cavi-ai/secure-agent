package sysagent

import (
	"fmt"
	"os"
	"path/filepath"
)

// The run slot holds the id of the one headless run in flight. These methods
// are its only accessors and expect the caller to hold a.mu.

// runBusy refuses with ErrBusy naming the run in flight, or returns nil.
func (a *Agent) runBusy() error {
	if a.running != 0 {
		return fmt.Errorf("%w: run %d is still running; one headless run at a time", ErrBusy, a.running)
	}
	return nil
}

// claimRun records id as the run in flight; the caller checked runBusy under the same hold of a.mu.
func (a *Agent) claimRun(id int64) { a.running = id }

func (a *Agent) releaseRun() { a.running = 0 }

// runningID is the run in flight, 0 when the slot is free.
func (a *Agent) runningID() int64 { return a.running }

// launchFolder checks the folder a run starts in; a headless harness is
// sandboxed to its folder, so / would scope it to the whole disk.
func launchFolder(mode, workdir string) (string, error) {
	const rootPath = string(filepath.Separator)
	resolved, err := filepath.EvalSymlinks(workdir)
	if err != nil || !filepath.IsAbs(resolved) {
		return "", fmt.Errorf("%w: the folder %s does not exist", ErrInvalid, workdir)
	}
	relative, err := filepath.Rel(rootPath, resolved)
	if err != nil || !filepath.IsLocal(relative) {
		return "", fmt.Errorf("%w: the folder %s does not exist", ErrInvalid, workdir)
	}
	if mode == ModeHeadless && relative == "." {
		return "", fmt.Errorf("%w: a headless run needs a folder narrower than /; pick one, or open it in a terminal", ErrInvalid)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return "", fmt.Errorf("%w: cannot inspect the launch folder: %v", ErrInvalid, err)
	}
	defer root.Close()
	if fi, err := root.Lstat(relative); err != nil || !fi.IsDir() {
		return "", fmt.Errorf("%w: the folder %s does not exist", ErrInvalid, workdir)
	}
	if mode == ModeTerminal {
		return workdir, nil
	}
	return resolved, nil
}
