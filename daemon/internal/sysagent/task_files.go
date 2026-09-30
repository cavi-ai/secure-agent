package sysagent

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// Each dispatch owns only this private directory, including files created by
// the harness itself. Requested outputs stay in the operator's working folder.
func (a *Agent) newTaskDir() (string, error) {
	if err := os.MkdirAll(a.stateDir, 0700); err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(a.stateDir, "task-")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, ".owner"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

var taskDirName = regexp.MustCompile(`^task-[0-9]+$`)

// Recover only our reserved task namespace. Never follow task symlinks, and
// preserve a live terminal shell that can outlive a daemon restart.
func (a *Agent) recoverTaskFiles() {
	entries, err := os.ReadDir(a.stateDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !taskDirName.MatchString(entry.Name()) {
			continue
		}
		dir := filepath.Join(a.stateDir, entry.Name())
		if entry.IsDir() && taskOwnerAlive(dir) {
			continue
		}
		_ = os.RemoveAll(dir)
	}
}

func taskOwnerAlive(dir string) bool {
	f, err := os.OpenFile(filepath.Join(dir, ".owner"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	data, err := io.ReadAll(io.LimitReader(f, 32))
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return false
	}
	err = syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

// Install cleanup before cd or launch. EXIT handles success/failure; signal
// handlers exit through the same cleanup. SIGKILL/crash leftovers are recovered
// on the next daemon start. Terminal replaces the creator with its own PID.
func terminalPrelude(l launch) string {
	cleanup := ""
	owner := ""
	if l.TaskDir != "" {
		cleanup = "/bin/rm -rf -- " + shellQuote(l.TaskDir)
		owner = fmt.Sprintf("printf '%%s\\n' \"$$\" > %s || exit 1\n", shellQuote(filepath.Join(l.TaskDir, ".owner")))
	} else {
		var paths []string
		for path := range l.Files {
			paths = append(paths, shellQuote(path))
		}
		if l.AnswerFile != "" {
			paths = append(paths, shellQuote(l.AnswerFile))
		}
		sort.Strings(paths)
		if len(paths) > 0 {
			cleanup = "/bin/rm -f -- " + strings.Join(paths, " ")
		} else {
			cleanup = ":"
		}
	}
	return "#!/bin/sh\numask 077\ncleanup() { " + cleanup + "; }\ntrap cleanup EXIT\n" +
		"trap 'exit 129' HUP\ntrap 'exit 130' INT\ntrap 'exit 143' TERM\n" + owner + "rm -f -- \"$0\"\n"
}
