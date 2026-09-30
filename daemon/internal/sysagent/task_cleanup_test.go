package sysagent

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

func TestTerminalTaskDeletesWorkspaceOnEveryExit(t *testing.T) {
	for _, outcome := range []string{"success", "failure", "missing-folder", "terminated"} {
		t.Run(outcome, func(t *testing.T) {
			ol := newFakeOllama(t, "0.15.1", "qwen3")
			work := t.TempDir()
			marker := filepath.Join(work, "requested-output")
			body := "touch " + shellQuote(marker) + "\n"
			switch outcome {
			case "failure":
				body += "exit 7\n"
			case "terminated":
				body += "printf 'ready\\n'\nsleep 60\n"
			}
			bin := fakeBin(t, t.TempDir(), "openclaw", body)
			a, _ := testAgent(t, ol.URL, map[string]string{"openclaw": bin})
			if err := os.MkdirAll(a.stateDir, 0700); err != nil {
				t.Fatal(err)
			}
			keep := filepath.Join(a.stateDir, "keep-settings")
			if err := os.WriteFile(keep, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			p, err := a.SavePlan(PlanInput{Harness: "openclaw", Mode: ModeTerminal, Workdir: work, Task: "test"})
			if err != nil {
				t.Fatal(err)
			}
			var script string
			a.openTerminal = func(path string) error { script = path; return nil }
			if _, err := a.Dispatch(context.Background(), DispatchInput{PlanID: p.ID}); err != nil {
				t.Fatal(err)
			}
			taskDir := filepath.Dir(script)
			if err := os.WriteFile(filepath.Join(taskDir, "runtime-cache"), []byte("synthetic task data"), 0600); err != nil {
				t.Fatal(err)
			}
			if outcome == "missing-folder" {
				if err := os.RemoveAll(work); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/bin/sh", script)
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			if outcome == "terminated" {
				ready := make(chan bool, 1)
				go func() {
					scanner := bufio.NewScanner(stdout)
					for scanner.Scan() {
						if scanner.Text() == "ready" {
							ready <- true
							return
						}
					}
					ready <- false
				}()
				select {
				case ok := <-ready:
					if !ok {
						_ = cmd.Cancel()
						_ = cmd.Wait()
						t.Fatal("task did not start")
					}
				case <-ctx.Done():
					_ = cmd.Cancel()
					_ = cmd.Wait()
					t.Fatal("task startup timed out")
				}
				a.Recover()
				if _, err := os.Stat(taskDir); err != nil {
					t.Fatal("recovery removed a live terminal workspace")
				}
				if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
			}
			err = cmd.Wait()
			if outcome == "success" && err != nil {
				t.Fatalf("command failed: %v", err)
			}
			if outcome != "success" && err == nil {
				t.Fatal("failure status was swallowed")
			}
			if _, err := os.Stat(taskDir); !os.IsNotExist(err) {
				t.Fatal("task workspace survived its exit")
			}
			if got, err := os.ReadFile(keep); err != nil || string(got) != "keep" {
				t.Fatal("cleanup changed unrelated app state")
			}
			if outcome == "success" {
				if _, err := os.Stat(marker); err != nil {
					t.Fatal("cleanup removed requested output")
				}
			}
		})
	}
}

func TestRecoverDoesNotFollowOwnerSymlink(t *testing.T) {
	a, _ := testAgent(t, "http://127.0.0.1:1", nil)
	dir := filepath.Join(a.stateDir, "task-104")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "owner")
	if err := os.WriteFile(outside, []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, ".owner")); err != nil {
		t.Fatal(err)
	}
	a.Recover()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("recovery trusted a symlinked owner file")
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatal("recovery changed the symlink target")
	}
}

func TestRecoverDoesNotBlockOnOwnerFIFO(t *testing.T) {
	a, _ := testAgent(t, "http://127.0.0.1:1", nil)
	dir := filepath.Join(a.stateDir, "task-105")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	owner := filepath.Join(dir, ".owner")
	if err := syscall.Mkfifo(owner, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { a.Recover(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		// Unblock the old reader so even a failing regression leaves no goroutine.
		f, err := os.OpenFile(owner, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			_ = f.Close()
		}
		<-done
		t.Fatal("recovery blocked on a non-regular owner file")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("invalid owner workspace survived")
	}
}

func TestLocalTerminalTaskDeletesWorkspace(t *testing.T) {
	ol := newFakeOllama(t, "0.15.1", "qwen3")
	a, st := testAgent(t, ol.URL, nil)
	work := t.TempDir()
	output := filepath.Join(work, "requested-output")
	var script string
	a.openTerminal = func(path string) error { script = path; return nil }
	id := st.PutSysAgentMessage(model.SysAgentMessage{TS: time.Now(), Role: "assistant", LocalCommand: &model.SysAgentLocalCommand{Workdir: work, Command: "touch " + shellQuote(output), Mode: ModeTerminal}})
	if _, err := a.RunLocal(id); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(script)
	if err := exec.Command("/bin/sh", script).Run(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("local task workspace survived")
	}
	if _, err := os.Stat(output); err != nil {
		t.Fatal("requested output was removed")
	}
}

func TestLocalTaskTemporaryFilesAreDeleted(t *testing.T) {
	for _, mode := range []string{ModeHeadless, ModeTerminal} {
		t.Run(mode, func(t *testing.T) {
			a, st := testAgent(t, "http://127.0.0.1:1", nil)
			work := t.TempDir()
			output := filepath.Join(work, "requested-output")
			var script string
			a.openTerminal = func(path string) error { script = path; return nil }
			command := `test -n "$TMPDIR" || exit 8; printf 'synthetic data' > "$TMPDIR/sensitive"; printf '%s' "$TMPDIR" > ` + shellQuote(output)
			id := st.PutSysAgentMessage(model.SysAgentMessage{TS: time.Now(), Role: "assistant", LocalCommand: &model.SysAgentLocalCommand{Workdir: work, Command: command, Mode: mode}})
			if _, err := a.RunLocal(id); err != nil {
				t.Fatal(err)
			}
			if mode == ModeTerminal {
				if err := exec.Command("/bin/sh", script).Run(); err != nil {
					t.Fatal(err)
				}
			} else {
				a.Wait()
			}
			data, err := os.ReadFile(output)
			if err != nil {
				t.Fatalf("command did not receive a private temporary directory: %v", err)
			}
			dir := string(data)
			if !strings.HasPrefix(dir, a.stateDir+string(filepath.Separator)+"task-") {
				t.Fatalf("temporary directory was outside the task workspace: %q", dir)
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatal("temporary command data survived")
			}
		})
	}
}

func TestRecoverDeletesOnlyOrphanedTaskWorkspaces(t *testing.T) {
	a, _ := testAgent(t, "http://127.0.0.1:1", nil)
	for name, owner := range map[string]string{"task-100": "2147483647", "task-101": strconv.Itoa(os.Getpid()), "task-102": "invalid", "keep": "2147483647"} {
		dir := filepath.Join(a.stateDir, name)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".owner"), []byte(owner), 0600); err != nil {
			t.Fatal(err)
		}
	}
	outside := t.TempDir()
	output := filepath.Join(outside, "keep")
	if err := os.WriteFile(output, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(a.stateDir, "task-103")); err != nil {
		t.Fatal(err)
	}
	a.Recover()
	for _, name := range []string{"task-100", "task-102", "task-103"} {
		if _, err := os.Lstat(filepath.Join(a.stateDir, name)); !os.IsNotExist(err) {
			t.Errorf("orphan %s survived", name)
		}
	}
	for _, name := range []string{"task-101", "keep"} {
		if _, err := os.Stat(filepath.Join(a.stateDir, name)); err != nil {
			t.Errorf("preserved directory %s disappeared", name)
		}
	}
	if _, err := os.Stat(output); err != nil {
		t.Fatal("cleanup followed symlink outside task directory")
	}
}

func TestHeadlessTaskDeletesHarnessCreatedFiles(t *testing.T) {
	ol := newFakeOllama(t, "0.15.1", "qwen3")
	bin := fakeBin(t, t.TempDir(), "openclaw", `test "$TMPDIR" = "$(dirname "$OPENCLAW_CONFIG_PATH")" || exit 8
printf 'cache' > "$(dirname "$OPENCLAW_CONFIG_PATH")/runtime-cache"
printf 'synthetic data' > "$TMPDIR/sensitive"`+"\n")
	a, _ := testAgent(t, ol.URL, map[string]string{"openclaw": bin})
	p, err := a.SavePlan(PlanInput{Harness: "openclaw", Mode: ModeHeadless, Workdir: t.TempDir(), Task: "test"})
	if err != nil {
		t.Fatal(err)
	}
	run, err := a.Dispatch(context.Background(), DispatchInput{PlanID: p.ID})
	if err != nil {
		t.Fatal(err)
	}
	a.Wait()
	completed := a.st.SysAgentRuns(1)
	if len(completed) != 1 || completed[0].ID != run.ID || completed[0].Status != "done" {
		t.Fatalf("harness did not receive a private temporary directory: %+v", completed)
	}
	entries, err := os.ReadDir(a.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("temporary artifacts survived: %v", entries)
	}
}
