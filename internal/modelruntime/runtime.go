// Package modelruntime installs the pinned model engine in a private location.
package modelruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// Revision is the immutable engine source used by the managed runtime installer.
const Revision = "cd65df238ab171ecb289b762b8bccd48bcf779e5"

func Root() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "secure-agent", "model-runtime", Revision)
}

// Find prefers the engine installed for this Secure Agent version. Existing
// global installations are retained and still checked by their callers.
func Find() (string, error) {
	if binary := OwnedBinary(); binary != "" {
		return binary, nil
	}
	return findTool("mlx-agent")
}

func OwnedBinary() string { return ownedAt(Root()) }

func privateDir(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Getuid()
}

func ownedAt(root string) string {
	if !privateDir(root) {
		return ""
	}
	f, err := os.OpenFile(filepath.Join(root, ".ready"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ""
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !privateFile(info) {
		return ""
	}
	ready, err := io.ReadAll(io.LimitReader(f, 41))
	if err != nil || string(ready) != Revision {
		return ""
	}
	binary := filepath.Join(root, "bin", "mlx-agent")
	info, err = os.Lstat(binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 {
		return ""
	}
	return binary
}

func privateFile(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && info.Mode().Perm()&0077 == 0 && int(stat.Uid) == os.Getuid() && stat.Nlink == 1
}

func readMarker(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !privateFile(info) {
		return nil, errors.New("unsafe installation marker")
	}
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(data) > 4096 {
		return nil, errors.New("invalid installation marker")
	}
	return data, nil
}

func writeMarker(path, value string) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".runtime-marker-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.WriteString(value)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}

func findTool(name string) (string, error) {
	if path, err := exec.LookPath(name); err == nil {
		return path, nil
	}
	home, _ := os.UserHomeDir()
	for _, dir := range []string{filepath.Join(home, ".local", "bin"), "/opt/homebrew/bin", "/usr/local/bin"} {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			return path, nil
		}
	}
	return "", errors.New("required tool is not installed")
}

func Install(ctx context.Context, output io.Writer) (string, error) {
	if len(Revision) != 40 {
		return "", errors.New("model runtime source pin is unavailable")
	}
	return install(ctx, Root(), "git+https://github.com/cavi-ai/mlx-agent.git@"+Revision, output)
}

func install(ctx context.Context, root, source string, output io.Writer) (string, error) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		return "", errors.New("managed MLX installation requires Apple Silicon macOS")
	}
	uv, err := findTool("uv")
	if err != nil {
		return "", errors.New("uv is required; install uv and rerun secure-agent model-runtime install")
	}
	if !filepath.IsAbs(root) {
		return "", errors.New("managed runtime directory must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(root), 0700); err != nil {
		return "", errors.New("managed runtime parent unavailable")
	}
	if !privateDir(filepath.Dir(root)) {
		return "", errors.New("managed runtime parent must be private and owned")
	}
	lock, err := os.OpenFile(filepath.Join(filepath.Dir(root), ".install.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return "", errors.New("managed runtime lock unavailable")
	}
	defer lock.Close()
	if info, err := lock.Stat(); err != nil || !privateFile(info) {
		return "", errors.New("unsafe installation lock")
	}
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return "", errors.New("another managed runtime installation is running")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	created := false
	if err := os.Mkdir(root, 0700); err == nil {
		created = true
	} else if !os.IsExist(err) {
		return "", errors.New("managed runtime directory unavailable")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return "", errors.New("managed runtime directory must be private and not a symlink")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return "", errors.New("managed runtime owner mismatch")
	}
	if !created {
		marker, err := readMarker(filepath.Join(root, ".source"))
		if err != nil || string(marker) != source {
			return "", errors.New("managed runtime directory belongs to another installation")
		}
	} else if err := writeMarker(filepath.Join(root, ".source"), source); err != nil {
		return "", err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", errors.New("managed runtime path unavailable")
	}
	if binary := ownedAt(root); binary != "" {
		return binary, Check(ctx, binary)
	}
	run := func(args ...string) error {
		cmd := exec.CommandContext(ctx, uv, args...)
		cmd.WaitDelay = time.Second
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GCM_INTERACTIVE=never")
		cmd.Stdout, cmd.Stderr = output, output
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Cancel = func() error {
			if cmd.Process != nil {
				return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
			}
			return nil
		}
		return cmd.Run()
	}
	python := filepath.Join(root, "bin", "python")
	if _, err := os.Stat(python); err != nil {
		if err := run("venv", "--allow-existing", "--python", "3.12", root); err != nil {
			return "", errors.New("managed Python environment creation failed; rerun installation to resume")
		}
	}
	if err := run("pip", "install", "--python", python, source, "mlx-lm==0.29.1", "mlx==0.31.1", "transformers==4.57.6", "tokenizers==0.22.2"); err != nil {
		return "", errors.New("managed runtime installation failed; rerun to resume the same source")
	}
	binary := filepath.Join(root, "bin", "mlx-agent")
	if err := Check(ctx, binary); err != nil {
		return "", err
	}
	if err := writeMarker(filepath.Join(root, ".ready"), Revision); err != nil {
		return "", err
	}
	return binary, nil
}

func Check(ctx context.Context, binary string) error {
	for _, cap := range []struct{ command, protocol string }{{"private-worker", "inherited-unix-v1"}, {"protected-service", "protected-service-v1"}} {
		checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		cmd := exec.CommandContext(checkCtx, binary, "serve", cap.command, "--describe")
		cmd.WaitDelay = 100 * time.Millisecond
		output := &capOutput{}
		cmd.Stdout = output
		err := cmd.Run()
		cancel()
		raw := output.Bytes()
		var value struct {
			Protocol string `json:"protocol"`
		}
		if err != nil || len(raw) > 4096 || json.Unmarshal(raw, &value) != nil || strings.TrimSpace(value.Protocol) != cap.protocol {
			return errors.New("installed model runtime does not satisfy the required private-serving capabilities")
		}
	}
	return nil
}

type capOutput struct{ bytes.Buffer }

func (b *capOutput) Write(data []byte) (int, error) {
	if b.Len()+len(data) > 4096 {
		return 0, errors.New("capability output limit")
	}
	return b.Buffer.Write(data)
}
