package modelservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const maxDefinition = 64 * 1024

var labelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var errJobAbsent = errors.New("launchd job is not loaded")

type jobState struct {
	PID     int
	Path    string
	Born    string
	Program string
	ArgsSHA string
}

type limitedOutput struct{ bytes.Buffer }

func (b *limitedOutput) Write(data []byte) (int, error) {
	if b.Len()+len(data) > 1024*1024 {
		return 0, errors.New("native output limit")
	}
	return b.Buffer.Write(data)
}

func native(parent context.Context, input []byte, executable string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.WaitDelay = 100 * time.Millisecond
	cmd.Stdin = bytes.NewReader(input)
	output := &limitedOutput{}
	cmd.Stdout, cmd.Stderr = output, io.Discard
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("native service operation failed: %w", err)
	}
	return output.Bytes(), nil
}

func inspectJob(ctx context.Context, label string) (jobState, error) {
	state := jobState{}
	if !labelPattern.MatchString(label) {
		return state, errors.New("invalid launchd label")
	}
	raw, err := native(ctx, nil, "/bin/launchctl", "print", "gui/"+strconv.Itoa(os.Getuid())+"/"+label)
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 113 {
			return state, errJobAbsent
		}
		return state, errors.New("select a loaded launchd job in the current user's GUI domain")
	}
	arguments := []string{}
	inArguments := false
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if inArguments {
			if trimmed == "}" {
				inArguments = false
			} else if trimmed != "" {
				arguments = append(arguments, trimmed)
			}
			continue
		}
		if !strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "\t\t") {
			continue
		}
		if trimmed == "arguments = {" {
			inArguments = true
			continue
		}
		key, value, ok := strings.Cut(strings.TrimSpace(line), " = ")
		if !ok {
			continue
		}
		switch key {
		case "pid":
			state.PID, _ = strconv.Atoi(value)
		case "path":
			state.Path = value
		case "program":
			state.Program = value
		}
	}
	encoded, _ := json.Marshal(arguments)
	state.ArgsSHA = digest(encoded)
	if !filepath.IsAbs(state.Path) {
		return state, errors.New("service must be running with an identified definition path")
	}
	if state.PID == 0 {
		return state, nil
	}
	born, err := native(ctx, nil, "/bin/ps", "-p", strconv.Itoa(state.PID), "-o", "lstart=")
	if err != nil || len(bytes.TrimSpace(born)) == 0 {
		return state, errors.New("service process identity unavailable")
	}
	state.Born = strings.TrimSpace(string(born))
	return state, nil
}

func stopJob(ctx context.Context, label string) error {
	state, inspectErr := inspectJob(ctx, label)
	if errors.Is(inspectErr, errJobAbsent) {
		return nil
	}
	if inspectErr != nil {
		return inspectErr
	}
	_, err := native(ctx, nil, "/bin/launchctl", "bootout", "gui/"+strconv.Itoa(os.Getuid())+"/"+label)
	if err != nil {
		return err
	}
	wait, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for {
		_, inspectErr := inspectJob(wait, label)
		alive := false
		if state.PID > 0 {
			born, err := native(wait, nil, "/bin/ps", "-p", strconv.Itoa(state.PID), "-o", "lstart=")
			alive = err == nil && strings.TrimSpace(string(born)) == state.Born
		}
		if !alive && errors.Is(inspectErr, errJobAbsent) {
			return nil
		}
		select {
		case <-wait.Done():
			return errors.New("service did not finish stopping")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func stopSelectedJob(ctx context.Context, label, source string) error {
	state, err := inspectJob(ctx, label)
	if errors.Is(err, errJobAbsent) {
		return nil
	}
	if err != nil {
		return err
	}
	if state.Path != source {
		return errors.New("loaded service definition changed")
	}
	return stopJob(ctx, label)
}

func startJob(ctx context.Context, path string) error {
	_, err := native(ctx, nil, "/bin/launchctl", "bootstrap", "gui/"+strconv.Itoa(os.Getuid()), path)
	return err
}

func definition(data []byte) (map[string]any, error) {
	raw, err := native(context.Background(), data, "/usr/bin/plutil", "-convert", "json", "-o", "-", "-")
	var job map[string]any
	if err != nil || json.Unmarshal(raw, &job) != nil || job == nil {
		return nil, errors.New("unsupported launchd definition")
	}
	return job, nil
}

func encodeDefinition(job map[string]any) ([]byte, error) {
	data, err := json.Marshal(job)
	if err != nil {
		return nil, err
	}
	return native(context.Background(), data, "/usr/bin/plutil", "-convert", "xml1", "-o", "-", "-")
}

func ownedFile(path string, limit int, private bool) ([]byte, os.FileMode, error) {
	if !filepath.IsAbs(path) || len(path) > 4096 {
		return nil, 0, errors.New("an absolute owned file path is required")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, 0, errors.New("owned file unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || private && info.Mode().Perm()&0077 != 0 {
		return nil, 0, errors.New("file must be regular and protected from other writers")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() || stat.Nlink != 1 {
		return nil, 0, errors.New("file must be singly linked and owned by the current user")
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(limit+1)))
	if err != nil || len(data) > limit {
		return nil, 0, errors.New("owned file exceeds its read limit")
	}
	return data, info.Mode().Perm(), nil
}

func digest(data []byte) string {
	value := sha256.Sum256(data)
	return hex.EncodeToString(value[:])
}

func executableDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", errors.New("service executable unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 {
		return "", errors.New("service executable is not protected")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() && stat.Uid != 0 || info.Size() > 512*1024*1024 {
		return "", errors.New("service executable identity unavailable")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return "", errors.New("service executable identity unavailable")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func atomicFile(path string, data []byte, mode os.FileMode) error {
	parent := filepath.Dir(path)
	f, err := os.CreateTemp(parent, ".model-write-")
	if err != nil {
		return errors.New("service configuration write failed")
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errors.New("service configuration write failed")
	}
	if err := os.Rename(name, path); err != nil {
		return errors.New("service configuration replacement failed")
	}
	return nil
}
