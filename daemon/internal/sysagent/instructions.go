package sysagent

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/cavi-ai/secure-agent/daemon/internal/playbook"
	"github.com/cavi-ai/secure-agent/daemon/internal/store"
	"golang.org/x/sys/unix"
)

// InstructionPreview contains only a built-in instruction and its destination,
// never the existing file contents. Revision binds approval to the preview.
type InstructionPreview struct {
	Path        string `json:"path"`
	Instruction string `json:"instruction"`
	Revision    string `json:"revision"`
	Applied     bool   `json:"applied"`
	Ready       bool   `json:"ready"`
	Reason      string `json:"reason,omitempty"`
}

const maxInstructionFile = 256 << 10

func instructionTarget(workspace, agent, rule string) (name, instruction string, err error) {
	if !filepath.IsAbs(workspace) || filepath.Clean(workspace) != workspace || workspace == string(filepath.Separator) {
		return "", "", fmt.Errorf("%w: a recorded project folder is required", ErrInvalid)
	}
	switch agent {
	case "codex":
		name = "AGENTS.md"
	case "claude":
		name = "CLAUDE.md"
	default:
		return "", "", fmt.Errorf("%w: no instruction file is configured for this agent", ErrInvalid)
	}
	instruction = playbook.AgentInstruction(rule)
	if instruction == "" {
		return "", "", fmt.Errorf("%w: no built-in instruction applies to this finding", ErrInvalid)
	}
	return name, instruction, nil
}

type instructionFile struct {
	root *os.Root
	file *os.File
	info os.FileInfo
	data []byte
}

func (f *instructionFile) close() {
	if f.file != nil {
		_ = f.file.Close()
	}
	_ = f.root.Close()
}

// The root pins the project directory; O_NOFOLLOW rejects instruction symlinks,
// O_NONBLOCK avoids hanging on pipes, and hard links are rejected before writing.
func readInstructionFile(workspace, name string, writable bool) (*instructionFile, error) {
	root, err := os.OpenRoot(workspace)
	if err != nil {
		return nil, fmt.Errorf("%w: project folder unavailable", ErrUnavailable)
	}
	f := &instructionFile{root: root}
	ok := false
	defer func() {
		if !ok {
			f.close()
		}
	}()
	flags := os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	if writable {
		flags = os.O_RDWR | os.O_APPEND | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	}
	f.file, err = root.OpenFile(name, flags, 0)
	if os.IsNotExist(err) {
		ok = true
		return f, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: instruction file cannot be opened safely", ErrUnavailable)
	}
	if writable {
		if err := unix.Flock(int(f.file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
			return nil, fmt.Errorf("%w: instruction file is in use", ErrBusy)
		}
	}
	f.info, err = f.file.Stat()
	if err != nil || !f.info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: instruction file must be a regular file", ErrInvalid)
	}
	if stat, ok := f.info.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 {
		return nil, fmt.Errorf("%w: instruction file must not be hard linked", ErrInvalid)
	}
	f.data, err = io.ReadAll(io.LimitReader(f.file, maxInstructionFile+1))
	if err != nil || len(f.data) > maxInstructionFile || !utf8.Valid(f.data) || strings.ContainsRune(string(f.data), 0) {
		return nil, fmt.Errorf("%w: instruction file must be bounded UTF-8 text", ErrInvalid)
	}
	after, err := f.file.Stat()
	if err != nil || after.Size() != f.info.Size() || !after.ModTime().Equal(f.info.ModTime()) {
		return nil, fmt.Errorf("%w: instruction file changed while reading; refresh", ErrBusy)
	}
	ok = true
	return f, nil
}

func (f *instructionFile) preview(workspace, name, instruction string) (InstructionPreview, error) {
	dir, err := f.root.Stat(".")
	if err != nil {
		return InstructionPreview{}, fmt.Errorf("%w: project folder unavailable", ErrUnavailable)
	}
	h := sha256.New()
	stat := dir.Sys().(*syscall.Stat_t)
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%d:%d\x00", workspace, name, instruction, stat.Dev, stat.Ino)
	if f.info != nil {
		stat := f.info.Sys().(*syscall.Stat_t)
		fmt.Fprintf(h, "%d:%d:%d:%d\x00", stat.Dev, stat.Ino, f.info.Mode(), f.info.ModTime().UnixNano())
		_, _ = h.Write(f.data)
	} else {
		_, _ = h.Write([]byte("missing"))
	}
	applied := false
	for _, line := range strings.Split(string(f.data), "\n") {
		if strings.TrimSpace(line) == instruction {
			applied = true
			break
		}
	}
	return InstructionPreview{Path: filepath.Join(workspace, name), Instruction: instruction,
		Revision: fmt.Sprintf("%x", h.Sum(nil)), Applied: applied, Ready: true}, nil
}

func (a *Agent) PreviewInstruction(workspace, agent, rule string) (InstructionPreview, error) {
	if !a.config().Enabled {
		return InstructionPreview{}, ErrDisabled
	}
	name, instruction, err := instructionTarget(workspace, agent, rule)
	if err != nil {
		return InstructionPreview{}, err
	}
	f, err := readInstructionFile(workspace, name, false)
	if err != nil {
		return InstructionPreview{}, err
	}
	defer f.close()
	return f.preview(workspace, name, instruction)
}

// ApplyInstruction appends a fixed safety rule after explicit approval of its
// preview. No model text, browser-provided path or shell command is executed.
func (a *Agent) ApplyInstruction(workspace, agent, rule, revision string) (InstructionPreview, error) {
	if !a.config().Enabled {
		return InstructionPreview{}, ErrDisabled
	}
	name, instruction, err := instructionTarget(workspace, agent, rule)
	if err != nil {
		return InstructionPreview{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.running != 0 {
		return InstructionPreview{}, fmt.Errorf("%w: a local run is in progress", ErrBusy)
	}
	f, err := readInstructionFile(workspace, name, true)
	if err != nil {
		return InstructionPreview{}, err
	}
	defer f.close()
	p, err := f.preview(workspace, name, instruction)
	if err != nil {
		return InstructionPreview{}, err
	}
	if p.Applied {
		return p, nil
	}
	if revision == "" || p.Revision != revision {
		return InstructionPreview{}, fmt.Errorf("%w: instruction file changed; refresh before applying", ErrBusy)
	}
	text := instruction + "\n"
	if len(f.data) > 0 && f.data[len(f.data)-1] != '\n' {
		text = "\n" + text
	}
	if len(f.data)+len(text) > maxInstructionFile {
		return InstructionPreview{}, fmt.Errorf("%w: instruction file has no space within the text limit", ErrInvalid)
	}
	if f.file == nil {
		f.file, err = f.root.OpenFile(name, os.O_WRONLY|os.O_APPEND|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
		if err != nil {
			return InstructionPreview{}, fmt.Errorf("%w: instruction file could not be created; refresh", ErrUnavailable)
		}
	} else {
		current, err := f.root.Lstat(name)
		if err != nil || !os.SameFile(f.info, current) || !current.Mode().IsRegular() || current.Mode().Perm()&0222 == 0 {
			return InstructionPreview{}, fmt.Errorf("%w: instruction file changed or is read-only; refresh", ErrBusy)
		}
	}
	// Append instead of replacing the file so unrelated concurrent writes are
	// preserved. One write keeps this fixed, short rule together.
	n, err := f.file.WriteString(text)
	if err != nil || n != len(text) {
		return InstructionPreview{}, fmt.Errorf("%w: instruction write failed; inspect the file before retrying", ErrUnavailable)
	}
	if err := f.file.Sync(); err != nil {
		return InstructionPreview{}, fmt.Errorf("%w: instruction durability could not be confirmed; inspect the file", ErrUnavailable)
	}
	current, err := f.root.Lstat(name)
	written, statErr := f.file.Stat()
	dir, dirErr := f.root.Stat(".")
	visibleDir, visibleErr := os.Stat(workspace)
	if err != nil || statErr != nil || dirErr != nil || visibleErr != nil || !os.SameFile(written, current) || !os.SameFile(dir, visibleDir) {
		return InstructionPreview{}, fmt.Errorf("%w: destination changed during the update; inspect the instruction file", ErrUnavailable)
	}
	if f.info == nil {
		directory, err := f.root.Open(".")
		if err != nil {
			return InstructionPreview{}, fmt.Errorf("%w: project folder unavailable after creation", ErrUnavailable)
		}
		err = directory.Sync()
		_ = directory.Close()
		if err != nil {
			return InstructionPreview{}, fmt.Errorf("%w: new instruction file durability could not be confirmed", ErrUnavailable)
		}
	}
	p.Applied = true
	a.st.PutAudit(store.AuditEntry{Action: "sysagent-instruction", Rule: rule,
		Detail: fmt.Sprintf("agent=%s file=%s", agent, p.Path)})
	return p, nil
}
