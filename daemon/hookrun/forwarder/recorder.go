package forwarder

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
)

// Recorder delivers one metadata record through the installed recorder. Each
// invocation closes stdin and waits for exit, rather than mistaking a pipe write
// for acceptance. Success confirms append, not fsync or daemon persistence.
// Output is optional; empty uses the recorder's standard activity log.
type Recorder struct{ Executable, Output string }

func (r Recorder) Send(ctx context.Context, metadata []byte) error {
	return r.send(ctx, metadata, false)
}

// SendDurable requires a recorder supporting --durable. Successful exit follows
// file and directory synchronization. Older recorders fail without fallback.
func (r Recorder) SendDurable(ctx context.Context, metadata []byte) error {
	return r.send(ctx, metadata, true)
}

func (r Recorder) send(ctx context.Context, metadata []byte, durable bool) error {
	if !filepath.IsAbs(r.Executable) {
		return hookrun.ErrRecorderUnavailable
	}
	args := []string{"hooks", "record", "--format", "record"}
	if durable {
		args = append(args, "--durable")
	}
	if r.Output != "" {
		args = append(args, "--output", r.Output)
	}
	cmd := exec.CommandContext(ctx, r.Executable, args...)
	cmd.Stdin = bytes.NewReader(append(bytes.Clone(metadata), '\n'))
	// Child output is discarded: paths and OS error text must not reach reports.
	if err := cmd.Run(); err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) || errors.Is(err, exec.ErrNotFound) {
			return hookrun.ErrRecorderUnavailable
		}
		return hookrun.ErrRecorderFailed
	}
	return nil
}
