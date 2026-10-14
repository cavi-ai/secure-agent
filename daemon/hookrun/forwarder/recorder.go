package forwarder

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"path/filepath"
)

// Recorder delivers one metadata record through the installed recorder. Each
// invocation closes stdin and waits for exit, rather than mistaking a pipe write
// for acceptance. Success confirms append, not fsync or daemon persistence.
// Output is optional; empty uses the recorder's standard activity log.
type Recorder struct{ Executable, Output string }

func (r Recorder) Send(ctx context.Context, metadata []byte) error {
	if !filepath.IsAbs(r.Executable) {
		return errors.New("hook recorder requires an absolute executable path")
	}
	args := []string{"hooks", "record", "--format", "record"}
	if r.Output != "" {
		args = append(args, "--output", r.Output)
	}
	cmd := exec.CommandContext(ctx, r.Executable, args...)
	cmd.Stdin = bytes.NewReader(append(bytes.Clone(metadata), '\n'))
	// Child output is discarded: paths and OS error text must not reach reports.
	if err := cmd.Run(); err != nil {
		return errors.New("hook recorder did not confirm append")
	}
	return nil
}
