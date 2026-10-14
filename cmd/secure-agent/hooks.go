package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
	"github.com/cavi-ai/secure-agent/daemon/hookrun/codex"
	"github.com/cavi-ai/secure-agent/daemon/hookrun/hermes"
	"github.com/cavi-ai/secure-agent/daemon/hookrun/openclaw"
	"github.com/cavi-ai/secure-agent/daemon/hookrun/opencode"
)

func handleHooks() {
	if err := runHooks(os.Stdin, os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// runHooks records forwarded host notifications, never launching or taking
// ownership of a harness. The daemon already tails this shared activity log.
func runHooks(in io.Reader, args []string) (err error) {
	if len(args) == 0 || args[0] != "record" {
		return errors.New("usage: secure-agent hooks record --format codex|openclaw|hermes|opencode|record [--output path]")
	}
	flags := flag.NewFlagSet("hooks record", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	format := flags.String("format", "codex", "input format")
	output := flags.String("output", "", "activity log path")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return errors.New("invalid hooks record arguments")
	}
	var decoder hookrun.Decoder
	switch *format {
	case "codex":
		decoder = codex.Decoder{}
	case "openclaw":
		decoder = openclaw.Decoder{}
	case "hermes":
		decoder = hermes.Decoder{}
	case "opencode":
		decoder = opencode.Decoder{}
	case "record":
		decoder = hookrun.RecordDecoder{}
	default:
		return errors.New("unsupported hook input format")
	}
	if *output == "" {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return errors.New("cannot locate hook activity log")
		}
		*output = filepath.Join(home, ".local", "state", "secure-agent", "activity.jsonl")
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0700); err != nil {
		return fmt.Errorf("create hook log directory: %w", err)
	}
	f, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("open hook log: %w", err)
	}
	defer func() {
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
	}()
	lines := bufio.NewScanner(in)
	lines.Buffer(make([]byte, 4096), 1024*1024)
	for n := 1; lines.Scan(); n++ {
		var record any
		report, reportOK, err := hookrun.DecodeForwarderReport(lines.Bytes())
		if reportOK && err == nil && *format != "record" && report.Harness != *format {
			err = errors.New("hook forwarder harness does not match input format")
		}
		if err != nil {
			return fmt.Errorf("hook input line %d: %w", n, err)
		}
		if reportOK {
			record = report
		} else {
			r, ok, err := decoder.Decode(lines.Bytes())
			if err != nil {
				return fmt.Errorf("hook input line %d: %w", n, err)
			}
			if !ok {
				continue
			}
			record = r
		}
		data, err := json.Marshal(record)
		if err != nil {
			return errors.New("cannot encode hook metadata")
		}
		// A single append keeps concurrent recorder writes from interleaving.
		if _, err := f.Write(append(data, '\n')); err != nil {
			return fmt.Errorf("append hook metadata: %w", err)
		}
	}
	if lines.Err() != nil {
		return errors.New("cannot read hook input (maximum line size: 1 MiB)")
	}
	return nil
}
