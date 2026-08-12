package collect

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/bus"
	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

type ESLogger struct {
	bus *bus.Bus
}

func NewESLogger(b *bus.Bus) *ESLogger {
	return &ESLogger{bus: b}
}

type esEnvelope struct {
	EventType int `json:"event_type"`
	Process   struct {
		AuditToken struct {
			PID int32 `json:"pid"`
		} `json:"audit_token"`
		PID        int32 `json:"pid"`
		Executable struct {
			Path string `json:"path"`
		} `json:"executable"`
	} `json:"process"`
	Event struct {
		Open *struct {
			File struct {
				Path string `json:"path"`
			} `json:"file"`
		} `json:"open"`
		Exec *struct {
			Target struct {
				Executable struct {
					Path string `json:"path"`
				} `json:"executable"`
			} `json:"target"`
		} `json:"exec"`
		Unlink *struct {
			Target struct {
				Path string `json:"path"`
			} `json:"target"`
		} `json:"unlink"`
		Rename *struct {
			Destination struct {
				ExistingFile *struct {
					Path string `json:"path"`
				} `json:"existing_file"`
				NewPath *struct {
					DirPath  string `json:"dir_path"`
					Filename string `json:"filename"`
				} `json:"new_path"`
			} `json:"destination"`
		} `json:"rename"`
		TCCModify *struct {
			Service string `json:"service"`
		} `json:"tcc_modify"`
	} `json:"event"`
	Time      string `json:"time"`
	Timestamp string `json:"timestamp"`
}

func ParseESLine(line []byte) (event.Event, bool) {
	if len(line) == 0 {
		return event.Event{}, false
	}
	var env esEnvelope
	if err := json.Unmarshal(line, &env); err != nil {
		return event.Event{}, false
	}

	pid := env.Process.AuditToken.PID
	if pid == 0 {
		pid = env.Process.PID
	}
	exe := env.Process.Executable.Path

	ts := time.Now()
	tsStr := env.Time
	if tsStr == "" {
		tsStr = env.Timestamp
	}
	if tsStr != "" {
		if t, err := time.Parse(time.RFC3339Nano, tsStr); err == nil {
			ts = t
		} else if t, err := time.Parse(time.RFC3339, tsStr); err == nil {
			ts = t
		}
	}

	var kind event.Kind
	var filePath string
	var detail string

	if env.Event.Open != nil {
		kind = event.KindFileOpen
		filePath = env.Event.Open.File.Path
	} else if env.Event.Exec != nil {
		kind = event.KindExec
		filePath = env.Event.Exec.Target.Executable.Path
	} else if env.Event.Unlink != nil {
		kind = event.KindFileDelete
		filePath = env.Event.Unlink.Target.Path
	} else if env.Event.Rename != nil {
		kind = event.KindFileWrite
		if env.Event.Rename.Destination.ExistingFile != nil {
			filePath = env.Event.Rename.Destination.ExistingFile.Path
		} else if env.Event.Rename.Destination.NewPath != nil {
			filePath = env.Event.Rename.Destination.NewPath.DirPath + "/" + env.Event.Rename.Destination.NewPath.Filename
		}
	} else if env.Event.TCCModify != nil {
		kind = event.KindTCCModify
		detail = env.Event.TCCModify.Service
	} else {
		return event.Event{}, false
	}

	return event.Event{
		Kind:    kind,
		TS:      ts,
		PID:     pid,
		ExePath: exe,
		Path:    filePath,
		Detail:  detail,
	}, true
}

func (es *ESLogger) Run(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "eslogger", "open", "exec", "unlink", "rename", "tcc_modify", "--format", "json")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("eslogger stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start eslogger: %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024) // up to 1MB per line

	for scanner.Scan() {
		line := scanner.Bytes()
		if e, ok := ParseESLine(line); ok {
			es.bus.Publish(e)
		}
	}

	if err := scanner.Err(); err != nil {
		_ = cmd.Process.Kill()
		return fmt.Errorf("eslogger scanner error: %w", err)
	}

	return cmd.Wait()
}
