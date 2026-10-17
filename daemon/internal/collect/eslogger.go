package collect

import (
	"bytes"
	"encoding/json"
	"os"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// eslogger's JSON reaches the daemon only through the privileged collector's
// spool (secure-agentd -es-collector, SpoolTailer); ParseESLine decodes it.

// unmarshalES is a test seam: production always calls json.Unmarshal; tests
// swap it to count calls and prove the fast-reject path in ParseESLine never
// reaches it for fragments.
var unmarshalES = json.Unmarshal

type esEnvelope struct {
	EventType int `json:"event_type"`
	Process   struct {
		AuditToken struct {
			PID int32 `json:"pid"`
		} `json:"audit_token"`
		PID        int32 `json:"pid"`
		PPID       int32 `json:"ppid"`
		Executable struct {
			Path string `json:"path"`
		} `json:"executable"`
	} `json:"process"`
	Event struct {
		Open *struct {
			FFlag int32 `json:"fflag"`
			File  struct {
				Path string `json:"path"`
				Stat struct {
					Mode      uint32 `json:"st_mode"`
					Ino       uint64 `json:"st_ino"`
					Birthtime string `json:"st_birthtimespec"`
				} `json:"stat"`
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

// minESLineLen is the shortest possible real ES envelope; anything shorter
// is a fragment (a defective writer's partial/garbage line) and is rejected
// without ever reaching json.Unmarshal.
const minESLineLen = 16

// esLineVerdict is what parseESLine made of one line: an event, a valid
// envelope that is deliberately not an event (the daemon's own file
// activity), or a line that is not an ES envelope it handles.
type esLineVerdict int

const (
	esEvent esLineVerdict = iota
	esOwn
	esGarbage
)

// ParseESLine decodes one eslogger line into an event; false for anything
// that is not an agent-relevant event.
func ParseESLine(line []byte) (event.Event, bool) {
	e, v := parseESLine(line)
	return e, v == esEvent
}

func parseESLine(line []byte) (event.Event, esLineVerdict) {
	if len(line) < minESLineLen {
		return event.Event{}, esGarbage
	}
	if b := bytes.TrimLeft(line, " \t"); len(b) == 0 || b[0] != '{' {
		return event.Event{}, esGarbage
	}
	var env esEnvelope
	if err := unmarshalES(line, &env); err != nil {
		return event.Event{}, esGarbage
	}

	pid := env.Process.AuditToken.PID
	if pid == 0 {
		pid = env.Process.PID
	}
	// The daemon's own reads (transcript tailing) are not agent activity.
	if pid == int32(os.Getpid()) {
		return event.Event{}, esOwn
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
	var open event.Event

	if env.Event.Open != nil {
		kind = event.KindFileOpen
		filePath = env.Event.Open.File.Path
		st := env.Event.Open.File.Stat
		open.OpenFlags, open.FileMode, open.FileIno = env.Event.Open.FFlag, st.Mode, st.Ino
		if t, err := time.Parse(time.RFC3339Nano, st.Birthtime); err == nil {
			open.FileBirth = t.UnixNano()
		}
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
		return event.Event{}, esGarbage
	}

	open.Kind, open.TS, open.PID, open.PPID = kind, ts, pid, env.Process.PPID
	open.ExePath, open.Path, open.Detail = exe, filePath, detail
	return open, esEvent
}
