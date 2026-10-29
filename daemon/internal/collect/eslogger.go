package collect

import (
	"bytes"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
)

// eslogger's JSON reaches the daemon only through the privileged collector's
// spool (secure-agentd -es-collector, SpoolTailer); ParseESLine decodes it.

// unmarshalES is a test seam: production always calls json.Unmarshal; tests
// swap it to count calls and prove the fast-reject path in ParseESLine never
// reaches it for fragments.
var unmarshalES = json.Unmarshal

type esProcess struct {
	AuditToken struct {
		PID int32 `json:"pid"`
	} `json:"audit_token"`
	PID        int32 `json:"pid"`
	PPID       int32 `json:"ppid"`
	Executable struct {
		Path string `json:"path"`
	} `json:"executable"`
}

func (p esProcess) pid() int32 {
	if p.AuditToken.PID != 0 {
		return p.AuditToken.PID
	}
	return p.PID
}

// esInstigated is the instigating-process part of the BTM and profile
// events: the process itself, or only its audit token on message version 8+
// when the process was not captured.
type esInstigated struct {
	Instigator      *esProcess `json:"instigator"`
	InstigatorToken *struct {
		PID int32 `json:"pid"`
	} `json:"instigator_token"`
}

type esBTMItem struct {
	ItemURL string `json:"item_url"`
	AppURL  string `json:"app_url"`
}

type esEnvelope struct {
	EventType int       `json:"event_type"`
	Process   esProcess `json:"process"`
	Event     struct {
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
		BTMAdd *struct {
			esInstigated
			Item           esBTMItem `json:"item"`
			ExecutablePath string    `json:"executable_path"`
		} `json:"btm_launch_item_add"`
		BTMRemove *struct {
			esInstigated
			Item esBTMItem `json:"item"`
		} `json:"btm_launch_item_remove"`
		XPMalware *struct {
			MalwareIdentifier  string `json:"malware_identifier"`
			DetectedPath       string `json:"detected_path"`
			DetectedExecutable string `json:"detected_executable"`
		} `json:"xp_malware_detected"`
		ProfileAdd *struct {
			esInstigated
			Profile struct {
				Identifier  string `json:"identifier"`
				DisplayName string `json:"display_name"`
			} `json:"profile"`
		} `json:"profile_add"`
		GatekeeperOverride *struct {
			File json.RawMessage `json:"file"`
		} `json:"gatekeeper_user_override"`
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

	pid := env.Process.pid()
	// The daemon's own reads (transcript tailing) are not agent activity.
	if pid == int32(os.Getpid()) {
		return event.Event{}, esOwn
	}
	ppid, exe := env.Process.PPID, env.Process.Executable.Path

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
	} else if a := env.Event.BTMAdd; a != nil {
		kind = event.KindLaunchItemAdd
		filePath, detail = fileURLPath(a.Item.ItemURL), a.ExecutablePath
		if detail == "" {
			detail = fileURLPath(a.Item.AppURL)
		}
		pid, ppid, exe = a.instigatedBy(pid, ppid, exe)
	} else if r := env.Event.BTMRemove; r != nil {
		kind = event.KindLaunchItemRemove
		filePath = fileURLPath(r.Item.ItemURL)
		pid, ppid, exe = r.instigatedBy(pid, ppid, exe)
	} else if m := env.Event.XPMalware; m != nil {
		kind = event.KindMalwareDetected
		filePath, detail = m.DetectedPath, m.MalwareIdentifier
		if filePath == "" {
			filePath = m.DetectedExecutable
		}
	} else if p := env.Event.ProfileAdd; p != nil {
		kind = event.KindProfileAdd
		detail = p.Profile.Identifier
		if detail == "" {
			detail = p.Profile.DisplayName
		}
		pid, ppid, exe = p.instigatedBy(pid, ppid, exe)
	} else if g := env.Event.GatekeeperOverride; g != nil {
		kind = event.KindGatekeeperOverride
		filePath = gatekeeperFilePath(g.File)
	} else {
		return event.Event{}, esGarbage
	}

	open.Kind, open.TS, open.PID, open.PPID = kind, ts, pid, ppid
	open.ExePath, open.Path, open.Detail = exe, filePath, detail
	return open, esEvent
}

// instigatedBy attributes a BTM or profile event to the process that asked
// for it; the message's own process (backgroundtaskmanagementd, mdmclient)
// stands in only when ES captured no instigator.
func (i esInstigated) instigatedBy(pid, ppid int32, exe string) (int32, int32, string) {
	if p := i.Instigator; p != nil && p.pid() != 0 {
		return p.pid(), p.PPID, p.Executable.Path
	}
	if t := i.InstigatorToken; t != nil && t.PID != 0 {
		return t.PID, 0, ""
	}
	return pid, ppid, exe
}

// fileURLPath turns a BTM item or app URL into a path; a URL of another
// scheme is kept as it is.
func fileURLPath(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "file" {
		return s
	}
	return strings.TrimSuffix(u.Path, "/")
}

// gatekeeperFilePath reads the overridden file from the Gatekeeper event's
// file union: a path string, or a file object carrying its path.
func gatekeeperFilePath(raw json.RawMessage) string {
	var path string
	if json.Unmarshal(raw, &path) == nil {
		return path
	}
	var f struct {
		Path     string `json:"path"`
		FilePath string `json:"file_path"`
		File     *struct {
			Path string `json:"path"`
		} `json:"file"`
	}
	if json.Unmarshal(raw, &f) != nil {
		return ""
	}
	switch {
	case f.Path != "":
		return f.Path
	case f.FilePath != "":
		return f.FilePath
	case f.File != nil:
		return f.File.Path
	}
	return ""
}
