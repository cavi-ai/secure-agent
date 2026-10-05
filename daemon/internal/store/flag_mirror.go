package store

import (
	"encoding/json"
	"os"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// SQLite is the source of truth; the forensic mirror retains the active file
// and one previous file, rotating before an append when the cap is reached.
const defaultFlagMirrorRotateBytes int64 = 8 << 20

// flagMirror owns the JSONL file lifecycle. Store serializes all access with
// its existing mutex and reports failures through its write-health tracker.
type flagMirror struct {
	path        string
	file        *os.File
	rotateBytes int64
}

// Return the mirror even if opening fails, so the next flag can retry once.
func openFlagMirror(path string) (*flagMirror, error) {
	m := &flagMirror{path: path, rotateBytes: defaultFlagMirrorRotateBytes}
	err := m.open()
	return m, err
}

func (m *flagMirror) open() error {
	f, err := os.OpenFile(m.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	m.file = f
	return nil
}

func (m *flagMirror) append(fl model.Flag) error {
	if m.file == nil {
		if err := m.open(); err != nil {
			return err
		}
	}
	if err := m.rotate(); err != nil {
		m.close()
		return err
	}
	data, err := json.Marshal(fl)
	if err != nil {
		return err
	}
	_, err = m.file.Write(append(data, '\n'))
	if err != nil {
		m.close() // retry opening on the next flag, never in a loop
	}
	return err
}

func (m *flagMirror) rotate() error {
	if m.file == nil || m.rotateBytes <= 0 {
		return nil
	}
	st, err := m.file.Stat()
	if err != nil {
		return err
	}
	if st.Size() < m.rotateBytes {
		return nil
	}
	m.close()
	rotated := m.path + ".1"
	_ = os.Remove(rotated)
	if err := os.Rename(m.path, rotated); err != nil {
		return err
	}
	return m.open()
}

func (m *flagMirror) close() {
	if m.file != nil {
		_ = m.file.Close()
		m.file = nil
	}
}
