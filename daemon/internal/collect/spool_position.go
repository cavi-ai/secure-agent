package collect

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"os"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/safefile"
)

// spoolPositionSaveEvery spaces the read-position saves.
const spoolPositionSaveEvery = 2 * time.Second

// spoolHeadBytes is how much of a spool file's start names it: a rotated
// file's inode number can be reused by its successor, its first bytes not.
const spoolHeadBytes = 4096

// spoolPosition is a saved read position: the offset read up to, in the file
// whose first HeadLen bytes digest to Head. The spool only grows, so those
// bytes never change.
type spoolPosition struct {
	Head    string `json:"head"`
	HeadLen int64  `json:"head_len"`
	Offset  int64  `json:"offset"`
}

// fileHead digests the first n bytes of path; "" when it holds fewer.
func fileHead(path string, n int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if copied, err := io.CopyN(h, f, n); err != nil || copied != n {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// lineEnd returns the offset just past the last complete line of path's
// first size bytes, looking back at most 1 MiB, the longest line the tailer
// reads; size when no newline is found there.
func lineEnd(path string, size int64) int64 {
	f, err := os.Open(path)
	if err != nil {
		return size
	}
	defer func() { _ = f.Close() }()
	from := max(0, size-(1<<20))
	buf := make([]byte, size-from)
	if _, err := f.ReadAt(buf, from); err != nil && err != io.EOF {
		return size
	}
	if i := bytes.LastIndexByte(buf, '\n'); i >= 0 {
		return from + int64(i) + 1
	}
	return size
}

// startCursor resumes the saved read position in the spool or its rotated
// predecessor. Without one that matches, the run starts at the spool's last
// complete line: it reads what is written from its start on, instead of a
// backlog it cannot catch up on before rotation overwrites it.
func (t *SpoolTailer) startCursor() spoolCursor {
	if t.StatePath == "" {
		return spoolCursor{}
	}
	var pos spoolPosition
	if data, err := os.ReadFile(t.StatePath); err == nil && json.Unmarshal(data, &pos) == nil && pos.HeadLen > 0 {
		for _, p := range []string{t.path, t.path + ".1"} {
			if fi, err := os.Stat(p); err == nil && pos.Offset <= fi.Size() && fileHead(p, pos.HeadLen) == pos.Head {
				return spoolCursor{offset: pos.Offset, file: fi}
			}
		}
	}
	fi, err := os.Stat(t.path)
	if err != nil {
		return spoolCursor{}
	}
	end := lineEnd(t.path, fi.Size())
	if end > 0 {
		log.Printf("collect: no saved position in the spool; reading from its end, %d earlier bytes not read", end)
	}
	return spoolCursor{offset: end, size: fi.Size(), mod: fi.ModTime(), file: fi}
}

// savePosition saves c's read position when it moved, at most every
// spoolPositionSaveEvery unless final.
func (t *SpoolTailer) savePosition(c spoolCursor, final bool) {
	if t.StatePath == "" || c.file == nil || c.offset <= 0 {
		return
	}
	if c.offset == t.savedOffset && os.SameFile(c.file, t.savedFile) {
		return
	}
	if !final && t.clock().Sub(t.savedAt) < spoolPositionSaveEvery {
		return
	}
	path := t.path
	if cur, err := os.Stat(t.path); err != nil || !os.SameFile(cur, c.file) {
		path = t.path + ".1"
	}
	fi, err := os.Stat(path)
	if err != nil || !os.SameFile(fi, c.file) {
		return
	}
	headLen := min(fi.Size(), spoolHeadBytes)
	head := fileHead(path, headLen)
	if head == "" {
		return
	}
	data, err := json.Marshal(spoolPosition{Head: head, HeadLen: headLen, Offset: c.offset})
	if err == nil {
		err = safefile.ReplaceFile(t.StatePath, data, 0o600)
	}
	if err != nil {
		log.Printf("collect: save spool position: %v", err)
		return
	}
	t.savedAt, t.savedOffset, t.savedFile = t.clock(), c.offset, c.file
}
