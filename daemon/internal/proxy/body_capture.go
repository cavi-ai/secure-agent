package proxy

import (
	"bytes"
	"errors"
	"io"
	"net/http"
)

func (ps *ProxyServer) captureRequestBody(original io.ReadCloser, host string) *inspectionBody {
	s := &bodySpool{}
	buf := make([]byte, 32<<10)
	var tail io.Reader = original
	complete := false
	var coverageErr error
	source := &captureSource{Reader: original}
	for s.size <= bodyInspectionCap {
		n, readErr := io.ReadFull(source, buf[:min(int64(len(buf)), bodyInspectionCap+1-s.size)])
		if readErr != nil || source.err != nil {
			readErr = source.err
		}
		written, writeErr := s.Write(buf[:n])
		if writeErr != nil {
			ps.publishHit(host, "proxy-inspection-incomplete:body-buffer")
			coverageErr = writeErr
			// Keep the unwritten bytes: failing replay storage must never turn
			// an otherwise valid upload into a truncated request.
			remaining := bytes.Clone(buf[written:n])
			if readErr == io.EOF {
				tail = http.NoBody
				complete = true
			} else if readErr != nil {
				ps.publishHit(host, "proxy-inspection-incomplete:body-read")
				tail = &readError{err: readErr}
				coverageErr = readErr
			}
			tail = io.MultiReader(bytes.NewReader(remaining), tail)
			break
		}
		if readErr != nil {
			if readErr == io.EOF {
				complete = true
				tail = http.NoBody
			} else {
				ps.publishHit(host, "proxy-inspection-incomplete:body-read")
				tail = &readError{err: readErr}
				coverageErr = readErr
			}
			break
		}
	}
	if s.size > bodyInspectionCap {
		complete = false
		coverageErr = errInspectionLimit
		ps.publishHit(host, "proxy-inspection-incomplete:body-limit")
	}
	return &inspectionBody{Reader: io.MultiReader(s.reader(), tail), original: original, spool: s, complete: complete, coverageErr: coverageErr}
}

// Preserve the source's actual error (io.ReadFull synthesizes ErrUnexpectedEOF
// for a normal final short chunk) and bound pathological zero-progress readers.
type captureSource struct {
	io.Reader
	err        error
	emptyReads int
}

func (s *captureSource) Read(p []byte) (int, error) {
	n, err := s.Reader.Read(p)
	if n == 0 && err == nil {
		s.emptyReads++
		if s.emptyReads == 100 {
			err = io.ErrNoProgress
		}
	} else {
		s.emptyReads = 0
	}
	s.err = err
	return n, err
}

var errInspectionLimit = errors.New("body inspection budget exhausted")

// Probe one byte past the budget to distinguish exact-size bodies from partial
// inspection, without presenting an artificial EOF as a real token boundary.
type budgetReader struct {
	io.Reader
	left int64
}

func (r *budgetReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.left == 0 {
		var probe [1]byte
		n, err := r.Reader.Read(probe[:])
		if n > 0 {
			return 0, errInspectionLimit
		}
		return 0, err
	}
	n, err := r.Reader.Read(p[:min(int64(len(p)), r.left)])
	r.left -= int64(n)
	return n, err
}
