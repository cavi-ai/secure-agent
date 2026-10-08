package proxy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"sync"
)

// bodySpool keeps small requests in memory and encrypts larger requests in a
// private temporary file. The key exists only in this request's memory. The
// file is unlinked immediately; Close releases its descriptor even on blocks.
const spoolChunk = 32 << 10

type bodySpool struct {
	buf       bytes.Buffer
	file      *os.File
	aead      cipher.AEAD
	nonce     [12]byte
	records   uint64
	size      int64
	stored    int64
	closeOnce sync.Once
	closeErr  error
}

func (s *bodySpool) spill() error {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return err
	}
	block, err := aes.NewCipher(key[:])
	clear(key[:])
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:4]); err != nil {
		return err
	}
	f, err := os.CreateTemp("", "secure-agent-body-*")
	if err != nil {
		return err
	}
	if err := os.Remove(f.Name()); err != nil {
		f.Close()
		_ = os.Remove(f.Name())
		return err
	}
	// Do not discard the memory prefix until every encrypted record is stored.
	// A failed spill can still replay the original request in full.
	disk := &bodySpool{file: f, aead: aead, nonce: nonce}
	if _, err := disk.Write(s.buf.Bytes()); err != nil {
		f.Close()
		return err
	}
	s.file, s.aead, s.nonce = f, aead, nonce
	s.records, s.stored = disk.records, disk.stored
	clear(s.buf.Bytes())
	s.buf.Reset()
	return nil
}

func (s *bodySpool) Write(p []byte) (int, error) {
	if s.file == nil && s.buf.Len()+len(p) > scanCap {
		if err := s.spill(); err != nil {
			return 0, err
		}
	}
	if s.file == nil {
		n, err := s.buf.Write(p)
		s.size += int64(n)
		return n, err
	}
	total := 0
	for len(p) > 0 {
		chunk := p[:min(len(p), spoolChunk)]
		binary.BigEndian.PutUint64(s.nonce[4:], s.records)
		sealed := s.aead.Seal(nil, s.nonce[:], chunk, nil)
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], uint32(len(sealed)))
		frame := append(header[:], sealed...)
		n, err := s.file.Write(frame)
		if err == nil && n != len(frame) {
			err = io.ErrShortWrite
		}
		if err != nil {
			return total, err
		}
		s.records++
		s.stored += int64(n)
		s.size += int64(len(chunk))
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

// Each reader has its own offset and nonce counter. Only committed, complete
// records are read; partial storage writes leave the remainder in memory.
func (s *bodySpool) reader() io.Reader {
	if s.file == nil {
		return bytes.NewReader(s.buf.Bytes())
	}
	return &spoolReader{reader: io.NewSectionReader(s.file, 0, s.stored), aead: s.aead, nonce: s.nonce, records: s.records}
}

func (s *bodySpool) Close() error {
	s.closeOnce.Do(func() {
		if s.file != nil {
			s.closeErr = s.file.Close()
		}
	})
	return s.closeErr
}

type spoolReader struct {
	reader  io.Reader
	aead    cipher.AEAD
	nonce   [12]byte
	record  uint64
	records uint64
	buf     []byte
}

func (r *spoolReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.buf) == 0 {
		if r.record == r.records {
			return 0, io.EOF
		}
		var header [4]byte
		if _, err := io.ReadFull(r.reader, header[:]); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return 0, err
		}
		size := int(binary.BigEndian.Uint32(header[:]))
		if size < r.aead.Overhead() || size > spoolChunk+r.aead.Overhead() {
			return 0, errors.New("invalid replay record")
		}
		data := make([]byte, size)
		if _, err := io.ReadFull(r.reader, data); err != nil {
			return 0, err
		}
		binary.BigEndian.PutUint64(r.nonce[4:], r.record)
		var err error
		r.buf, err = r.aead.Open(data[:0], r.nonce[:], data, nil)
		if err != nil {
			return 0, err
		}
		r.record++
	}
	n := copy(p, r.buf)
	clear(r.buf[:n])
	r.buf = r.buf[n:]
	return n, nil
}

type inspectionBody struct {
	io.Reader
	original    io.Closer
	spool       *bodySpool
	complete    bool
	coverageErr error
	closeOnce   sync.Once
	closeErr    error
}

func (b *inspectionBody) Close() error {
	b.closeOnce.Do(func() { b.closeErr = errors.Join(b.spool.Close(), b.original.Close()) })
	return b.closeErr
}
