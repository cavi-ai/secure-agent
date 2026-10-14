package forwarder

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	sqlite "modernc.org/sqlite"
	lib "modernc.org/sqlite/lib"

	"github.com/cavi-ai/secure-agent/daemon/hookrun"
	"github.com/cavi-ai/secure-agent/internal/durablefs"
)

var (
	ErrStorage     = errors.New("hook outbox storage unavailable")
	ErrClosed      = errors.New("hook forwarder is closed")
	ErrUnpersisted = errors.New("hook forwarder closed with unpersisted completions")
)

// DurableSender acknowledges synchronized destination storage. Outbox records
// may be removed only after this stronger acknowledgment, not a pipe write or
// an ordinary append. Implementations must tolerate replay after uncertain acks.
type DurableSender interface {
	Sender
	SendDurable(context.Context, []byte) error
}

type outbox struct {
	db   *sql.DB
	lock *os.File
}

const outboxApplicationID = 0x5341484f

func privateOutboxFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, ErrStorage
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	var stat unix.Stat_t
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || unix.Fstat(fd, &stat) != nil || stat.Uid != uint32(os.Getuid()) {
		f.Close()
		return nil, ErrStorage
	}
	return f, nil
}

func openOutbox(cfg Config) (o *outbox, items []queued, err error) {
	if !filepath.IsAbs(cfg.OutboxDir) {
		return nil, nil, errors.New("hook outbox requires an absolute directory")
	}
	if err := durablefs.MakeDir(cfg.OutboxDir); err != nil {
		return nil, nil, ErrStorage
	}
	info, err := os.Lstat(cfg.OutboxDir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, nil, ErrStorage
	}
	var stat unix.Stat_t
	if unix.Stat(cfg.OutboxDir, &stat) != nil || stat.Uid != uint32(os.Getuid()) {
		return nil, nil, ErrStorage
	}
	lock, err := privateOutboxFile(filepath.Join(cfg.OutboxDir, "outbox.lock"))
	if err != nil {
		return nil, nil, err
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, nil, errors.New("hook outbox is already owned or unavailable")
	}
	o = &outbox{lock: lock}
	defer func() {
		if err != nil {
			o.close()
			o = nil
			items = nil
			err = ErrStorage
		}
	}()
	path := filepath.Join(cfg.OutboxDir, "outbox.db")
	f, err := privateOutboxFile(path)
	if err != nil {
		return o, nil, err
	}
	fi, err := f.Stat()
	closeErr := f.Close()
	if err != nil || closeErr != nil || fi.Size() > cfg.OutboxMaxBytes {
		return o, nil, ErrStorage
	}
	fresh := fi.Size() == 0
	u := url.URL{Scheme: "file", Path: path}
	// These settings are connection-local. database/sql may discard an
	// interrupted connection, so every replacement must initialize them too.
	params := url.Values{}
	for _, pragma := range []string{"busy_timeout(0)", "trusted_schema(OFF)", "synchronous(FULL)", "fullfsync(ON)", "journal_size_limit(0)", fmt.Sprintf("max_page_count(%d)", cfg.OutboxMaxBytes/4096)} {
		params.Add("_pragma", pragma)
	}
	u.RawQuery = params.Encode()
	o.db, err = sql.Open("sqlite", u.String())
	if err != nil {
		return o, nil, err
	}
	o.db.SetMaxOpenConns(1)
	o.db.SetMaxIdleConns(1)
	var app, version int
	if err = o.db.QueryRow("PRAGMA application_id").Scan(&app); err != nil {
		return o, nil, err
	}
	if err = o.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return o, nil, err
	}
	if !fresh && (app != outboxApplicationID || version != 1) {
		return o, nil, ErrStorage
	}
	if _, err = o.db.Exec("PRAGMA busy_timeout=0; PRAGMA trusted_schema=OFF; PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA journal_size_limit=0;"); err != nil {
		return o, nil, err
	}
	var mode string
	if err = o.db.QueryRow("PRAGMA journal_mode=DELETE").Scan(&mode); err != nil || mode != "delete" {
		return o, nil, ErrStorage
	}
	if fresh {
		if _, err = o.db.Exec("PRAGMA page_size=4096; PRAGMA auto_vacuum=FULL"); err != nil {
			return o, nil, err
		}
	}
	var pageSize, limit, vacuum int64
	if err = o.db.QueryRow("PRAGMA page_size").Scan(&pageSize); err != nil {
		return o, nil, err
	}
	if pageSize != 4096 {
		return o, nil, ErrStorage
	}
	if err = o.db.QueryRow("PRAGMA auto_vacuum").Scan(&vacuum); err != nil || vacuum != 1 {
		return o, nil, ErrStorage
	}
	pages := cfg.OutboxMaxBytes / pageSize
	if err = o.db.QueryRow(fmt.Sprintf("PRAGMA max_page_count=%d", pages)).Scan(&limit); err != nil || limit > pages {
		return o, nil, ErrStorage
	}
	if fresh {
		tx, txErr := o.db.Begin()
		if txErr != nil {
			return o, nil, txErr
		}
		defer tx.Rollback()
		_, err = tx.Exec(fmt.Sprintf(`PRAGMA application_id=%d; PRAGMA user_version=1;
CREATE TABLE scope (id INTEGER PRIMARY KEY CHECK(id=1), harness TEXT NOT NULL, session TEXT NOT NULL);
CREATE TABLE pending (seq INTEGER PRIMARY KEY, session TEXT NOT NULL, id TEXT NOT NULL, data BLOB NOT NULL, UNIQUE(session,id));`, outboxApplicationID))
		if err != nil {
			return o, nil, err
		}
		if _, err = tx.Exec("INSERT INTO scope VALUES(1,?,?)", cfg.Harness, cfg.SessionID); err != nil {
			return o, nil, err
		}
		if err = tx.Commit(); err != nil {
			return o, nil, err
		}
	}
	var harness, session string
	if err = o.db.QueryRow("SELECT harness,session FROM scope WHERE id=1").Scan(&harness, &session); err != nil || harness != cfg.Harness || session != cfg.SessionID {
		return o, nil, ErrStorage
	}
	rows, err := o.db.Query("SELECT session,id,data FROM pending ORDER BY seq LIMIT ?", cfg.Capacity+1)
	if err != nil {
		return o, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var item queued
		if err = rows.Scan(&item.session, &item.id, &item.data); err != nil {
			return o, nil, err
		}
		r, ok, e := hookrun.DecodeRecord(item.data)
		if !ok || e != nil || r.ID != item.id || r.SessionID != item.session || r.Harness != cfg.Harness || cfg.SessionID != "" && r.SessionID != cfg.SessionID || len(items) >= cfg.Capacity {
			return o, nil, ErrStorage
		}
		item.persisted = true
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return o, nil, err
	}
	if err = durablefs.SyncDir(cfg.OutboxDir); err != nil {
		return o, nil, err
	}
	return o, items, nil
}

func (o *outbox) put(ctx context.Context, item queued) error {
	if _, err := o.db.ExecContext(ctx, "INSERT INTO pending(session,id,data) VALUES(?,?,?) ON CONFLICT(session,id) DO NOTHING", item.session, item.id, item.data); err != nil {
		return err
	}
	var data []byte
	if err := o.db.QueryRowContext(ctx, "SELECT data FROM pending WHERE session=? AND id=?", item.session, item.id).Scan(&data); err != nil {
		return err
	}
	if !bytes.Equal(data, item.data) {
		return ErrConflict
	}
	return nil
}

func (o *outbox) ack(ctx context.Context, item queued) error {
	// Destination durability was acknowledged before this call. A repeated
	// DELETE is safe after an uncertain local acknowledgment commit.
	_, err := o.db.ExecContext(ctx, "DELETE FROM pending WHERE session=? AND id=?", item.session, item.id)
	return err
}

func isOutboxFull(err error) bool {
	var e *sqlite.Error
	return errors.As(err, &e) && e.Code()&0xff == lib.SQLITE_FULL
}

func (o *outbox) close() error {
	var err error
	if o.db != nil {
		err = o.db.Close()
	}
	if o.lock != nil {
		err = errors.Join(err, o.lock.Close())
	}
	return err
}
