package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync/atomic"
)

// dbCounters are shared by every pooled connection of one store.
type dbCounters struct {
	// writes advances once a write is visible to new reads: after an
	// autocommit Exec returns, or after Commit of a transaction that ran Exec.
	writes     atomic.Uint64
	statements atomic.Uint64
}

// WriteGeneration changes after every committed database write and every
// agent-history lock change, so a read begun after loading it reflects every
// change the loaded value counts.
func (s *Store) WriteGeneration() uint64 { return s.counters.writes.Load() }

// StatementCount is the number of SQL statements the store has run.
func (s *Store) StatementCount() uint64 { return s.counters.statements.Load() }

// openCounted opens dsn with the registered sqlite driver through
// connections that maintain counters.
func openCounted(dsn string, counters *dbCounters) (*sql.DB, error) {
	probe, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	drv := probe.Driver()
	if err := probe.Close(); err != nil {
		return nil, err
	}
	return sql.OpenDB(countingConnector{dsn: dsn, drv: drv, counters: counters}), nil
}

type countingConnector struct {
	dsn      string
	drv      driver.Driver
	counters *dbCounters
}

// sqliteConn is the connection surface database/sql uses on the driver.
type sqliteConn interface {
	driver.Conn
	driver.ConnBeginTx
	driver.ConnPrepareContext
	driver.ExecerContext
	driver.QueryerContext
	driver.Pinger
	driver.SessionResetter
	driver.Validator
}

type sqliteStmt interface {
	driver.Stmt
	driver.StmtExecContext
	driver.StmtQueryContext
}

func (c countingConnector) Connect(ctx context.Context) (driver.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := c.drv.Open(c.dsn)
	if err != nil {
		return nil, err
	}
	inner, ok := conn.(sqliteConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("sqlite driver connection lacks context methods")
	}
	return &countingConn{inner: inner, counters: c.counters}, nil
}

func (c countingConnector) Driver() driver.Driver { return c.drv }

// countingConn counts statements and advances the write generation once a
// write is visible. database/sql never uses one connection concurrently.
type countingConn struct {
	inner    sqliteConn
	counters *dbCounters
	tx       *countingTx
}

// wrote records an Exec: inside a transaction it advances at Commit.
func (c *countingConn) wrote() {
	if c.tx != nil {
		c.tx.wrote = true
		return
	}
	c.counters.writes.Add(1)
}

func (c *countingConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.counters.statements.Add(1)
	defer c.wrote()
	return c.inner.ExecContext(ctx, query, args)
}

func (c *countingConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.counters.statements.Add(1)
	return c.inner.QueryContext(ctx, query, args)
}

func (c *countingConn) Prepare(query string) (driver.Stmt, error) {
	return c.PrepareContext(context.Background(), query)
}

func (c *countingConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	st, err := c.inner.PrepareContext(ctx, query)
	if err != nil {
		return nil, err
	}
	inner, ok := st.(sqliteStmt)
	if !ok {
		_ = st.Close()
		return nil, errors.New("sqlite driver statement lacks context methods")
	}
	return &countingStmt{inner: inner, conn: c}, nil
}

func (c *countingConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

func (c *countingConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	tx, err := c.inner.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	c.tx = &countingTx{inner: tx, conn: c}
	return c.tx, nil
}

func (c *countingConn) Close() error                           { return c.inner.Close() }
func (c *countingConn) Ping(ctx context.Context) error         { return c.inner.Ping(ctx) }
func (c *countingConn) ResetSession(ctx context.Context) error { return c.inner.ResetSession(ctx) }
func (c *countingConn) IsValid() bool                          { return c.inner.IsValid() }

type countingTx struct {
	inner driver.Tx
	conn  *countingConn
	wrote bool
}

func (t *countingTx) Commit() error {
	err := t.inner.Commit()
	t.conn.tx = nil
	if t.wrote {
		t.conn.counters.writes.Add(1)
	}
	return err
}

func (t *countingTx) Rollback() error {
	t.conn.tx = nil
	return t.inner.Rollback()
}

type countingStmt struct {
	inner sqliteStmt
	conn  *countingConn
}

func (s *countingStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	s.conn.counters.statements.Add(1)
	defer s.conn.wrote()
	return s.inner.ExecContext(ctx, args)
}

func (s *countingStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	s.conn.counters.statements.Add(1)
	return s.inner.QueryContext(ctx, args)
}

func (s *countingStmt) Exec(args []driver.Value) (driver.Result, error) {
	return s.ExecContext(context.Background(), namedValues(args))
}

func (s *countingStmt) Query(args []driver.Value) (driver.Rows, error) {
	return s.QueryContext(context.Background(), namedValues(args))
}

func (s *countingStmt) Close() error  { return s.inner.Close() }
func (s *countingStmt) NumInput() int { return s.inner.NumInput() }

func namedValues(args []driver.Value) []driver.NamedValue {
	out := make([]driver.NamedValue, len(args))
	for i, v := range args {
		out[i] = driver.NamedValue{Ordinal: i + 1, Value: v}
	}
	return out
}
