package store

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/event"
	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// Writes to each table the snapshot and posture read advance WriteGeneration;
// reads leave it unchanged.
func TestWriteGenerationFollowsCommittedWrites(t *testing.T) {
	s := reviewStore(t)
	at := time.Now().UTC()
	step := func(name string, advances bool, op func() error) {
		t.Helper()
		before := s.WriteGeneration()
		if err := op(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if moved := s.WriteGeneration() != before; moved != advances {
			t.Errorf("%s: generation moved %v, want %v", name, moved, advances)
		}
	}
	f := model.Flag{ID: "g1", Rule: "sensitive-read-then-connect", Severity: 3, PID: 7, Agent: "claude", TS: at}
	step("event", true, func() error {
		_, err := s.PutEvent(event.Event{Kind: event.KindFileOpen, PID: 7, TS: at})
		return err
	})
	step("session", true, func() error { return s.UpsertSession(model.Session{ID: "s1", Harness: "claude"}) })
	step("flag", true, func() error {
		_, err := s.PutFlag(f)
		return err
	})
	step("advisor verdict", true, func() error {
		return s.PutAdvisorVerdict("g1", "flag", model.AdvisorVerdict{Rationale: "r", CreatedAt: at})
	})
	step("finding review", true, func() error {
		_, err := s.ObserveFindingReview(f, model.AssessFinding(f))
		return err
	})
	step("incident", true, func() error {
		return s.PutIncident(model.IncidentReport{ID: "i1", FlagID: "g1", Rule: f.Rule, Timestamp: at})
	})
	step("event read", false, func() error {
		_, err := s.QueryEvents(EventFilter{Limit: 5})
		return err
	})
	step("flag read", false, func() error {
		_, err := s.QueryFlags(FlagFilter{Limit: 5})
		return err
	})
	step("review read", false, func() error {
		_, err := s.ListFindingReviews("", 10)
		return err
	})
	step("agent history lock", true, func() error {
		s.LockAgentHistory()
		return nil
	})
}

// A transaction advances the generation when it commits, never before, so a
// reader that loads it first cannot pair the new value with older rows.
func TestWriteGenerationAdvancesAtCommit(t *testing.T) {
	s := reviewStore(t)
	const touch = `UPDATE flags SET severity = severity WHERE id = 'none'`
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	before := s.WriteGeneration()
	if _, err := tx.Exec(touch); err != nil {
		t.Fatal(err)
	}
	if s.WriteGeneration() != before {
		t.Fatal("generation advanced before commit")
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if s.WriteGeneration() == before {
		t.Fatal("commit did not advance the generation")
	}

	ctx := context.Background()
	itx, err := s.beginImmediate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer itx.Rollback()
	if _, err := itx.ExecContext(ctx, touch); err != nil {
		t.Fatal(err)
	}
	inside := s.WriteGeneration()
	if err := itx.Commit(); err != nil {
		t.Fatal(err)
	}
	if s.WriteGeneration() == inside {
		t.Fatal("COMMIT on a pinned connection did not advance the generation")
	}

	rtx, err := s.readTx()
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := rtx.QueryRow(`SELECT COUNT(*) FROM flags`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	before = s.WriteGeneration()
	if err := rtx.Commit(); err != nil {
		t.Fatal(err)
	}
	if s.WriteGeneration() != before {
		t.Fatal("a read-only transaction advanced the generation")
	}
}

// Query methods never advance WriteGeneration, so no store statement may
// write through one.
func TestNoStoreWriteRunsThroughAQuery(t *testing.T) {
	write := regexp.MustCompile(`(?is)^\s*(INSERT|UPDATE|DELETE|REPLACE)\b`)
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	values := map[string]ast.Expr{}
	var parsed []*ast.File
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, f)
		for _, decl := range f.Decls {
			if d, ok := decl.(*ast.GenDecl); ok {
				for _, spec := range d.Specs {
					if v, ok := spec.(*ast.ValueSpec); ok && len(v.Names) == len(v.Values) {
						for i, n := range v.Names {
							values[n.Name] = v.Values[i]
						}
					}
				}
			}
		}
	}
	literals := func(e ast.Expr) []string {
		var out []string
		var visit func(ast.Expr, bool)
		visit = func(e ast.Expr, follow bool) {
			ast.Inspect(e, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.BasicLit:
					if s, err := strconv.Unquote(n.Value); err == nil && n.Kind == token.STRING {
						out = append(out, s)
					}
				case *ast.Ident:
					if v := values[n.Name]; v != nil && follow {
						visit(v, false)
					}
				}
				return true
			})
		}
		visit(e, true)
		return out
	}
	queries := 0
	for _, f := range parsed {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "Query", "QueryRow", "QueryContext", "QueryRowContext":
				queries++
				for _, arg := range call.Args {
					for _, lit := range literals(arg) {
						if write.MatchString(lit) {
							t.Errorf("%s: %s runs a write statement", fset.Position(call.Pos()), sel.Sel.Name)
						}
					}
				}
			}
			return true
		})
	}
	if queries < 50 {
		t.Fatalf("found %d query calls; the scan no longer sees the store's reads", queries)
	}
}
