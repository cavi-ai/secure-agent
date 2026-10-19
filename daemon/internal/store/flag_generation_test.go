package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cavi-ai/secure-agent/daemon/internal/model"
)

// Cached flag reads trust the generation, so every statement that writes
// flags or advisor verdicts must reach flagsChanged: in its own method, or in
// every function that calls the helper or uses the statement it sits in.
// Schema setup runs before the store exists and is exempt.
func TestEveryFlagWriteAdvancesTheGeneration(t *testing.T) {
	write := regexp.MustCompile(`(?i)\b(INSERT(\s+OR\s+\w+)?\s+INTO|UPDATE|DELETE\s+FROM)\s+(flags|advisor_verdicts)\b`)
	exempt := map[string]bool{"migrations.go": true}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	funcs := map[string]*ast.FuncDecl{}
	var writers []string // functions and package-level variables holding a write
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") || exempt[name] {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			holder := ""
			switch d := decl.(type) {
			case *ast.FuncDecl:
				funcs[d.Name.Name] = d
				holder = d.Name.Name
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					if v, ok := spec.(*ast.ValueSpec); ok && len(v.Names) == 1 {
						holder = v.Names[0].Name
					}
				}
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING && write.MatchString(lit.Value) && holder != "" {
					writers = append(writers, holder)
				}
				return true
			})
		}
	}
	bumps := func(fn *ast.FuncDecl) bool {
		found := false
		ast.Inspect(fn, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "flagsChanged" {
				found = true
			}
			return !found
		})
		return found
	}
	uses := func(fn *ast.FuncDecl, name string) bool {
		found := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == name {
				found = true
			}
			return !found
		})
		return found
	}
	if len(writers) < 10 {
		t.Fatalf("found %d flag writers; the scan no longer sees the store's statements", len(writers))
	}
	for _, w := range writers {
		if fn := funcs[w]; fn != nil && fn.Recv != nil && bumps(fn) {
			continue
		}
		users := 0
		for name, fn := range funcs {
			if name == w || fn.Body == nil || !uses(fn, w) {
				continue
			}
			users++
			if !bumps(fn) {
				t.Errorf("%s writes flags or advisor verdicts through %s without flagsChanged", name, w)
			}
		}
		if users == 0 && (funcs[w] == nil || funcs[w].Recv == nil || !bumps(funcs[w])) {
			t.Errorf("%s writes flags or advisor verdicts without flagsChanged", w)
		}
	}
}

func TestFlagWritesAdvanceTheGeneration(t *testing.T) {
	s := reviewStore(t)
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	step := func(name string, write func() bool) {
		t.Helper()
		before := s.FlagGeneration()
		changed := write()
		if after := s.FlagGeneration(); (after != before) != changed {
			t.Errorf("%s: generation %d -> %d, write changed rows %v", name, before, after, changed)
		}
	}
	step("put", func() bool {
		r, err := s.PutFlag(model.Flag{ID: "g1", Rule: "r", Severity: 2, PID: 7, Agent: "untagged:7", TS: at})
		return err == nil && r.Changed
	})
	step("repeat", func() bool { return s.BumpFlagRepeat("g1", at.Add(time.Minute)) })
	step("reattribute", func() bool { return s.ReattributeFlags(7, "claude", at.Add(-time.Hour)) > 0 })
	step("verdict", func() bool {
		return s.PutAdvisorVerdict("g1", "flag", model.AdvisorVerdict{Rationale: "r", CreatedAt: at}) == nil
	})
	step("acknowledge", func() bool { return s.AcknowledgeFlag("g1") })
	step("acknowledge missing", func() bool { return s.AcknowledgeFlag("missing") })
	step("reattribute nothing", func() bool { return s.ReattributeFlags(99, "claude", at) > 0 })
}
