package handlers_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scanPkg indexes one package's non-test functions by name: package
// funcs, and methods on its own receiver type (Application, Repository).
type scanPkg struct {
	name    string
	funcs   map[string]*ast.FuncDecl
	methods map[string]*ast.FuncDecl
}

func loadScanPkg(t *testing.T, fset *token.FileSet, name, dir, recv string) *scanPkg {
	t.Helper()
	p := &scanPkg{name: name, funcs: map[string]*ast.FuncDecl{}, methods: map[string]*ast.FuncDecl{}}
	for _, path := range globGo(t, dir, "*.go", true) {
		f, err := parser.ParseFile(fset, path, nil, 0)
		require.NoError(t, err)
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			switch {
			case fn.Recv == nil:
				p.funcs[fn.Name.Name] = fn
			case strings.TrimPrefix(recvType(fn.Recv.List[0].Type), "*") == recv:
				p.methods[fn.Name.Name] = fn
			}
		}
	}
	return p
}

func recvType(e ast.Expr) string {
	if s, ok := e.(*ast.StarExpr); ok {
		return "*" + recvType(s.X)
	}
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// TestStateReadsKeepEveryError walks every function GET /mock/state can
// reach, from collectState through the gathers, their helpers and each
// Repository method they call, and fails on any way to lose a read
// error: a `_` in an assignment or a var (unless the last value is a
// checked err), a call statement that drops its results (outside
// bareCalls), an `if err != nil` whose block does not end by returning a
// non-nil error (a continue, `return nil`, `return x, nil`), an
// `if err == nil` (its else is a fallback that drops the error), and a
// rows.Next loop with no rows.Err. A skip on purpose names its error
// (`errors.Is(err, models.ErrNotFound)`), which this scan does not match.
func TestStateReadsKeepEveryError(t *testing.T) {
	fset := token.NewFileSet()
	pkgs := map[string]*scanPkg{
		"handlers":   loadScanPkg(t, fset, "handlers", ".", "Application"),
		"repository": loadScanPkg(t, fset, "repository", filepath.Join("..", "repository"), "Repository"),
	}
	type ref struct{ pkg, name string }
	root := ref{"handlers", "collectState"}
	require.Contains(t, pkgs["handlers"].methods, root.name)

	seen := map[ref]bool{root: true}
	queue := []ref{root}
	reach := func(r ref) {
		if !seen[r] {
			seen[r] = true
			queue = append(queue, r)
		}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		p := pkgs[cur.pkg]
		fn := p.methods[cur.name]
		if fn == nil {
			fn = p.funcs[cur.name]
		}
		if fn == nil {
			continue // a method of another type, or outside both packages
		}
		recv := ""
		if fn.Recv != nil && len(fn.Recv.List[0].Names) > 0 {
			recv = fn.Recv.List[0].Names[0].Name
		}
		where := cur.pkg + "." + cur.name
		nexts, errs := map[string]bool{}, map[string]bool{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.Ident:
				if _, ok := p.funcs[n.Name]; ok {
					reach(ref{cur.pkg, n.Name})
				}
			case *ast.SelectorExpr:
				if x, ok := n.X.(*ast.Ident); ok && x.Name == recv && recv != "" {
					reach(ref{cur.pkg, n.Sel.Name})
				}
				if x, ok := n.X.(*ast.SelectorExpr); ok && x.Sel.Name == "repo" {
					reach(ref{"repository", n.Sel.Name})
				}
			case *ast.CallExpr:
				if sel, ok := n.Fun.(*ast.SelectorExpr); ok {
					if x, ok := sel.X.(*ast.Ident); ok && sel.Sel.Name == "Next" {
						nexts[x.Name] = true
					}
					if x, ok := sel.X.(*ast.Ident); ok && sel.Sel.Name == "Err" {
						errs[x.Name] = true
					}
				}
			case *ast.AssignStmt:
				if discards(n.Lhs) {
					assert.Fail(t, "a state read discards a value with _", "%s at %s", where, fset.Position(n.Pos()))
				}
			case *ast.ExprStmt:
				if call, ok := n.X.(*ast.CallExpr); ok && !bareCallAllowed(call) {
					assert.Fail(t, "a state read drops a call's results", "%s at %s", where, fset.Position(n.Pos()))
				}
			case *ast.ValueSpec:
				if len(n.Values) > 0 && discards(identExprs(n.Names)) {
					assert.Fail(t, "a state read declares a value as _", "%s at %s", where, fset.Position(n.Pos()))
				}
			case *ast.IfStmt:
				if isErrCompare(n.Cond, token.NEQ) && !returnsError(n.Body) {
					assert.Fail(t, "a state read's `if err != nil` does not return the error", "%s at %s", where, fset.Position(n.Pos()))
				}
				if isErrCompare(n.Cond, token.EQL) {
					assert.Fail(t, "a state read branches on `err == nil`, so its else drops the error", "%s at %s", where, fset.Position(n.Pos()))
				}
			}
			return true
		})
		for rows := range nexts {
			assert.True(t, errs[rows], "%s iterates %s.Next() and never checks %s.Err()", where, rows, rows)
		}
	}

	var gathers []string
	for r := range seen {
		if strings.HasPrefix(r.name, "gather") {
			gathers = append(gathers, r.name)
		}
	}
	sort.Strings(gathers)
	require.NotEmpty(t, gathers, "collectState reaches no gather")
	t.Logf("scanned %d functions, gathers %v", len(seen), gathers)
}

// discards reports whether an assignment binds a `_`, unless its last
// value is bound to an err name (`_, err := r.GetHostedZone(...)` keeps
// the error, which the `if err != nil` rule then checks).
func discards(lhs []ast.Expr) bool {
	last, ok := lhs[len(lhs)-1].(*ast.Ident)
	errLast := ok && last.Name != "_" && strings.Contains(strings.ToLower(last.Name), "err")
	for _, e := range lhs {
		if id, ok := e.(*ast.Ident); ok && id.Name == "_" && !errLast {
			return true
		}
	}
	return false
}

func identExprs(ids []*ast.Ident) []ast.Expr {
	out := make([]ast.Expr, len(ids))
	for i, id := range ids {
		out[i] = id
	}
	return out
}

// bareCalls are the only calls a state read may make as a statement,
// its results dropped: rows.Close, once rows.Err is checked, and
// log.Printf, which returns nothing. Anything else (json.Unmarshal,
// rows.Scan, fmt.Printf) must bind its error.
var bareCalls = map[string]bool{"rows.Close": true, "log.Printf": true}

func bareCallAllowed(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	x, ok := sel.X.(*ast.Ident)
	return ok && bareCalls[x.Name+"."+sel.Sel.Name]
}

// isErrCompare reports whether cond is `<name> <op> nil` for a name
// holding "err" in any case.
func isErrCompare(cond ast.Expr, op token.Token) bool {
	b, ok := cond.(*ast.BinaryExpr)
	if !ok || b.Op != op {
		return false
	}
	x, xok := b.X.(*ast.Ident)
	y, yok := b.Y.(*ast.Ident)
	return xok && yok && y.Name == "nil" && strings.Contains(strings.ToLower(x.Name), "err")
}

// returnsError reports whether a block ends in a return whose last
// result is not the literal nil.
func returnsError(body *ast.BlockStmt) bool {
	if len(body.List) == 0 {
		return false
	}
	ret, ok := body.List[len(body.List)-1].(*ast.ReturnStmt)
	if !ok || len(ret.Results) == 0 {
		return false
	}
	id, ok := ret.Results[len(ret.Results)-1].(*ast.Ident)
	return !ok || id.Name != "nil"
}
