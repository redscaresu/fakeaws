package handlers_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redscaresu/fakeaws/handlers/awsproto"
)

// accountDefaultFuncs are the only places in non-test handlers code
// that may name FakeAccountID: its declaration in awsproto.go,
// AccountID, the accessor every handler reads, and setIdentity, which
// hands SetIdentity the account that holds when none is stored.
var accountDefaultFuncs = map[string]bool{
	"awsproto/awsproto.go:": true,
	"admin.go:AccountID":    true,
	"admin.go:setIdentity":  true,
}

// TestAccountSourceScan closes the class the identity stories moved
// off: a handler answering 000000000000 instead of the stored account.
// Outside awsproto.go no non-test handlers file holds the literal, and
// only accountDefaultFuncs reference awsproto.FakeAccountID.
func TestAccountSourceScan(t *testing.T) {
	files := append(globGo(t, ".", "*.go", true), globGo(t, "awsproto", "*.go", true)...)
	require.NotEmpty(t, files)
	for _, path := range files {
		src, err := os.ReadFile(path)
		require.NoError(t, err)
		if path != filepath.Join("awsproto", "awsproto.go") {
			for i, line := range strings.Split(string(src), "\n") {
				assert.False(t, strings.Contains(line, awsproto.FakeAccountID), "%s:%d holds the literal default account", path, i+1)
			}
		}
		for _, use := range fakeAccountIDUses(t, path, src) {
			assert.True(t, accountDefaultFuncs[use], "%s references FakeAccountID; read app.AccountID() instead", use)
		}
	}
}

// fakeAccountIDUses returns "<file>:<func>" for each identifier named
// FakeAccountID in src, however its package is qualified, with an empty
// func outside any function.
func fakeAccountIDUses(t *testing.T, path string, src []byte) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
	require.NoError(t, err)
	var uses []string
	for _, decl := range f.Decls {
		name := ""
		if fn, ok := decl.(*ast.FuncDecl); ok {
			name = fn.Name.Name
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && id.Name == "FakeAccountID" {
				uses = append(uses, filepath.ToSlash(path)+":"+name)
			}
			return true
		})
	}
	return uses
}
