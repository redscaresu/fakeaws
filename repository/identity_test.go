package repository

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loaded(t *testing.T, r *Repository) bool {
	t.Helper()
	got, err := r.Loaded()
	require.NoError(t, err)
	return got
}

// The flag survives snapshot/restore and a reopen, and reset clears it
// with the identity row.
func TestLoadedFlagLifecycle(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	r, err := New(dbPath)
	require.NoError(t, err)
	assert.False(t, loaded(t, r), "no identity row")

	require.NoError(t, r.SetLoaded(true, "000000000000"))
	assert.True(t, loaded(t, r))
	id, err := r.GetIdentity()
	require.NoError(t, err)
	assert.Equal(t, Identity{AccountID: "000000000000"}, id, "SetLoaded stores the default account when none is stored")

	require.NoError(t, r.Snapshot())
	require.NoError(t, r.SetLoaded(false, "000000000000"))
	assert.False(t, loaded(t, r))
	require.NoError(t, r.Restore(nil))
	assert.True(t, loaded(t, r), "restore")

	require.NoError(t, r.Close())
	r, err = New(dbPath)
	require.NoError(t, err)
	defer r.Close()
	assert.True(t, loaded(t, r), "reopen")

	require.NoError(t, r.Reset())
	assert.False(t, loaded(t, r), "reset")
}

// SetLoaded leaves the stored account and region alone.
func TestSetLoadedKeepsIdentity(t *testing.T) {
	r, err := New(":memory:")
	require.NoError(t, err)
	defer r.Close()
	want := Identity{AccountID: "111111111111", Region: "eu-west-1"}
	require.NoError(t, r.SetIdentity(want, "000000000000", nil))
	require.NoError(t, r.SetLoaded(true, "000000000000"))
	got, err := r.GetIdentity()
	require.NoError(t, err)
	assert.Equal(t, want, got)
	assert.True(t, loaded(t, r))
}
