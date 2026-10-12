package repository

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redscaresu/fakeaws/models"
)

func ssmPut(name, value string) *SSMParameterPut {
	return &SSMParameterPut{Name: name, Type: "String", Value: value, Region: testRegion, Now: "t"}
}

func TestSSMParameterPutNoOverwriteConflicts(t *testing.T) {
	r := setupRepo(t)
	v, err := r.PutSSMParameter(testAccount, ssmPut("/app/x", "one"), false)
	require.NoError(t, err)
	assert.Equal(t, int64(1), v)

	_, err = r.PutSSMParameter(testAccount, ssmPut("/app/x", "two"), false)
	assert.ErrorIs(t, err, models.ErrConflict)

	got, err := r.GetSSMParameter(testAccount, testRegion, "/app/x")
	require.NoError(t, err)
	assert.Equal(t, "one", got.Value)
	assert.Equal(t, int64(1), got.Version)
}

func TestSSMParameterOverwriteKeepsOmittedFields(t *testing.T) {
	r := setupRepo(t)
	desc := "first"
	create := ssmPut("/app/x", "one")
	create.Description = &desc
	create.Tags = map[string]string{"env": "dev"}
	_, err := r.PutSSMParameter(testAccount, create, false)
	require.NoError(t, err)

	v, err := r.PutSSMParameter(testAccount, ssmPut("/app/x", "two"), true)
	require.NoError(t, err)
	assert.Equal(t, int64(2), v)

	got, err := r.GetSSMParameter(testAccount, testRegion, "/app/x")
	require.NoError(t, err)
	assert.Equal(t, "two", got.Value)
	assert.Equal(t, "first", got.Description)
	assert.Equal(t, "text", got.DataType)
	assert.Equal(t, "Standard", got.Tier)
	assert.Equal(t, map[string]string{"env": "dev"}, got.Tags)
}

func TestSSMParameterPatchTags(t *testing.T) {
	r := setupRepo(t)
	p := ssmPut("x", "v")
	p.Tags = map[string]string{"a": "1", "b": "2"}
	_, err := r.PutSSMParameter(testAccount, p, false)
	require.NoError(t, err)

	require.NoError(t, r.PatchSSMParameterTags(testAccount, testRegion, "x", map[string]any{"a": nil, "c": "3"}))
	got, err := r.GetSSMParameter(testAccount, testRegion, "x")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"b": "2", "c": "3"}, got.Tags)

	err = r.PatchSSMParameterTags(testAccount, testRegion, "missing", map[string]any{"a": "1"})
	assert.ErrorIs(t, err, models.ErrNotFound)
}

func TestSSMParameterDelete(t *testing.T) {
	r := setupRepo(t)
	_, err := r.PutSSMParameter(testAccount, ssmPut("x", "v"), false)
	require.NoError(t, err)
	require.NoError(t, r.DeleteSSMParameter(testAccount, testRegion, "x"))

	assert.ErrorIs(t, r.DeleteSSMParameter(testAccount, testRegion, "x"), models.ErrNotFound)
	_, err = r.GetSSMParameter(testAccount, testRegion, "x")
	assert.ErrorIs(t, err, models.ErrNotFound)
}

func TestSSMParameterResetSnapshotRestore(t *testing.T) {
	r, err := New(filepath.Join(t.TempDir(), "test.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })

	_, err = r.PutSSMParameter(testAccount, ssmPut("kept", "v"), false)
	require.NoError(t, err)
	require.NoError(t, r.Snapshot())
	require.NoError(t, r.DeleteSSMParameter(testAccount, testRegion, "kept"))
	require.NoError(t, r.Restore(nil))

	got, err := r.GetSSMParameter(testAccount, testRegion, "kept")
	require.NoError(t, err)
	assert.Equal(t, "v", got.Value)

	require.NoError(t, r.Reset())
	params, err := r.ListSSMParameters(testAccount, "")
	require.NoError(t, err)
	assert.Empty(t, params)
}

func TestIsPublicSSMParameter(t *testing.T) {
	assert.True(t, IsPublicSSMParameter("/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"))
	for _, name := range []string{"/app/x", "aws/service/x", "/aws/servicex", "/AWS/service/x"} {
		assert.False(t, IsPublicSSMParameter(name), name)
	}
}

func TestSSMParameterRefMatchesItsOwnARN(t *testing.T) {
	const public = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
	r := setupRepo(t)
	for _, name := range []string{public, "/app/x"} {
		_, err := r.PutSSMParameter(testAccount, ssmPut(name, "v"), false)
		require.NoError(t, err)
	}
	arn := func(account, name string) string {
		return "arn:aws:ssm:" + testRegion + ":" + account + ":parameter" + name
	}

	for ref, want := range map[string]string{
		public:                     public,
		arn("", public):            public,
		"/app/x":                   "/app/x",
		arn(testAccount, "/app/x"): "/app/x",
	} {
		got, err := r.GetSSMParameter(testAccount, testRegion, ref)
		if assert.NoError(t, err, ref) {
			assert.Equal(t, want, got.Name, ref)
		}
	}
	for _, ref := range []string{
		arn(testAccount, public),
		arn("", "/app/x"),
		arn("111111111111", "/app/x"),
		"arn:aws:ssm:eu-west-9:" + testAccount + ":parameter/app/x",
		arn(testAccount, "//app/x"),
		arn("", "/"+public),
		arn(testAccount, "/"),
	} {
		_, err := r.GetSSMParameter(testAccount, testRegion, ref)
		assert.ErrorIs(t, err, models.ErrNotFound, ref)
		assert.ErrorIs(t, r.PatchSSMParameterTags(testAccount, testRegion, ref, map[string]any{"a": "1"}), models.ErrNotFound, ref)
	}

	require.NoError(t, r.PatchSSMParameterTags(testAccount, testRegion, arn(testAccount, "/app/x"), map[string]any{"a": "1"}))
	got, err := r.GetSSMParameter(testAccount, testRegion, "/app/x")
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"a": "1"}, got.Tags)
}

func TestSSMParameterPatchTagsNeverTouchesPublic(t *testing.T) {
	const public = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
	r := setupRepo(t)
	p := ssmPut(public, "v")
	p.Tags = map[string]string{"k": "v"}
	_, err := r.PutSSMParameter(testAccount, p, false)
	require.NoError(t, err)

	for _, ref := range []string{public, "arn:aws:ssm:" + testRegion + "::parameter" + public} {
		err := r.PatchSSMParameterTags(testAccount, testRegion, ref, map[string]any{"k": nil, "a": "1"})
		assert.ErrorIs(t, err, models.ErrNotFound, ref)
	}
	got, err := r.GetSSMParameter(testAccount, testRegion, public)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"k": "v"}, got.Tags)
}

func TestSSMParameterDeleteNeverTouchesPublic(t *testing.T) {
	const public = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
	r := setupRepo(t)
	_, err := r.PutSSMParameter(testAccount, ssmPut(public, "v"), false)
	require.NoError(t, err)

	assert.ErrorIs(t, r.DeleteSSMParameter(testAccount, testRegion, public), models.ErrNotFound)
	got, err := r.GetSSMParameter(testAccount, testRegion, public)
	require.NoError(t, err, "DeleteSSMParameter removed the public row")
	assert.Equal(t, "v", got.Value)
}
