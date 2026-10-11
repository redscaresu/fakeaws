package main

import (
	"database/sql"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redscaresu/fakeaws/handlers"
)

const testToken = "s3cr3t-admin-token"

// env is a getenv backed by a map.
func env(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

func TestOptionsFromFlags_BindListensOnThatHost(t *testing.T) {
	opts, err := optionsFromFlags([]string{"-bind", "127.0.0.1", "-port", "0"}, env(nil))
	require.NoError(t, err)

	ln, err := net.Listen("tcp", opts.ListenAddr())
	require.NoError(t, err)
	defer ln.Close()
	assert.Equal(t, "127.0.0.1", ln.Addr().(*net.TCPAddr).IP.String())
}

func TestOptionsFromFlags_AdminToken(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		env  map[string]string
		want string
	}{
		{"flag sets it", []string{"-admin-token", "x"}, nil, "x"},
		{"flag beats env", []string{"-admin-token", "x"}, map[string]string{adminTokenEnv: "y"}, "x"},
		{"env alone sets it", nil, map[string]string{adminTokenEnv: "y"}, "y"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, err := optionsFromFlags(tc.args, env(tc.env))
			require.NoError(t, err)
			assert.Equal(t, tc.want, opts.AdminToken)
		})
	}
}

func TestOptionsFromFlags_Defaults(t *testing.T) {
	opts, err := optionsFromFlags(nil, env(nil))
	require.NoError(t, err)
	assert.Empty(t, opts.AdminToken)
	assert.Equal(t, ":8082", opts.ListenAddr())
}

func TestStartupMessage_NeverPrintsTheToken(t *testing.T) {
	opts, err := optionsFromFlags([]string{"-admin-token", testToken}, env(nil))
	require.NoError(t, err)
	msg := startupMessage(opts)
	assert.NotContains(t, msg, testToken)
	assert.Contains(t, msg, "admin-token set=true")

	opts, err = optionsFromFlags(nil, env(map[string]string{adminTokenEnv: testToken}))
	require.NoError(t, err)
	assert.NotContains(t, startupMessage(opts), testToken)

	opts, err = optionsFromFlags(nil, env(nil))
	require.NoError(t, err)
	assert.Contains(t, startupMessage(opts), "admin-token set=false")
}

func TestOptionsFromFlags_Identity(t *testing.T) {
	opts, err := optionsFromFlags([]string{"-account", "123456789012", "-region", "eu-west-1"}, env(nil))
	require.NoError(t, err)
	assert.Equal(t, "123456789012", opts.AccountID)
	assert.Equal(t, "eu-west-1", opts.Region)

	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"two-digit account": {[]string{"-account", "12"}, `invalid value "12" for flag -account: must be 12 digits`},
		"malformed region":  {[]string{"-account", "123456789012", "-region", "eu-west"}, `invalid value "eu-west" for flag -region: must look like us-east-1`},
		"region alone":      {[]string{"-region", "eu-west-1"}, "-region needs -account"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := optionsFromFlags(tc.args, env(nil))
			assert.EqualError(t, err, tc.want)
		})
	}
}

func TestBootWithoutAccountWritesNoIdentity(t *testing.T) {
	opts, err := optionsFromFlags(nil, env(nil))
	require.NoError(t, err)
	app, err := handlers.NewApplication(opts)
	require.NoError(t, err)
	defer app.Close()

	_, err = app.Repository().GetIdentity()
	assert.ErrorIs(t, err, sql.ErrNoRows)
}

func TestOptionsFromFlags_RecordRequestsNeedsAToken(t *testing.T) {
	_, err := optionsFromFlags([]string{"-record-requests"}, env(nil))
	assert.EqualError(t, err, "-record-requests needs an admin token: -admin-token or "+adminTokenEnv)

	for name, tc := range map[string]struct {
		args []string
		env  map[string]string
	}{
		"-admin-token": {[]string{"-record-requests", "-admin-token", testToken}, nil},
		adminTokenEnv:  {[]string{"-record-requests"}, map[string]string{adminTokenEnv: testToken}},
	} {
		t.Run(name, func(t *testing.T) {
			opts, err := optionsFromFlags(tc.args, env(tc.env))
			require.NoError(t, err)
			assert.True(t, opts.RecordRequests)

			app, err := handlers.NewApplication(opts)
			require.NoError(t, err)
			defer app.Close()
			req := httptest.NewRequest(http.MethodGet, "/mock/requests", nil)
			req.Header.Set("Authorization", "Bearer "+testToken)
			rec := httptest.NewRecorder()
			app.Router().ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		})
	}
}
