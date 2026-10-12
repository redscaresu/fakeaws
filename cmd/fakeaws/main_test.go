package main

import (
	"context"
	"database/sql"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

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

func TestRecordRequestsNeedsAToken(t *testing.T) {
	opts, err := optionsFromFlags([]string{"-record-requests"}, env(nil))
	require.NoError(t, err)
	_, err = handlers.NewApplication(opts)
	assert.ErrorIs(t, err, handlers.ErrRecordRequestsNeedsAdminToken, "main exits 1 on it, naming the token")

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

func TestOptionsFromFlags_LoadMaxBytes(t *testing.T) {
	opts, err := optionsFromFlags(nil, env(nil))
	require.NoError(t, err)
	assert.Zero(t, opts.LoadMaxBytes, "off by default")

	for name, tc := range map[string]struct {
		args []string
		env  map[string]string
	}{
		"-admin-token": {[]string{"-load-max-bytes", "1048576", "-admin-token", testToken}, nil},
		adminTokenEnv:  {[]string{"-load-max-bytes", "1048576"}, map[string]string{adminTokenEnv: testToken}},
	} {
		t.Run(name, func(t *testing.T) {
			opts, err := optionsFromFlags(tc.args, env(tc.env))
			require.NoError(t, err)
			assert.Equal(t, int64(1048576), opts.LoadMaxBytes)
		})
	}

	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no token": {[]string{"-load-max-bytes", "1048576"}, "-load-max-bytes needs -admin-token or " + adminTokenEnv},
		"negative": {[]string{"-load-max-bytes", "-1", "-admin-token", testToken}, `invalid value "-1" for flag -load-max-bytes: must be a byte count, 0 or more`},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := optionsFromFlags(tc.args, env(nil))
			assert.EqualError(t, err, tc.want)
		})
	}
}

// mainArgsEnv, set, makes TestLoadMaxBytesWithoutTokenExits run main
// with its value's fields as the arguments.
const mainArgsEnv = "FAKEAWS_TEST_MAIN_ARGS"

// TestLoadMaxBytesWithoutTokenExits runs this binary as fakeaws with
// -load-max-bytes and no token: it exits non-zero, naming the flag and
// both token sources.
func TestLoadMaxBytesWithoutTokenExits(t *testing.T) {
	if args := os.Getenv(mainArgsEnv); args != "" {
		os.Args = append([]string{"fakeaws"}, strings.Fields(args)...)
		main()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLoadMaxBytesWithoutTokenExits$")
	cmd.Env = append(os.Environ(), adminTokenEnv+"=", mainArgsEnv+"=-load-max-bytes 1048576 -bind 127.0.0.1 -port 0")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 10 * time.Second
	out, err := cmd.CombinedOutput()

	require.NoError(t, ctx.Err(), "fakeaws started: %s", out)
	var exit *exec.ExitError
	require.ErrorAs(t, err, &exit, "%s", out)
	assert.NotZero(t, exit.ExitCode())
	assert.Contains(t, string(out), "-load-max-bytes needs -admin-token or "+adminTokenEnv)
}
