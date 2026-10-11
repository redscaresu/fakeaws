package main

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
