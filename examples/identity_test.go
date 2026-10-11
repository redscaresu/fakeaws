package examples_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// identityExample is the example's directory under examples/, and
	// its name in the shard list.
	identityExample = "identity/allowed_account_ids"
	// tofuStepTimeout bounds each tofu run in this file.
	tofuStepTimeout = 5 * time.Minute
)

// TestIdentityAllowedAccountIDs runs identity/allowed_account_ids against
// its own fakeaws: started with -account, every step passes and plan is
// clean; started without, the provider refuses the default account.
func TestIdentityAllowedAccountIDs(t *testing.T) {
	requireE2EGate(t)
	requireTofu(t)
	if !inShard(t, identityExample) {
		t.Skipf("%s runs in another %s shard", identityExample, shardEnvVar)
	}
	t.Parallel()
	bin := buildFakeAWS(t)

	dir := copyExample(t, "identity", "allowed_account_ids")
	env := identityEnv(t, startFakeAWS(t, bin, "-account", allowedAccount(t, dir)))
	for _, args := range [][]string{
		{"init"},
		{"apply", "-auto-approve"},
		{"plan", "-detailed-exitcode"},
		{"destroy", "-auto-approve"},
	} {
		out, err := runTofu(t, dir, env(args[0]), args...)
		require.NoError(t, err, "tofu %s:\n%s", args[0], out)
	}

	dir = copyExample(t, "identity", "allowed_account_ids")
	env = identityEnv(t, startFakeAWS(t, bin))
	out, err := runTofu(t, dir, env("init"), "init")
	require.NoError(t, err, "tofu init:\n%s", out)
	out, err = runTofu(t, dir, env("apply"), "apply", "-auto-approve")
	require.Error(t, err, "apply succeeded against the default account:\n%s", out)
	assert.Contains(t, out, "AWS account ID not allowed")
}

// allowedAccountLine matches the provider's one allowed account.
var allowedAccountLine = regexp.MustCompile(`(?m)^\s*allowed_account_ids\s*=\s*\["(\d{12})"\]`)

// allowedAccount reads the account the example in dir allows.
func allowedAccount(t *testing.T, dir string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(dir, "main.tf"))
	require.NoError(t, err)
	m := allowedAccountLine.FindSubmatch(body)
	require.NotNil(t, m, "no allowed_account_ids in %s/main.tf", dir)
	return string(m[1])
}

// buildFakeAWS builds cmd/fakeaws into a temp dir.
func buildFakeAWS(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "fakeaws")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/fakeaws")
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "go build:\n%s", out)
	return bin
}

// startFakeAWS starts bin on a free loopback port with a temp db and
// args, waits for /healthz, and returns its base URL. t.Cleanup kills it.
func startFakeAWS(t *testing.T, bin string, args ...string) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())

	var logs strings.Builder
	cmd := exec.Command(bin, append([]string{
		"-bind", "127.0.0.1",
		"-port", strconv.Itoa(port),
		"-db", filepath.Join(t.TempDir(), "fakeaws.db"),
	}, args...)...)
	cmd.Stdout, cmd.Stderr = &logs, &logs
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
	})

	url := fmt.Sprintf("http://127.0.0.1:%d", port)
	client := http.Client{Timeout: time.Second}
	require.Eventually(t, func() bool {
		resp, err := client.Get(url + "/healthz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 10*time.Second, 100*time.Millisecond, "fakeaws %v did not answer /healthz:\n%s", args, &logs)
	return url
}

// identityEnv returns smokeEnv with every endpoint moved from the
// shared :8082 fakeaws to url.
func identityEnv(t *testing.T, url string) func(subcommand string) []string {
	return func(subcommand string) []string {
		env := smokeEnv(t, subcommand)
		for i, kv := range env {
			if strings.HasPrefix(kv, "AWS_ENDPOINT_URL_") {
				env[i] = strings.Replace(kv, defaultFakeAWSURL, url, 1)
			}
		}
		return env
	}
}

// runTofu runs one tofu subcommand in dir with env. On timeout it kills
// tofu's whole process group, provider plugins included.
func runTofu(t *testing.T, dir string, env []string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), tofuStepTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "tofu", append(args, "-input=false", "-no-color")...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 10 * time.Second
	out, err := cmd.CombinedOutput()
	return string(out), err
}
