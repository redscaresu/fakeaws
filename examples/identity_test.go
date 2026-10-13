package examples_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
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
	env := identityEnv(t, startFakeAWS(t, bin, "-account", allowedAccount(t, dir)).url)
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
	env = identityEnv(t, startFakeAWS(t, bin).url)
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

// fakeAWS is a fakeaws startFakeAWS started: its base URL and the admin
// token it was started with.
type fakeAWS struct{ url, token string }

// startAttempts is how many free ports startFakeAWS tries: another
// process can bind the one it picked before fakeaws does.
const startAttempts = 3

// errExitedFirst is launchFakeAWS's failure when fakeaws exits before
// it answers, as one that lost its port does.
var errExitedFirst = errors.New("exited before it answered")

// startFakeAWS starts bin on a free loopback port (launchFakeAWS) and
// returns it once it answers, trying a new port when fakeaws exits
// first, up to startAttempts ports. t.Cleanup kills it.
func startFakeAWS(t *testing.T, bin string, args ...string) fakeAWS {
	t.Helper()
	var f fakeAWS
	var err error
	for range startAttempts {
		l, lerr := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, lerr)
		port := l.Addr().(*net.TCPAddr).Port
		require.NoError(t, l.Close())
		if f, err = launchFakeAWS(t, bin, port, args...); !errors.Is(err, errExitedFirst) {
			break
		}
	}
	require.NoError(t, err, "after %d ports", startAttempts)
	return f
}

// launchFakeAWS starts bin on port with a temp db, a random admin token
// of its own and args, and waits until GET /mock/state answers 200 to
// that token: another fakeaws holding port answers 401, so it is never
// taken for this one. It fails with errExitedFirst when the process
// exits first, as one that lost port does, or when it answers nothing
// within 10s. t.Cleanup kills its process group unless it has exited,
// when its pid may already be another's.
func launchFakeAWS(t *testing.T, bin string, port int, args ...string) (fakeAWS, error) {
	t.Helper()
	token := make([]byte, 16)
	_, _ = rand.Read(token) // never fails (crypto/rand)
	f := fakeAWS{url: fmt.Sprintf("http://127.0.0.1:%d", port), token: hex.EncodeToString(token)}

	var logs strings.Builder
	cmd := exec.Command(bin, append([]string{
		"-bind", "127.0.0.1",
		"-port", strconv.Itoa(port),
		"-db", filepath.Join(t.TempDir(), "fakeaws.db"),
		"-admin-token", f.token,
	}, args...)...)
	cmd.Stdout, cmd.Stderr = &logs, &logs
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return fakeAWS{}, err
	}
	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(exited)
	}()
	kill := func() {
		select {
		case <-exited: // reaped: its pid may be another process group's now
		default:
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-exited
		}
	}
	t.Cleanup(kill)

	client := http.Client{Timeout: time.Second}
	deadline := time.After(10 * time.Second)
	for tick := time.Tick(100 * time.Millisecond); ; {
		select {
		case <-exited:
			return fakeAWS{}, fmt.Errorf("fakeaws %v %w:\n%s", args, errExitedFirst, logs.String())
		case <-deadline:
			kill()
			return fakeAWS{}, fmt.Errorf("fakeaws %v did not answer within 10s:\n%s", args, logs.String())
		case <-tick:
			if f.answers(&client) {
				return f, nil
			}
		}
	}
}

// answers reports whether GET /mock/state answers f's token 200.
func (f fakeAWS) answers(client *http.Client) bool {
	req, err := http.NewRequest(http.MethodGet, f.url+"/mock/state", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+f.token)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// TestStartFakeAWSRefusesATakenPort: a fakeaws started on a port another
// already holds loses the bind and exits, and launchFakeAWS names that
// rather than returning the other one.
func TestStartFakeAWSRefusesATakenPort(t *testing.T) {
	requireE2EGate(t)
	requireShard(t)
	t.Parallel()
	bin := buildFakeAWS(t)
	first := startFakeAWS(t, bin)
	u, err := url.Parse(first.url)
	require.NoError(t, err)
	port, err := strconv.Atoi(u.Port())
	require.NoError(t, err)
	_, err = launchFakeAWS(t, bin, port)
	require.ErrorIs(t, err, errExitedFirst)
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
