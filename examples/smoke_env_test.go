package examples_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redscaresu/fakeaws/handlers"
)

// deadProxy is a port nothing listens on: any request that is not for
// fakeaws dies here instead of reaching AWS.
const deadProxy = "http://127.0.0.1:9"

// endpointEnv maps a service id (handlers.LandedServices) to its
// AWS_ENDPOINT_URL_<SVC> suffix and the fakeaws URL the examples'
// endpoints blocks use.
var endpointEnv = map[string]struct{ suffix, url string }{
	"dynamodb":       {"DYNAMODB", defaultFakeAWSURL + "/dynamodb/region/us-east-1"},
	"ec2":            {"EC2", defaultFakeAWSURL + "/ec2/region/us-east-1"},
	"eks":            {"EKS", defaultFakeAWSURL + "/eks/region/us-east-1"},
	"iam":            {"IAM", defaultFakeAWSURL + "/iam"},
	"kms":            {"KMS", defaultFakeAWSURL + "/kms/region/us-east-1"},
	"rds":            {"RDS", defaultFakeAWSURL + "/rds/region/us-east-1"},
	"route53":        {"ROUTE_53", defaultFakeAWSURL + "/route53"},
	"s3":             {"S3", defaultFakeAWSURL + "/s3"},
	"secretsmanager": {"SECRETS_MANAGER", defaultFakeAWSURL + "/secretsmanager/region/us-east-1"},
	"sqs":            {"SQS", defaultFakeAWSURL + "/sqs/region/us-east-1"},
	"sts":            {"STS", defaultFakeAWSURL + "/sts"},
	"ssm":            {"SSM", defaultFakeAWSURL + "/ssm/region/us-east-1"},
}

// smokeEnv is the environment for one tofu subcommand, and it fails
// closed: every inherited AWS_* var is dropped, the keys are fake,
// IMDS and the shared config files are unreachable, and every service
// endpoint is fakeaws. Every subcommand but init (which must reach
// registry.opentofu.org) sends all other traffic to deadProxy.
func smokeEnv(t *testing.T, subcommand string) []string {
	t.Helper()
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "AWS_") {
			env = append(env, kv)
		}
	}
	missing := t.TempDir()
	env = append(env,
		"AWS_ACCESS_KEY_ID=fake",
		"AWS_SECRET_ACCESS_KEY=fake",
		"AWS_REGION=us-east-1",
		"AWS_EC2_METADATA_DISABLED=true",
		"AWS_CONFIG_FILE="+filepath.Join(missing, "config"),
		"AWS_SHARED_CREDENTIALS_FILE="+filepath.Join(missing, "credentials"),
	)
	for _, e := range endpointEnv {
		env = append(env, "AWS_ENDPOINT_URL_"+e.suffix+"="+e.url)
	}
	if subcommand != "init" {
		env = append(env, "HTTPS_PROXY="+deadProxy, "HTTP_PROXY="+deadProxy, "NO_PROXY=127.0.0.1,localhost")
	}
	return env
}

// envValue returns the value of key in env, and whether it is set.
func envValue(env []string, key string) (string, bool) {
	for _, kv := range env {
		if k, v, _ := strings.Cut(kv, "="); k == key {
			return v, true
		}
	}
	return "", false
}

func TestSmokeEnvScrubsAWS(t *testing.T) {
	leaks := map[string]string{
		"AWS_PROFILE":           "leak-profile",
		"AWS_ACCESS_KEY_ID":     "leak-access-key",
		"AWS_SESSION_TOKEN":     "leak-session-token",
		"AWS_ENDPOINT_URL":      "http://leak-endpoint.example",
		"AWS_SECRET_ACCESS_KEY": "leak-secret-key",
	}
	for k, v := range leaks {
		t.Setenv(k, v)
	}

	env := smokeEnv(t, "apply")
	for _, kv := range env {
		for k, v := range leaks {
			assert.NotContains(t, kv, v, "smokeEnv leaks %s", k)
		}
	}
	for _, key := range []string{"AWS_PROFILE", "AWS_SESSION_TOKEN", "AWS_ENDPOINT_URL"} {
		_, set := envValue(env, key)
		assert.False(t, set, "%s is set", key)
	}
	for key, want := range map[string]string{
		"AWS_ACCESS_KEY_ID":         "fake",
		"AWS_SECRET_ACCESS_KEY":     "fake",
		"AWS_REGION":                "us-east-1",
		"AWS_EC2_METADATA_DISABLED": "true",
	} {
		got, _ := envValue(env, key)
		assert.Equal(t, want, got, key)
	}
	for _, key := range []string{"AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		path, set := envValue(env, key)
		require.True(t, set, "%s is not set", key)
		_, err := os.Stat(path)
		assert.ErrorIs(t, err, os.ErrNotExist, "%s=%s must not exist", key, path)
	}

	for _, sub := range []string{"apply", "plan", "destroy"} {
		env := smokeEnv(t, sub)
		for _, key := range []string{"HTTPS_PROXY", "HTTP_PROXY"} {
			got, _ := envValue(env, key)
			assert.Equal(t, deadProxy, got, "%s %s", sub, key)
		}
		got, _ := envValue(env, "NO_PROXY")
		assert.Equal(t, "127.0.0.1,localhost", got, "%s NO_PROXY", sub)
	}
	for _, kv := range smokeEnv(t, "init") {
		assert.NotContains(t, kv, deadProxy, "init must reach the registry")
	}
}

// endpointLine matches an endpoints-block entry in an example's main.tf.
var endpointLine = regexp.MustCompile(`(?m)^\s*(\w+)\s*=\s*"(http://127\.0\.0\.1:8082/[^"]*)"`)

func TestSmokeEnvEndpointsCoverLandedServices(t *testing.T) {
	env := smokeEnv(t, "apply")
	for _, id := range handlers.LandedServices {
		e, ok := endpointEnv[id]
		if !assert.True(t, ok, "service %q has no AWS_ENDPOINT_URL_<SVC> in smokeEnv", id) {
			continue
		}
		got, _ := envValue(env, "AWS_ENDPOINT_URL_"+e.suffix)
		assert.Equal(t, e.url, got, id)
	}

	// smokeEnv must point each service where the examples do.
	files, err := filepath.Glob(filepath.Join(repoRoot(t), "examples", "*", "*", "main.tf"))
	require.NoError(t, err)
	for _, f := range files {
		body, err := os.ReadFile(f)
		require.NoError(t, err)
		for _, m := range endpointLine.FindAllStringSubmatch(string(body), -1) {
			assert.Equal(t, m[2], endpointEnv[m[1]].url, "%s: endpoint %s", f, m[1])
		}
	}
}

// TestSmokeEnvFailsClosed proves the env, not the example, keeps tofu off
// real AWS: without its EC2 endpoint var, env_endpoints must die on the
// dead proxy, and fast.
func TestSmokeEnvFailsClosed(t *testing.T) {
	requireE2EGate(t)
	requireTofu(t)
	dir := filepath.Join(repoRoot(t), "examples", "working", "env_endpoints")
	require.Nil(t, runSteps(t, dir, step{"init", []string{"init"}}))

	env := slices.DeleteFunc(smokeEnv(t, "apply"), func(kv string) bool {
		return strings.HasPrefix(kv, "AWS_ENDPOINT_URL_EC2=")
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "tofu", "apply", "-auto-approve", "-input=false", "-no-color")
	cmd.Dir = dir
	cmd.Env = append(env, "AWS_MAX_ATTEMPTS=1")
	out, err := cmd.CombinedOutput()

	require.NoError(t, ctx.Err(), "apply did not fail within 2m:\n%s", out)
	require.Error(t, err, "apply succeeded without AWS_ENDPOINT_URL_EC2:\n%s", out)
	assert.Contains(t, string(out), "127.0.0.1:9")
}
