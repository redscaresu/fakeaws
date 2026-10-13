package examples_test

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// filterRefusedHCL reads a VPC by dhcp-options-id, a filter AWS
// accepts and fakeaws does not model. Credentials and the endpoints
// come from the env, so it reaches only the fakeaws the test starts.
const filterRefusedHCL = `
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.100.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

data "aws_vpc" "by_dhcp_options" {
  filter {
    name   = "dhcp-options-id"
    values = ["dopt-0123456789abcdef0"]
  }
}
`

// requestLog is the part of GET /mock/requests this test reads.
type requestLog struct {
	Requests []struct {
		Status         int               `json:"status"`
		Classification string            `json:"classification"`
		Action         string            `json:"action"`
		Params         map[string]string `json:"params"`
	} `json:"requests"`
}

// TestFilterRefused proves a refused filter end to end: the real
// provider's plan fails naming the filter and fakeaws's refusal, and
// the request log holds that DescribeVpcs as a 501 filter-refused.
func TestFilterRefused(t *testing.T) {
	requireE2EGate(t)
	requireTofu(t)
	requireShard(t)
	t.Parallel()
	fakeaws := startFakeAWS(t, buildFakeAWS(t), "-record-requests")
	env := identityEnv(t, fakeaws.url)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), []byte(filterRefusedHCL), 0o644))

	out, err := runTofu(t, dir, env("init"), "init")
	require.NoError(t, err, "tofu init:\n%s", out)
	out, err = runTofu(t, dir, env("plan"), "plan")
	var exit *exec.ExitError
	require.ErrorAs(t, err, &exit, "tofu plan:\n%s", out)
	assert.Equal(t, 1, exit.ExitCode(), "tofu plan exit:\n%s", out)
	for _, want := range []string{"dhcp-options-id", "NotImplemented", "not modelled by fakeaws"} {
		assert.Contains(t, out, want)
	}
	t.Logf("tofu plan:\n%s", out)

	req, err := http.NewRequest(http.MethodGet, fakeaws.url+"/mock/requests", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+fakeaws.token)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var log requestLog
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&log))

	refused := 0
	for _, r := range log.Requests {
		if r.Action != "DescribeVpcs" || r.Params["Filter.1.Name"] != "dhcp-options-id" {
			continue
		}
		refused++
		assert.Equal(t, http.StatusNotImplemented, r.Status)
		assert.Equal(t, "filter-refused", r.Classification)
	}
	assert.Equal(t, 1, refused, "DescribeVpcs by dhcp-options-id in the request log: %+v", log.Requests)
}
