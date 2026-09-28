package examples_test

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redscaresu/fakeaws/handlers/awsproto"
)

// tfState is the part of `tofu show -json` this test reads.
type tfState struct {
	Values struct {
		RootModule struct {
			Resources []struct {
				Address string         `json:"address"`
				Type    string         `json:"type"`
				Values  map[string]any `json:"values"`
			} `json:"resources"`
		} `json:"root_module"`
	} `json:"values"`
}

// TestWebStepOneState applies working/web_step_one and checks what
// state carries: the instance's public IP, and fakeaws's account in
// every arn and owner_id.
func TestWebStepOneState(t *testing.T) {
	requireE2EGate(t)
	requireTofu(t)
	resetFakeAWS(t)
	dir := filepath.Join(repoRoot(t), "examples", "working", "web_step_one")
	require.Nil(t, runSteps(t, dir, step{"init", []string{"init"}}))
	t.Cleanup(func() {
		assert.Nil(t, runSteps(t, dir, step{"destroy", []string{"destroy", "-auto-approve"}}))
	})
	require.Nil(t, runSteps(t, dir, step{"apply", []string{"apply", "-auto-approve"}}))

	cmd := exec.Command("tofu", "show", "-json", "-no-color")
	cmd.Dir = dir
	cmd.Env = smokeEnv(t, "show")
	out, err := cmd.Output()
	require.NoError(t, err)
	var state tfState
	require.NoError(t, json.Unmarshal(out, &state))

	checked := map[string]int{}
	for _, r := range state.Values.RootModule.Resources {
		if r.Type == "aws_instance" {
			checked["aws_instance"]++
			assert.NotEmpty(t, r.Values["public_ip"], "%s public_ip", r.Address)
		}
		for _, key := range []string{"arn", "owner_id"} {
			v, ok := r.Values[key]
			if !ok {
				continue
			}
			checked[key]++
			s, _ := v.(string)
			assert.Contains(t, s, awsproto.FakeAccountID, "%s %s", r.Address, key)
		}
	}
	// Without these the loop above could pass having checked nothing.
	assert.Equal(t, 1, checked["aws_instance"], "aws_instance count")
	assert.Positive(t, checked["arn"], "no arn in state")
	assert.Positive(t, checked["owner_id"], "no owner_id in state")
}
