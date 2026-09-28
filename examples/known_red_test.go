package examples_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// knownRedEntry records how a known-red example fails today.
type knownRedEntry struct {
	stage    string // runSteps stage name: init, apply, plan, destroy, "apply v1", ...
	fragment string // substring the failing stage's output must contain
	owner    string // story that turns it green, or "none: follow-up"
}

// knownRed lists the examples the provider-smoke job shows red, keyed
// "<tree>/<dir>". An entry that starts passing, or fails any other
// way, fails the harness: fix the example or update the entry.
var knownRed = map[string]knownRedEntry{
	// main.tf separates arguments with ';', which HCL rejects.
	"working/eks_cluster": {stage: "init", fragment: "Invalid character", owner: "none: follow-up"},
	"working/s3_bucket":   {stage: "apply", fragment: "GetBucketPolicy", owner: "none: follow-up"},

	"misconfigured/eks_node_group_subnet_outside_cluster": {stage: "init", fragment: "Invalid character", owner: "none: follow-up"},
	// Route53 answers 409 UnknownError, not InvalidChangeBatch.
	"misconfigured/route53_apex_cname": {stage: "apply", fragment: "api error UnknownError", owner: "none: follow-up"},

	"updates/update_iam_role_description": {stage: "apply v2", fragment: "UpdateRoleDescription", owner: "none: follow-up"},
	"updates/update_rds_parameter_group":  {stage: "destroy", fragment: "DeleteDBParameterGroup", owner: "none: follow-up"},
	"updates/update_s3_bucket_versioning": {stage: "apply v1", fragment: "GetBucketPolicy", owner: "none: follow-up"},
	"updates/update_security_group_rules": {stage: "plan v1", fragment: "DescribeSecurityGroupRules", owner: "none: follow-up"},
	// SetQueueAttributes is a no-op, so the provider's 3m wait times out.
	"updates/update_sqs_queue_visibility": {stage: "apply v2", fragment: "attributes update: timeout while waiting", owner: "none: follow-up"},
}

// checkKnownRed judges one example's outcome (failure == nil means it
// passed) against known. nil means the outcome is acceptable.
func checkKnownRed(known map[string]knownRedEntry, name string, failure *stageErr) error {
	entry, isKnown := known[name]
	switch {
	case failure == nil && isKnown:
		return fmt.Errorf("%s passes now: remove it from knownRed", name)
	case failure == nil:
		return nil
	case !isKnown:
		return failure
	case failure.stage != entry.stage:
		return fmt.Errorf("%s is known red at %s but failed at another stage: %w", name, entry.stage, failure)
	case !strings.Contains(failure.out, entry.fragment):
		return fmt.Errorf("%s failed at %s without the knownRed fragment %q: %w", name, entry.stage, entry.fragment, failure)
	}
	return nil
}

func TestCheckKnownRed(t *testing.T) {
	known := map[string]knownRedEntry{
		"working/red": {stage: "plan", fragment: "user_data", owner: "none: follow-up"},
	}
	planDiff := &stageErr{stage: "plan", out: "~ user_data"}

	cases := []struct {
		name    string
		example string
		failure *stageErr
		wantErr string
	}{
		{"pass+unknown is ok", "working/green", nil, ""},
		{"pass+known errors", "working/red", nil, "remove it from knownRed"},
		{"fail at recorded stage with fragment is ok", "working/red", planDiff, ""},
		{"fail at another stage errors", "working/red", &stageErr{stage: "apply", out: "user_data"}, "failed at another stage"},
		{"fail without fragment errors", "working/red", &stageErr{stage: "plan", out: "~ tags"}, "without the knownRed fragment"},
		{"fail+unknown errors", "working/green", planDiff, "tofu plan failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkKnownRed(known, tc.example, tc.failure)
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tc.wantErr)
		})
	}
}

// TestKnownRedEntriesAreValid keeps knownRed from pointing at examples
// that no longer exist or carrying an entry nothing could match.
func TestKnownRedEntriesAreValid(t *testing.T) {
	root := repoRoot(t)
	for name, entry := range knownRed {
		_, err := os.Stat(filepath.Join(root, "examples", name))
		require.NoError(t, err, "knownRed entry %s has no example directory", name)
		assert.NotEmpty(t, entry.stage, "%s: stage", name)
		assert.NotEmpty(t, entry.fragment, "%s: fragment", name)
		assert.NotEmpty(t, entry.owner, "%s: owner (a story, or 'none: follow-up')", name)
	}
}
