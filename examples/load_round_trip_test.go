package examples_test

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redscaresu/fakeaws/handlers"
	"github.com/redscaresu/fakeaws/handlers/awsproto"
	"github.com/redscaresu/fakeaws/internal/audit"
)

const (
	// loadMaxBytes is fakeaws B's -load-max-bytes.
	loadMaxBytes = 64 << 20
	// recordTimeout bounds each request the recorder and the load send.
	recordTimeout = 30 * time.Second
)

// TestLoadRoundTrip proves load, not real shape. Each working example
// whose every type is a loadable coverage_matrix.yaml row
// (CoverageMatrix.RoundTripExamples) is applied against its own fakeaws
// A, refreshed from A, recorded (recordRead), loaded into a fresh fakeaws
// B, and planned with A's state against B, plain and refresh-only, each
// of which must exit 0; then destroyed on A.
func TestLoadRoundTrip(t *testing.T) {
	requireE2EGate(t)
	requireTofu(t)
	requireShard(t)
	t.Parallel()
	root := repoRoot(t)
	matrix, err := audit.LoadCoverageMatrix(filepath.Join(root, "coverage_matrix.yaml"))
	require.NoError(t, err)
	examples, err := matrix.RoundTripExamples(root)
	require.NoError(t, err)
	names := slices.Sorted(maps.Keys(examples))
	t.Logf("round-tripping %d working examples: %s", len(names), strings.Join(names, ", "))
	require.Subset(t, names, []string{"vpc_network", "web_step_one"})

	bin := buildFakeAWS(t)
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			roundTrip(t, bin, name)
		})
	}
}

// roundTrip applies working/<name> on a fakeaws A, loads A's recorded
// read into a fresh fakeaws B, plans A's state against B, plain and
// refresh-only, and destroys on A.
func roundTrip(t *testing.T, bin, name string) {
	dir := t.TempDir()
	tofu := func(fakeaws string, args ...string) {
		t.Helper()
		pointExampleAt(t, dir, name, fakeaws)
		out, err := runTofu(t, dir, identityEnv(t, fakeaws)(args[0]), args...)
		require.NoError(t, err, "tofu %s against %s:\n%s", args[0], fakeaws, out)
	}
	a := startFakeAWS(t, bin).url
	tofu(a, "init")
	tofu(a, "apply", "-auto-approve")
	// The provider's read of an applied object differs from what apply
	// stored (tags null → {}, a route table's routes, a role's inline
	// policies), so state first takes A's own read: B is then compared
	// with what A answers, not with what apply wrote.
	tofu(a, "apply", "-refresh-only", "-auto-approve")
	read := recordRead(t, a)

	b := startFakeAWS(t, bin, "-load-max-bytes", strconv.Itoa(loadMaxBytes))
	loadRead(t, b, read)
	tofu(b.url, "plan", "-detailed-exitcode")
	// A plan exits 0 on drift it plans no action for; refresh-only
	// exits 2 on any attribute B answers otherwise than A did.
	tofu(b.url, "plan", "-refresh-only", "-detailed-exitcode")
	tofu(a, "destroy", "-auto-approve")
}

// pointExampleAt writes working/<name>'s main.tf into dir with every
// endpoint the example hardcodes moved from the shared :8082 fakeaws to
// fakeaws.
func pointExampleAt(t *testing.T, dir, name, fakeaws string) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(repoRoot(t), "examples", "working", name, "main.tf"))
	require.NoError(t, err)
	body = bytes.ReplaceAll(body, []byte(defaultFakeAWSURL), []byte(fakeaws))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.tf"), body, 0o644))
}

// loadRead POSTs read to fakeaws's /mock/load, which must answer 200; a
// refusal names each row's type and path.
func loadRead(t *testing.T, fakeaws fakeAWS, read *recordedRead) {
	t.Helper()
	body, err := json.Marshal(read)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, fakeaws.url+"/mock/load", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+fakeaws.token)
	resp, err := (&http.Client{Timeout: recordTimeout}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	answer, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "POST /mock/load:\n%s", answer)
	t.Logf("loaded: %s", answer)
}

// recordedRead is ADR-0041's recorded read.
type recordedRead struct {
	Account    string             `json:"account"`
	Region     string             `json:"region"`
	Timestamp  string             `json:"timestamp"`
	DurationMS int64              `json:"duration_ms"`
	Calls      int                `json:"calls"`
	Exchanges  []recordedExchange `json:"exchanges"`
}

// recordedExchange is ADR-0041's exchange: a query read-set entry, the
// wire status and the raw body.
type recordedExchange struct {
	Service  string            `json:"service"`
	Protocol string            `json:"protocol"`
	Action   string            `json:"action"`
	Params   map[string]string `json:"params"`
	Status   int               `json:"status"`
	Body     string            `json:"body"`
}

// recordedLists are the reads recordRead records unfiltered: on a
// fakeaws of one example's apply, every row of every loadable EC2 type.
var recordedLists = []string{
	"DescribeAvailabilityZones", "DescribeImages", "DescribeVpcs", "DescribeSubnets",
	"DescribeInternetGateways", "DescribeRouteTables", "DescribeSecurityGroups",
	"DescribeSecurityGroupRules", "DescribeNetworkInterfaces", "DescribeAddresses",
	"DescribeKeyPairs", "DescribeVolumes", "DescribeInstances",
}

// recordedRoleReads are the IAM reads recordRead records per role, by
// RoleName; GetRolePolicy it records per ListRolePolicies name.
var recordedRoleReads = []string{"GetRole", "ListRolePolicies", "ListAttachedRolePolicies", "ListInstanceProfilesForRole"}

// recordRead records fakeaws's rows as the reader would read them, as
// fakeaws's account in smokeEnv's region: recordedLists, then each
// VPC's and instance's handlers.LoadAttributeReads (in action order), then each role's
// recordedRoleReads and inline policies. The ListRoles that finds the
// roles is sent and counted in calls, never recorded.
func recordRead(t *testing.T, fakeaws string) *recordedRead {
	t.Helper()
	region, _ := envValue(smokeEnv(t, "apply"), "AWS_REGION")
	r := &recorder{t: t, fakeaws: fakeaws, client: &http.Client{Timeout: recordTimeout},
		read: recordedRead{Account: awsproto.FakeAccountID, Region: region, Exchanges: []recordedExchange{}}}
	start := time.Now()
	r.read.Timestamp = start.UTC().Format(time.RFC3339)
	bodies := map[string]string{}
	for _, action := range recordedLists {
		bodies[action] = r.send("ec2", action, nil, true)
	}
	var vpcs struct {
		IDs []string `xml:"vpcSet>item>vpcId"`
	}
	var instances struct {
		IDs []string `xml:"reservationSet>item>instancesSet>item>instanceId"`
	}
	r.decode(bodies["DescribeVpcs"], &vpcs)
	r.decode(bodies["DescribeInstances"], &instances)
	// Each attribute read's id param and the ids recorded for it.
	idSources := map[string]struct {
		param string
		ids   []string
	}{
		"DescribeInstanceAttribute": {"InstanceId", instances.IDs},
		"DescribeVpcAttribute":      {"VpcId", vpcs.IDs},
	}
	attributes := handlers.LoadAttributeReads()
	for _, action := range slices.Sorted(maps.Keys(attributes)) {
		src, ok := idSources[action]
		require.True(t, ok, "handlers.LoadAttributeReads names %s, which the recorder has no id source for", action)
		for _, id := range src.ids {
			for _, attr := range attributes[action] {
				r.send("ec2", action, map[string]string{src.param: id, "Attribute": attr}, true)
			}
		}
	}

	var roles struct {
		Names []string `xml:"ListRolesResult>Roles>member>RoleName"`
	}
	r.decode(r.send("iam", "ListRoles", nil, false), &roles)
	for _, role := range roles.Names {
		params := map[string]string{"RoleName": role}
		for _, action := range recordedRoleReads {
			body := r.send("iam", action, params, true)
			if action != "ListRolePolicies" {
				continue
			}
			var policies struct {
				Names []string `xml:"ListRolePoliciesResult>PolicyNames>member"`
			}
			r.decode(body, &policies)
			for _, policy := range policies.Names {
				r.send("iam", "GetRolePolicy", map[string]string{"RoleName": role, "PolicyName": policy}, true)
			}
		}
	}
	r.read.DurationMS = time.Since(start).Milliseconds()
	return &r.read
}

// recorder sends query reads to one fakeaws and records them.
type recorder struct {
	t       *testing.T
	fakeaws string
	client  *http.Client
	read    recordedRead
}

// send sends action to service with params, which must answer 200, and
// returns the body; record appends the exchange to the read.
func (r *recorder) send(service, action string, params map[string]string, record bool) string {
	r.t.Helper()
	form := url.Values{"Action": {action}} // fakeaws reads no Version, and params never hold one
	for k, v := range params {
		form.Set(k, v)
	}
	endpoint := strings.Replace(endpointEnv[service].url, defaultFakeAWSURL, r.fakeaws, 1)
	resp, err := r.client.PostForm(endpoint, form)
	require.NoError(r.t, err, "%s %s", service, action)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(r.t, err, "%s %s", service, action)
	r.read.Calls++
	require.Equal(r.t, http.StatusOK, resp.StatusCode, "%s %s %v:\n%s", service, action, params, body)
	if record {
		if params == nil {
			params = map[string]string{}
		}
		r.read.Exchanges = append(r.read.Exchanges, recordedExchange{
			Service: service, Protocol: "query", Action: action, Params: params, Status: resp.StatusCode, Body: string(body),
		})
	}
	return string(body)
}

func (r *recorder) decode(body string, v any) {
	r.t.Helper()
	require.NoError(r.t, xml.Unmarshal([]byte(body), v))
}

// TestRecordedReadMatchesADR0041 decodes ADR-0041's recorded-read
// example strictly into recordedRead and marshals it back unchanged: the
// envelope's keys are exactly account, region, timestamp, duration_ms,
// calls and exchanges, and an exchange's are the ADR's.
func TestRecordedReadMatchesADR0041(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join("testdata", "adr0041-recorded-read.json"))
	require.NoError(t, err)
	dec := json.NewDecoder(bytes.NewReader(golden))
	dec.DisallowUnknownFields()
	var read recordedRead
	require.NoError(t, dec.Decode(&read))
	require.Len(t, read.Exchanges, 1)
	got, err := json.Marshal(read)
	require.NoError(t, err)
	assert.JSONEq(t, string(golden), string(got))
}
