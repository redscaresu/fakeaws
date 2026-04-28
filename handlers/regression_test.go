package handlers_test

// Package handlers regression-test seed. Per concepts.md § "Standing
// patterns to seed regression_test.go on day one" — 16 named tests,
// one per pattern. Each test has a narrative comment header
// explaining the bug it prevents from regressing.
//
// Tests for services not yet in LandedServices call
// requireHandlerImplemented (in handlers package, exported via
// the package-handlers helper file) which t.Skipf's with a
// structured TODO marker. As services land, their entry in
// LandedServices flips, the test stops skipping, and the assertion
// must hold against the real handler — failure red is the contract.
//
// Two CI audits enforce no silent green-lights:
//   - TestRegressionSeedAuditManifestMatchesHandlers (handler↔manifest
//     consistency)
//   - TestRegressionSeedAuditNoVacuousPasses (no requireHandlerImplemented
//     coexists with assert./require. in the same func body)
//
// Both audits ship in handlers/regression_audit_test.go (S43-T10).

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/redscaresu/fakeaws/handlers"
)

// requireHandlerImplemented re-exports the package-private helper so
// the regression suite (which lives in handlers_test) can use it.
// The helper itself is in handlers/regression_manifest.go.
func requireHandlerImplemented(t *testing.T, id, slice, pattern string) {
	t.Helper()
	handlers.RequireHandlerImplementedForTest(t, id, slice, pattern)
}

// 1. Cross-account FK rejection (resolveSameAccountName).
//
// Pattern: a cross-resource reference whose embedded account-id is a
// different account must reject with 404 even if the trailing name
// happens to exist locally. Mirror of fakegcp's pass-27 finding.
//
// Lands when: any service that accepts ARN refs to other resources
// (IAM AttachRolePolicy → policy ARN, EC2 instance → security-group
// ARN, etc.). IAM is in scope today.
func TestRegressionCrossAccountFKRejection(t *testing.T) {
	srv := newTestServerForRegression(t)
	// AttachRolePolicy with a foreign-account policy ARN must 404.
	createRole(t, srv, "r")
	resp, _ := iamPost(t, srv, "AttachRolePolicy", url.Values{
		"RoleName":  {"r"},
		"PolicyArn": {"arn:aws:iam::999999999999:policy/foreign"},
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("cross-account ARN must 404, got %d", resp.StatusCode)
	}
}

// 2. Wrong-collection FK rejection (same-account paths).
//
// Pattern: an ARN whose resource-type segment doesn't match the
// expected collection must reject. E.g., AttachRolePolicy with a
// `:role/` ARN where the API expects `:policy/` must 404. Closes the
// trailing-name-collision escape hatch (fakegcp pass-28).
func TestRegressionWrongCollectionFKRejection(t *testing.T) {
	srv := newTestServerForRegression(t)
	createRole(t, srv, "r")
	createPolicy(t, srv, "p")
	// AttachRolePolicy with a role ARN (wrong collection — should be
	// policy) must 404, not silently match by trailing name.
	resp, _ := iamPost(t, srv, "AttachRolePolicy", url.Values{
		"RoleName":  {"r"},
		"PolicyArn": {"arn:aws:iam::000000000000:role/p"},
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("wrong-collection ARN must 404, got %d", resp.StatusCode)
	}
}

// 3. Relative-path wrong-collection rejection.
//
// Pattern: same as #2 but for non-ARN refs (relative paths like
// "regions/us-east-1/policies/foo"). The fix landed in fakegcp pass-29.
// AWS rarely uses relative paths in HCL, but if a future scenario
// generates them, the rejection must hold uniformly.
// TestRegressionRelativePathWrongCollectionRejection — Codex pass 3
// BLOCKING #1 fix. Lit up via EC2: the AWS provider sometimes
// generates a security-group ARN-shaped reference where a bare id
// is expected (or vice versa). Mismatched-shape refs must reject
// rather than silently match by trailing name.
func TestRegressionRelativePathWrongCollectionRejection(t *testing.T) {
	srv := newTestServerForRegression(t)
	const region = "us-east-1"
	// Setup VPC + subnet + SG.
	_, body := ec2PostRegression(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
	vpcID := xmlExtract(body, "vpcId")
	_, body = ec2PostRegression(t, srv, region, "CreateSubnet", url.Values{
		"VpcId": {vpcID}, "CidrBlock": {"10.0.1.0/24"},
	})
	subnetID := xmlExtract(body, "subnetId")
	_, body = ec2PostRegression(t, srv, region, "CreateSecurityGroup", url.Values{
		"GroupName": {"app"}, "GroupDescription": {"app"}, "VpcId": {vpcID},
	})
	sgID := xmlExtract(body, "groupId")

	// Wrong collection: pass the SG's id where a SubnetId is expected.
	// The trailing name is a 17-char hex string (sg-xxxxxxxxxxxxxxxxx),
	// not a subnet id. Must reject — handler must validate via
	// GetSubnet, not lazy trailing-name match.
	resp, _ := ec2PostRegression(t, srv, region, "RunInstances", url.Values{
		"SubnetId":          {sgID}, // wrong-collection ref
		"ImageId":           {"ami-0abcd1234"},
		"InstanceType":      {"t3.micro"},
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("wrong-collection ref (sg id where subnet id expected): got %d, want 404", resp.StatusCode)
	}
	// Confirm the right shape DOES succeed under same prereqs.
	resp, _ = ec2PostRegression(t, srv, region, "RunInstances", url.Values{
		"SubnetId":     {subnetID},
		"ImageId":      {"ami-0abcd1234"},
		"InstanceType": {"t3.micro"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("right-shape ref control: got %d, want 200", resp.StatusCode)
	}
}

// 4. Subnet/VPC pairing on instance / cluster create.
//
// Pattern: when both a VPC ref and a subnet ref are provided, the
// subnet's stored parent VPC MUST match the requested VPC. Mismatched
// pair → 404. Mirror of fakegcp pass-27's biggest finding.
func TestRegressionSubnetVPCPairing(t *testing.T) {
	srv := newTestServerForRegression(t)
	const region = "us-east-1"
	// Two VPCs; SG in vpc-A, subnet in vpc-B.
	_, body := ec2PostRegression(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
	vpcA := xmlExtract(body, "vpcId")
	_, body = ec2PostRegression(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.1.0.0/16"}})
	vpcB := xmlExtract(body, "vpcId")
	_, body = ec2PostRegression(t, srv, region, "CreateSubnet", url.Values{
		"VpcId": {vpcB}, "CidrBlock": {"10.1.1.0/24"},
	})
	subnetB := xmlExtract(body, "subnetId")
	_, body = ec2PostRegression(t, srv, region, "CreateSecurityGroup", url.Values{
		"GroupName": {"app"}, "GroupDescription": {"app"}, "VpcId": {vpcA},
	})
	sgA := xmlExtract(body, "groupId")

	resp, body := ec2PostRegression(t, srv, region, "RunInstances", url.Values{
		"SubnetId": {subnetB}, "ImageId": {"ami-0abcd1234"},
		"InstanceType": {"t3.micro"}, "SecurityGroupId.1": {sgA},
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("subnet/SG VPC mismatch must 404, got %d body=%s", resp.StatusCode, body)
	}
}

// 5. Post-merge PATCH validation.
//
// Pattern: UpdateXxx must validate the MERGED state, not the raw
// patch. A partial PATCH that flips only `subnetwork` (not `network`)
// can otherwise smuggle in a mismatched VPC/subnet pair. Mirror of
// fakegcp pass-28.
//
// EC2 expression at v1: AuthorizeSecurityGroupIngress is the closest
// PATCH-shaped flow today. The merge-validation surface here is that
// authorising a rule against a non-existent SG must 404 (the merged
// state — pre-existing rules + new — is invalid because the SG
// doesn't exist). Without the existence gate, a 200 silently writes
// orphan rules.
func TestRegressionPostMergePATCHValidation(t *testing.T) {
	srv := newTestServerForRegression(t)
	const region = "us-east-1"
	resp, body := ec2PostRegression(t, srv, region, "AuthorizeSecurityGroupIngress", url.Values{
		"GroupId":                          {"sg-missing"},
		"IpPermissions.1.IpProtocol":       {"tcp"},
		"IpPermissions.1.FromPort":         {"443"},
		"IpPermissions.1.ToPort":           {"443"},
		"IpPermissions.1.IpRanges.1.CidrIp": {"0.0.0.0/0"},
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Authorize on missing SG must 404 (merged state invalid), got %d body=%s", resp.StatusCode, body)
	}
}

// 6. Bare-name region scoping.
//
// Pattern: a bare-name subnet ref (no embedded region) must be
// resolved against the request's zone-derived region (or cluster's
// location). Pre-fix code rejected bare names; post-fix code derives
// region from context. Mirror of fakegcp pass-30.
//
// EC2 expression: bare ids like "subnet-abc" are the AWS norm — every
// EC2 endpoint is per-region by URL path, and ids resolve against the
// caller's account regardless of the AZ a subnet belongs to. Test
// confirms an id created in region us-east-1 is reachable when the
// caller posts to /ec2/region/us-east-1 with no zone disambiguation.
func TestRegressionBareNameRegionScoping(t *testing.T) {
	srv := newTestServerForRegression(t)
	_, body := ec2PostRegression(t, srv, "us-east-1", "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
	vpcID := xmlExtract(body, "vpcId")
	_, body = ec2PostRegression(t, srv, "us-east-1", "CreateSubnet", url.Values{
		"VpcId": {vpcID}, "CidrBlock": {"10.0.1.0/24"},
	})
	subnetID := xmlExtract(body, "subnetId")

	// DescribeSubnets in same region resolves the bare id without an
	// AZ-derived disambiguator.
	_, body = ec2PostRegression(t, srv, "us-east-1", "DescribeSubnets", nil)
	if !strings.Contains(string(body), subnetID) {
		t.Errorf("bare-name subnet id must resolve in same region; body=%s", body)
	}
}

// 7. Region-vs-zone heuristic.
//
// Pattern: distinguishing region (e.g., us-east-1) from zone
// (us-east-1a) by suffix shape. Don't strip a region's trailing
// segment as if it were a zone letter. Mirror of fakegcp pass-31
// regionFromZone fix.
//
// EC2 expression: subnet AvailabilityZone is the place this surfaces.
// The handler defaults the AZ to <region>+"a" when callers omit it,
// and the stored value is region-suffixed. The bug we guard against
// is treating the URL-path region as if it were already an AZ
// (us-east-1 → strip → us-east, wrong). Asserted by checking the
// subnet AZ is exactly us-east-1a, not "us-east"+"a".
func TestRegressionRegionVsZoneHeuristic(t *testing.T) {
	srv := newTestServerForRegression(t)
	_, body := ec2PostRegression(t, srv, "us-east-1", "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
	vpcID := xmlExtract(body, "vpcId")
	_, body = ec2PostRegression(t, srv, "us-east-1", "CreateSubnet", url.Values{
		"VpcId": {vpcID}, "CidrBlock": {"10.0.1.0/24"},
	})
	if got := xmlExtract(body, "availabilityZone"); got != "us-east-1a" {
		t.Errorf("region us-east-1 must produce AZ us-east-1a (not us-easta or us-east-a); got %q", got)
	}
}

// 8. Cache-baseline lifecycle on /mock/reset.
//
// Pattern: any in-process cache (SQS visibility timeouts in S46;
// Route53 change-id cache in S47) MUST clear alongside the SQLite repo
// when /mock/reset fires. Mirror of fakegcp pass-18. Codex pass 1
// BLOCKING #3 — lit up with a real SQS assertion.
//
// SQS at v1 has no separate in-process cache (visibility timeout is
// stored in the DB, not a Go map), so the contract reduces to: after
// /mock/reset, queues + their messages MUST be gone. This is the
// minimum the cache-clearing pattern requires; richer caches (SQS
// in-flight tracker, Route53 change-id ring) extend this assertion
// when they land.
func TestRegressionCacheBaselineLifecycle(t *testing.T) {
	srv := newTestServerForRegression(t)
	const region = "us-east-1"
	sqsURL := srv.URL + "/sqs/region/" + region

	// Pre: create a queue + send a message, then snapshot via state.
	post := func(target, body string) (*http.Response, []byte) {
		req, _ := http.NewRequest(http.MethodPost, sqsURL,
			strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-amz-json-1.0")
		req.Header.Set("X-Amz-Target", target)
		resp, _ := srv.Client().Do(req)
		defer resp.Body.Close()
		out := readResponseBody(t, resp)
		return resp, out
	}

	post("AmazonSQS.CreateQueue", `{"QueueName":"jobs"}`)
	state, _ := http.Get(srv.URL + "/mock/state")
	stateBytes := readResponseBody(t, state)
	if !strings.Contains(string(stateBytes), `"jobs"`) {
		t.Fatalf("setup: queue not in pre-reset state: %s", stateBytes)
	}

	// Reset.
	resp, _ := http.Post(srv.URL+"/mock/reset", "application/json", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/mock/reset: %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Post-reset: queue is gone (cache + DB cleared together).
	state, _ = http.Get(srv.URL + "/mock/state")
	stateBytes = readResponseBody(t, state)
	if strings.Contains(string(stateBytes), `"jobs"`) {
		t.Errorf("queue should be gone after /mock/reset; state=%s", stateBytes)
	}
}

// 9. Terminal state refuses transitions.
//
// Pattern: Secrets Manager `RestoreSecret` after the recovery window
// has fully elapsed returns 409 InvalidRequestException. EC2
// terminated-instance refusal of restart. RDS deleting-instance
// refusal of modify. Mirror of fakegcp pass-18. Lit up via the
// Secrets Manager Destroyed state.
func TestRegressionTerminalStateRefusesTransitions(t *testing.T) {
	srv := newTestServerForRegression(t)
	const region = "us-east-1"
	smURL := srv.URL + "/secretsmanager/region/" + region
	post := func(target, body string) (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, smURL, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-amz-json-1.1")
		req.Header.Set("X-Amz-Target", target)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", target, err)
		}
		defer resp.Body.Close()
		return resp, readResponseBody(t, resp)
	}

	post("secretsmanager.CreateSecret", `{"Name":"db","SecretString":"x"}`)
	post("secretsmanager.DeleteSecret", `{"SecretId":"db","ForceDeleteWithoutRecovery":true}`)

	// Restore after destroy → 409.
	resp, body := post("secretsmanager.RestoreSecret", `{"SecretId":"db"}`)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("RestoreSecret on Destroyed: got %d, want 409; body=%s", resp.StatusCode, body)
	}
}

// 10. Distinct 409 sentinels.
//
// Pattern: ErrInUse (FK-blocked delete) and ErrTerminalState (state
// can't transition) carry different wire payloads — different AWS
// error codes. Generic ErrConflict is a fallback only. Mirror of
// fakegcp pass-20.
//
// IAM is in scope today: DeletePolicy of an attached policy returns
// ResourceInUseException (409); a hypothetical terminal-state error
// would return InvalidRequestException (409). The two must NOT
// collapse.
func TestRegressionDistinct409Sentinels(t *testing.T) {
	srv := newTestServerForRegression(t)
	createRole(t, srv, "r")
	createPolicy(t, srv, "p")
	// Attach + try to delete: ErrInUse → 409 ResourceInUseException.
	policyArn := "arn:aws:iam::000000000000:policy/p"
	if _, body := iamPost(t, srv, "AttachRolePolicy", url.Values{
		"RoleName": {"r"}, "PolicyArn": {policyArn},
	}); body == nil {
		t.Fatalf("AttachRolePolicy returned nil body")
	}
	resp, body := iamPost(t, srv, "DeletePolicy", url.Values{"PolicyName": {"p"}})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("DeletePolicy attached: got %d, want 409", resp.StatusCode)
	}
	if !strings.Contains(string(body), "ResourceInUseException") {
		t.Errorf("body must carry ResourceInUseException (not generic ConflictException): %s", body)
	}
}

// 11. Hosted-zone delete refused if non-empty.
//
// Pattern: Route53 hosted-zone delete must check rrset count first
// and refuse with 409 if records still exist. Mirror of fakegcp
// pass-21 (DNS managed-zone delete). Lit up via Route53.
func TestRegressionHostedZoneDeleteRefusedIfNonEmpty(t *testing.T) {
	srv := newTestServerForRegression(t)
	r53Post := func(method, path, body string) (*http.Response, []byte) {
		t.Helper()
		var rd *strings.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		var req *http.Request
		if rd != nil {
			req, _ = http.NewRequest(method, srv.URL+path, rd)
			req.Header.Set("Content-Type", "application/xml")
		} else {
			req, _ = http.NewRequest(method, srv.URL+path, nil)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		return resp, readResponseBody(t, resp)
	}

	resp, body := r53Post(http.MethodPost, "/route53/2013-04-01/hostedzone",
		`<CreateHostedZoneRequest><Name>example.com.</Name><CallerReference>r1</CallerReference></CreateHostedZoneRequest>`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("setup CreateHostedZone: %d %s", resp.StatusCode, body)
	}
	idStart := strings.Index(string(body), "<Id>/hostedzone/") + len("<Id>/hostedzone/")
	idEnd := strings.Index(string(body)[idStart:], "</Id>") + idStart
	zoneID := string(body)[idStart:idEnd]

	// Add a record.
	r53Post(http.MethodPost, "/route53/2013-04-01/hostedzone/"+zoneID+"/rrset/",
		`<ChangeResourceRecordSetsRequest><ChangeBatch><Changes><Change><Action>CREATE</Action><ResourceRecordSet>
		<Name>www.example.com.</Name><Type>A</Type><TTL>300</TTL>
		<ResourceRecords><ResourceRecord><Value>192.0.2.1</Value></ResourceRecord></ResourceRecords>
		</ResourceRecordSet></Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>`)

	// Delete must reject.
	resp, _ = r53Post(http.MethodDelete, "/route53/2013-04-01/hostedzone/"+zoneID, "")
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("non-empty zone delete: got %d, want 409", resp.StatusCode)
	}
}

// 12. Tombstone semantics on parent delete.
//
// Pattern: SQS queue delete must rebadge in-flight messages to a
// "_deleted-queue_" tombstone, mirroring fakegcp's pass-25 Pub/Sub
// pattern. Without this, downstream consumers race against deletion.
// Codex pass 1 BLOCKING #2 + #3 — lit up with a real assertion now
// that the tombstone path is implemented in repository/sqs.go;
// /mock/state surfaces tombstoned_messages count under .sqs.
func TestRegressionTombstoneSemanticsOnParentDelete(t *testing.T) {
	srv := newTestServerForRegression(t)
	const region = "us-east-1"
	sqsURL := srv.URL + "/sqs/region/" + region

	post := func(target, body string) []byte {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, sqsURL,
			strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-amz-json-1.0")
		req.Header.Set("X-Amz-Target", target)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", target, err)
		}
		defer resp.Body.Close()
		return readResponseBody(t, resp)
	}

	body := post("AmazonSQS.CreateQueue", `{"QueueName":"jobs"}`)
	urlStart := strings.Index(string(body), `"QueueUrl":"`) + len(`"QueueUrl":"`)
	urlEnd := strings.Index(string(body)[urlStart:], `"`) + urlStart
	queueURL := string(body)[urlStart:urlEnd]

	post("AmazonSQS.SendMessage", `{"QueueUrl":"`+queueURL+`","MessageBody":"hello"}`)
	post("AmazonSQS.DeleteQueue", `{"QueueUrl":"`+queueURL+`"}`)

	// /mock/state.sqs.tombstoned_messages must be 1 — message rebadged.
	resp, err := http.Get(srv.URL + "/mock/state")
	if err != nil {
		t.Fatalf("GET /mock/state: %v", err)
	}
	defer resp.Body.Close()
	stateBytes := readResponseBody(t, resp)
	if !strings.Contains(string(stateBytes), `"tombstoned_messages":1`) {
		t.Errorf("tombstone count after queue delete: state=%s", stateBytes)
	}
}

// 13. Resource-existence gate on every sub-resource / child handler.
//
// Pattern: record-set under hosted-zone, item under DynamoDB table,
// message under SQS queue, version under secret — each handler calls
// a requireParentX helper that 404s if the parent is missing.
// Missing-parent must be 404 (resource not found), NOT 500. Mirror
// of fakegcp pass-22.
//
// IAM has the analog: AttachRolePolicy on a missing role must 404
// (not 500). Asserted here for the IAM case; service tickets light
// up additional sub-resources as they land.
func TestRegressionResourceExistenceGateOnSubResource(t *testing.T) {
	srv := newTestServerForRegression(t)
	resp, body := iamPost(t, srv, "AttachRolePolicy", url.Values{
		"RoleName":  {"missing"},
		"PolicyArn": {"arn:aws:iam::000000000000:policy/p"},
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("AttachRolePolicy with missing role: %d want 404 body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "ResourceNotFoundException") {
		t.Errorf("body must carry ResourceNotFoundException: %s", body)
	}
}

// 14. Server-stamped fields are never trusted from the client.
//
// Pattern: id, arn, creationDate, etc. are written by the repo on
// insert and never honoured from the request body. PATCH carries an
// explicit skip-list of immutable fields. Mirror of fakegcp pass-4.
//
// IAM CreateRole: even if the caller smuggles in an `Arn` value, the
// stored ARN must be the synthetic awsproto.BuildIAMRoleARN result.
func TestRegressionServerStampedFieldsNeverTrusted(t *testing.T) {
	srv := newTestServerForRegression(t)
	// CreateRole with a smuggled Arn — server must ignore it.
	resp, body := iamPost(t, srv, "CreateRole", url.Values{
		"RoleName":                 {"x"},
		"AssumeRolePolicyDocument": {`{"Version":"2012-10-17"}`},
		"Arn":                      {"arn:aws:iam::000000000000:role/SMUGGLED"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateRole: %d body=%s", resp.StatusCode, body)
	}
	if strings.Contains(string(body), "SMUGGLED") {
		t.Errorf("server must ignore smuggled Arn: %s", body)
	}
	if !strings.Contains(string(body), "arn:aws:iam::000000000000:role/x") {
		t.Errorf("server must stamp canonical ARN: %s", body)
	}
}

// 15. SQL-column / JSON-blob sync on UPDATE.
//
// Pattern: when an Update writes a JSON blob AND mutates an extracted
// SQL column (e.g., vpc_id, region), both must be updated atomically.
// mockway's bug catalogue lists this as the highest-frequency
// regression: the JSON gets rewritten, the indexed column stays
// stale, list-by-region returns wrong results.
//
// IAM doesn't have indexed FK columns at v1 (no cross-resource SQL
// joins on IAM tables); the test flips active when EC2 lands (S44).
//
// EC2 expression: the strongest test target is SecurityGroup rules.
// CreateSecurityGroup writes the JSON `data` blob (containing rule
// arrays) AND extracted indexed columns (vpc_id, group_name).
// AuthorizeSecurityGroupIngress mutates the ingress JSON column.
// The bug we guard against is "JSON updated, indexed scalar lookups
// stale". Asserted by round-tripping a rule via Authorize then
// reading it back via DescribeSecurityGroups (which queries via
// indexed column AND parses the JSON) and confirming the rule is
// present.
func TestRegressionSQLColumnJSONBlobSyncOnUpdate(t *testing.T) {
	srv := newTestServerForRegression(t)
	const region = "us-east-1"
	_, body := ec2PostRegression(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
	vpcID := xmlExtract(body, "vpcId")
	_, body = ec2PostRegression(t, srv, region, "CreateSecurityGroup", url.Values{
		"GroupName": {"app"}, "GroupDescription": {"app"}, "VpcId": {vpcID},
	})
	sgID := xmlExtract(body, "groupId")

	resp, _ := ec2PostRegression(t, srv, region, "AuthorizeSecurityGroupIngress", url.Values{
		"GroupId":                          {sgID},
		"IpPermissions.1.IpProtocol":       {"tcp"},
		"IpPermissions.1.FromPort":         {"22"},
		"IpPermissions.1.ToPort":           {"22"},
		"IpPermissions.1.IpRanges.1.CidrIp": {"10.0.0.0/8"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Authorize: %d", resp.StatusCode)
	}

	params := url.Values{}
	params.Set("GroupId.1", sgID)
	_, body = ec2PostRegression(t, srv, region, "DescribeSecurityGroups", params)
	if !strings.Contains(string(body), "<cidrIp>10.0.0.0/8</cidrIp>") {
		t.Errorf("rule JSON column must round-trip through indexed lookup; body=%s", body)
	}
}

// 16. Transactional batched changes.
//
// Pattern: Route53 ChangeResourceRecordSets is a batch primitive — a
// batch with one bad change rejects the whole batch with no partial
// state. v1 canonical example. Mirror of fakegcp pass-1 + cross-
// pollination. Lit up via Route53.
func TestRegressionTransactionalBatchedChanges(t *testing.T) {
	srv := newTestServerForRegression(t)
	r53Post := func(method, path, body string) (*http.Response, []byte) {
		t.Helper()
		var req *http.Request
		if body != "" {
			req, _ = http.NewRequest(method, srv.URL+path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/xml")
		} else {
			req, _ = http.NewRequest(method, srv.URL+path, nil)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		return resp, readResponseBody(t, resp)
	}

	_, body := r53Post(http.MethodPost, "/route53/2013-04-01/hostedzone",
		`<CreateHostedZoneRequest><Name>example.com.</Name><CallerReference>x</CallerReference></CreateHostedZoneRequest>`)
	idStart := strings.Index(string(body), "<Id>/hostedzone/") + len("<Id>/hostedzone/")
	idEnd := strings.Index(string(body)[idStart:], "</Id>") + idStart
	zoneID := string(body)[idStart:idEnd]

	// Mixed batch: one good change, one apex CNAME (invalid). Whole
	// batch must reject — neither change applies.
	mixed := `<ChangeResourceRecordSetsRequest><ChangeBatch><Changes>
		<Change><Action>CREATE</Action><ResourceRecordSet>
			<Name>www.example.com.</Name><Type>A</Type><TTL>300</TTL>
			<ResourceRecords><ResourceRecord><Value>192.0.2.1</Value></ResourceRecord></ResourceRecords>
		</ResourceRecordSet></Change>
		<Change><Action>CREATE</Action><ResourceRecordSet>
			<Name>example.com.</Name><Type>CNAME</Type><TTL>300</TTL>
			<ResourceRecords><ResourceRecord><Value>bad</Value></ResourceRecord></ResourceRecords>
		</ResourceRecordSet></Change>
	</Changes></ChangeBatch></ChangeResourceRecordSetsRequest>`
	resp, _ := r53Post(http.MethodPost, "/route53/2013-04-01/hostedzone/"+zoneID+"/rrset/", mixed)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("mixed batch: %d, want 409", resp.StatusCode)
	}

	// Verify NEITHER change applied.
	_, body = r53Post(http.MethodGet, "/route53/2013-04-01/hostedzone/"+zoneID+"/rrset", "")
	if strings.Contains(string(body), "www.example.com.") {
		t.Errorf("transactional violation — www applied despite batch failure: %s", body)
	}
}

// TestRegressionStateGatherCollectionsComplete pins Codex pass 7
// BLOCKING #2: every modeled child collection must surface in
// /mock/state. Items under DynamoDB tables and messages under SQS
// queues were previously absent, so update-phase verification could
// not see mutations to those rows. Now they're listed alongside their
// parents.
func TestRegressionStateGatherCollectionsComplete(t *testing.T) {
	srv := newTestServerForRegression(t)
	const region = "us-east-1"

	// Seed a DynamoDB table + item.
	post := func(svc, target, body string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/"+svc+"/region/"+region,
			strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-amz-json-1.0")
		req.Header.Set("X-Amz-Target", target)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("POST %s %s: %v", svc, target, err)
		}
		defer resp.Body.Close()
		readResponseBody(t, resp)
	}
	postJSON11 := func(svc, target, body string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/"+svc+"/region/"+region,
			strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-amz-json-1.1")
		req.Header.Set("X-Amz-Target", target)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("POST %s %s: %v", svc, target, err)
		}
		defer resp.Body.Close()
		readResponseBody(t, resp)
	}

	postJSON11("dynamodb", "DynamoDB_20120810.CreateTable",
		`{"TableName":"Users","AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],"KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"BillingMode":"PAY_PER_REQUEST"}`)
	postJSON11("dynamodb", "DynamoDB_20120810.PutItem",
		`{"TableName":"Users","Item":{"id":{"S":"alice"}}}`)

	post("sqs", "AmazonSQS.CreateQueue", `{"QueueName":"jobs"}`)
	post("sqs", "AmazonSQS.SendMessage",
		`{"QueueUrl":"http://localhost/sqs/`+region+`/000000000000/jobs","MessageBody":"hello"}`)

	resp, err := http.Get(srv.URL + "/mock/state")
	if err != nil {
		t.Fatalf("GET /mock/state: %v", err)
	}
	defer resp.Body.Close()
	stateBytes := readResponseBody(t, resp)
	state := string(stateBytes)

	if !strings.Contains(state, `"items"`) {
		t.Errorf("dynamodb.items collection missing from /mock/state: %s", state)
	}
	if !strings.Contains(state, `"alice"`) {
		t.Errorf("dynamodb item not surfaced in /mock/state: %s", state)
	}
	if !strings.Contains(state, `"messages"`) {
		t.Errorf("sqs.messages collection missing from /mock/state: %s", state)
	}
	if !strings.Contains(state, `"hello"`) {
		t.Errorf("sqs message body not surfaced in /mock/state: %s", state)
	}
}

// TestRegressionEC2DescribeRegionScoped pins Codex pass 8 BLOCKING #1:
// DescribeSubnets and DescribeInternetGateways must scope to the
// request region. Previously both list paths queried account-wide
// and leaked rows from other regions.
func TestRegressionEC2DescribeRegionScoped(t *testing.T) {
	srv := newTestServerForRegression(t)

	// Seed: VPC + Subnet + IGW in us-east-1 AND eu-west-1.
	for _, region := range []string{"us-east-1", "eu-west-1"} {
		_, body := ec2PostRegression(t, srv, region, "CreateVpc", url.Values{
			"CidrBlock": {"10.0.0.0/16"},
		})
		vpcID := xmlExtract(body, "vpcId")
		ec2PostRegression(t, srv, region, "CreateSubnet", url.Values{
			"VpcId":            {vpcID},
			"CidrBlock":        {"10.0.1.0/24"},
			"AvailabilityZone": {region + "a"},
		})
		ec2PostRegression(t, srv, region, "CreateInternetGateway", url.Values{})
	}

	// DescribeSubnets in us-east-1: must NOT contain eu-west-1's subnet.
	_, body := ec2PostRegression(t, srv, "us-east-1", "DescribeSubnets", nil)
	if strings.Contains(string(body), "eu-west-1") {
		t.Errorf("DescribeSubnets us-east-1 leaked eu-west-1 row: %s", body)
	}

	// DescribeInternetGateways in us-east-1: same isolation.
	_, body = ec2PostRegression(t, srv, "us-east-1", "DescribeInternetGateways", nil)
	if strings.Contains(string(body), "eu-west-1") {
		t.Errorf("DescribeInternetGateways us-east-1 leaked eu-west-1 row: %s", body)
	}
}

// TestRegressionStateGatherAccountWide pins Codex pass 8 BLOCKING #2:
// /mock/state must enumerate account-wide for collections that were
// previously walked via a hard-coded region slice (key pairs and
// Secrets Manager). Resources created outside that slice must still
// appear in the state surface.
func TestRegressionStateGatherAccountWide(t *testing.T) {
	srv := newTestServerForRegression(t)

	// Use a region NOT in the previous hard-coded slice
	// {us-east-1, us-east-2, us-west-1, us-west-2,
	//  eu-west-1, eu-west-2, eu-central-1, ap-southeast-1}.
	const oddRegion = "ap-northeast-1"

	// Key pair in odd region.
	ec2PostRegression(t, srv, oddRegion, "ImportKeyPair", url.Values{
		"KeyName":           {"odd-kp"},
		"PublicKeyMaterial": {"c3NoLXJzYSBBQUFBQjN... AmZmFrZQ=="},
	})

	// Secret in odd region.
	smReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/secretsmanager/region/"+oddRegion,
		strings.NewReader(`{"Name":"odd-secret","SecretString":"hello"}`))
	smReq.Header.Set("Content-Type", "application/x-amz-json-1.1")
	smReq.Header.Set("X-Amz-Target", "secretsmanager.CreateSecret")
	resp, err := srv.Client().Do(smReq)
	if err != nil {
		t.Fatalf("CreateSecret %s: %v", oddRegion, err)
	}
	resp.Body.Close()

	resp, err = http.Get(srv.URL + "/mock/state")
	if err != nil {
		t.Fatalf("GET /mock/state: %v", err)
	}
	defer resp.Body.Close()
	state := string(readResponseBody(t, resp))

	if !strings.Contains(state, "odd-kp") {
		t.Errorf("/mock/state.ec2.key_pairs missing odd-region key pair: %s", state)
	}
	if !strings.Contains(state, "odd-secret") {
		t.Errorf("/mock/state.secretsmanager.secrets missing odd-region secret: %s", state)
	}
}

// TestRegressionRunInstancesRejectsUnknownAMI pins Codex pass 9
// BLOCKING #1: RunInstances must reject a typoed/unsupported
// ImageId rather than silently inserting an instance row that
// references a nonexistent AMI. Mirrors real EC2 semantics for
// invalid AMI references.
func TestRegressionRunInstancesRejectsUnknownAMI(t *testing.T) {
	srv := newTestServerForRegression(t)
	const region = "us-east-1"

	_, body := ec2PostRegression(t, srv, region, "CreateVpc", url.Values{
		"CidrBlock": {"10.0.0.0/16"},
	})
	vpcID := xmlExtract(body, "vpcId")
	_, body = ec2PostRegression(t, srv, region, "CreateSubnet", url.Values{
		"VpcId":            {vpcID},
		"CidrBlock":        {"10.0.1.0/24"},
		"AvailabilityZone": {"us-east-1a"},
	})
	subnetID := xmlExtract(body, "subnetId")

	resp, body := ec2PostRegression(t, srv, region, "RunInstances", url.Values{
		"SubnetId":     {subnetID},
		"ImageId":      {"ami-does-not-exist"},
		"InstanceType": {"t3.micro"},
		"MinCount":     {"1"}, "MaxCount": {"1"},
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("RunInstances unknown AMI: got %d, want 404 body=%s", resp.StatusCode, body)
	}
}

// TestRegressionRunInstancesAvailableInAnyRegion pins Codex pass 9
// BLOCKING #1's lazy-seed contract: canonical AMI fixtures must be
// reachable from any region, not just the boot-time slice.
func TestRegressionRunInstancesAvailableInAnyRegion(t *testing.T) {
	srv := newTestServerForRegression(t)
	const region = "ap-northeast-1" // outside the original 8-region slice

	_, body := ec2PostRegression(t, srv, region, "CreateVpc", url.Values{
		"CidrBlock": {"10.0.0.0/16"},
	})
	vpcID := xmlExtract(body, "vpcId")
	_, body = ec2PostRegression(t, srv, region, "CreateSubnet", url.Values{
		"VpcId":            {vpcID},
		"CidrBlock":        {"10.0.1.0/24"},
		"AvailabilityZone": {region + "a"},
	})
	subnetID := xmlExtract(body, "subnetId")

	resp, body := ec2PostRegression(t, srv, region, "RunInstances", url.Values{
		"SubnetId":     {subnetID},
		"ImageId":      {"ami-0abcd1234"},
		"InstanceType": {"t3.micro"},
		"MinCount":     {"1"}, "MaxCount": {"1"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("RunInstances ap-northeast-1: got %d, want 200 body=%s", resp.StatusCode, body)
	}
}

// TestRegressionStateGatherEC2Collections pins Codex pass 10 BLOCKING
// #2: /mock/state.ec2 must surface route_tables, routes,
// route_table_associations, and eips so topology_derive_aws can see
// public-subnet wiring and EIP allocations. Previously these
// collections were absent entirely.
func TestRegressionStateGatherEC2Collections(t *testing.T) {
	srv := newTestServerForRegression(t)
	const region = "us-east-1"

	// VPC + subnet to anchor the route table + association.
	_, body := ec2PostRegression(t, srv, region, "CreateVpc", url.Values{
		"CidrBlock": {"10.0.0.0/16"},
	})
	vpcID := xmlExtract(body, "vpcId")
	if vpcID == "" {
		t.Fatalf("CreateVpc: missing vpcId in %s", body)
	}
	_, body = ec2PostRegression(t, srv, region, "CreateSubnet", url.Values{
		"VpcId":            {vpcID},
		"CidrBlock":        {"10.0.1.0/24"},
		"AvailabilityZone": {"us-east-1a"},
	})
	subnetID := xmlExtract(body, "subnetId")
	if subnetID == "" {
		t.Fatalf("CreateSubnet: missing subnetId in %s", body)
	}

	// Internet gateway — provides a target for the default route.
	_, body = ec2PostRegression(t, srv, region, "CreateInternetGateway", url.Values{})
	igwID := xmlExtract(body, "internetGatewayId")
	if igwID == "" {
		t.Fatalf("CreateInternetGateway: missing internetGatewayId in %s", body)
	}

	// Route table.
	_, body = ec2PostRegression(t, srv, region, "CreateRouteTable", url.Values{
		"VpcId": {vpcID},
	})
	rtID := xmlExtract(body, "routeTableId")
	if rtID == "" {
		t.Fatalf("CreateRouteTable: missing routeTableId in %s", body)
	}

	// Route on the table — 0.0.0.0/0 → IGW.
	if resp, body := ec2PostRegression(t, srv, region, "CreateRoute", url.Values{
		"RouteTableId":         {rtID},
		"DestinationCidrBlock": {"0.0.0.0/0"},
		"GatewayId":            {igwID},
	}); resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateRoute: %d body=%s", resp.StatusCode, body)
	}

	// Subnet association.
	_, body = ec2PostRegression(t, srv, region, "AssociateRouteTable", url.Values{
		"RouteTableId": {rtID},
		"SubnetId":     {subnetID},
	})
	assocID := xmlExtract(body, "associationId")
	if assocID == "" {
		t.Fatalf("AssociateRouteTable: missing associationId in %s", body)
	}

	// EIP allocation.
	_, body = ec2PostRegression(t, srv, region, "AllocateAddress", url.Values{
		"Domain": {"vpc"},
	})
	allocID := xmlExtract(body, "allocationId")
	if allocID == "" {
		t.Fatalf("AllocateAddress: missing allocationId in %s", body)
	}

	resp, err := http.Get(srv.URL + "/mock/state")
	if err != nil {
		t.Fatalf("GET /mock/state: %v", err)
	}
	defer resp.Body.Close()
	state := string(readResponseBody(t, resp))

	// Each collection key must appear (non-nil empty list contract).
	for _, want := range []string{
		`"route_tables"`,
		`"routes"`,
		`"route_table_associations"`,
		`"eips"`,
	} {
		if !strings.Contains(state, want) {
			t.Errorf("/mock/state.ec2 missing collection %s: %s", want, state)
		}
	}
	// Each created id must surface in the corresponding collection.
	for _, want := range []string{rtID, assocID, allocID, "0.0.0.0/0", igwID} {
		if !strings.Contains(state, want) {
			t.Errorf("/mock/state.ec2 missing %q: %s", want, state)
		}
	}
}

// TestRegressionStateGatherRoute53AliasTarget pins Codex pass 13
// BLOCKING #2: ALIAS records persist an alias_target JSON blob, but
// gatherRoute53StateReal previously dropped that field, leaving
// alias records indistinguishable from no-record entries. Now the
// /mock/state projection includes alias_target.
func TestRegressionStateGatherRoute53AliasTarget(t *testing.T) {
	srv := newTestServerForRegression(t)

	// Create hosted zone.
	r53Post := func(method, path, body string) (*http.Response, []byte) {
		t.Helper()
		var req *http.Request
		if body != "" {
			req, _ = http.NewRequest(method, srv.URL+path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/xml")
		} else {
			req, _ = http.NewRequest(method, srv.URL+path, nil)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		return resp, readResponseBody(t, resp)
	}

	_, body := r53Post(http.MethodPost, "/route53/2013-04-01/hostedzone",
		`<CreateHostedZoneRequest><Name>example.com.</Name><CallerReference>x</CallerReference></CreateHostedZoneRequest>`)
	idStart := strings.Index(string(body), "<Id>/hostedzone/") + len("<Id>/hostedzone/")
	idEnd := strings.Index(string(body)[idStart:], "</Id>") + idStart
	zoneID := string(body)[idStart:idEnd]

	// Create an ALIAS record with AliasTarget.
	alias := `<ChangeResourceRecordSetsRequest><ChangeBatch><Changes>
		<Change><Action>CREATE</Action><ResourceRecordSet>
			<Name>www.example.com.</Name><Type>A</Type>
			<AliasTarget>
				<HostedZoneId>Z2FDTNDATAQYW2</HostedZoneId>
				<DNSName>d111111abcdef8.cloudfront.net.</DNSName>
				<EvaluateTargetHealth>false</EvaluateTargetHealth>
			</AliasTarget>
		</ResourceRecordSet></Change>
	</Changes></ChangeBatch></ChangeResourceRecordSetsRequest>`
	r53Post(http.MethodPost, "/route53/2013-04-01/hostedzone/"+zoneID+"/rrset/", alias)

	// /mock/state.route53.record_sets must include alias_target.
	resp, err := http.Get(srv.URL + "/mock/state")
	if err != nil {
		t.Fatalf("GET /mock/state: %v", err)
	}
	defer resp.Body.Close()
	state := string(readResponseBody(t, resp))
	if !strings.Contains(state, "alias_target") {
		t.Errorf("alias_target field missing from /mock/state.route53.record_sets: %s", state)
	}
	if !strings.Contains(state, "d111111abcdef8.cloudfront.net.") {
		t.Errorf("AliasTarget DNSName not surfaced in /mock/state: %s", state)
	}
}

// TestRegressionPutSecretValueRefusedAfterForceDelete pins Codex
// pass 14 BLOCKING #1: PutSecretValue on a force-deleted secret
// previously returned 200 and persisted a hidden version row that
// every read path treated as gone. Now PutSecretValue uses the
// terminal-state-aware lookup and rejects with NotFound, matching
// real Secrets Manager semantics.
func TestRegressionPutSecretValueRefusedAfterForceDelete(t *testing.T) {
	srv := newTestServerForRegression(t)
	const region = "us-east-1"

	post := func(target, body string) (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/secretsmanager/region/"+region,
			strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-amz-json-1.1")
		req.Header.Set("X-Amz-Target", "secretsmanager."+target)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", target, err)
		}
		defer resp.Body.Close()
		return resp, readResponseBody(t, resp)
	}

	post("CreateSecret", `{"Name":"db/password","SecretString":"first"}`)
	post("DeleteSecret", `{"SecretId":"db/password","ForceDeleteWithoutRecovery":true}`)

	resp, body := post("PutSecretValue", `{"SecretId":"db/password","SecretString":"sneak"}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("PutSecretValue after force-delete: got %d, want 404 body=%s", resp.StatusCode, body)
	}
}

// TestRegressionSecretsManagerTerminalStateWireShape pins Codex
// pass 15 BLOCKING #1: terminal-state refusal on Secrets Manager
// must surface as InvalidRequestException on the wire, not the
// generic ConflictException. The "distinct 409 sentinels" rule
// matters because update flows branch on the body.
func TestRegressionSecretsManagerTerminalStateWireShape(t *testing.T) {
	srv := newTestServerForRegression(t)
	const region = "us-east-1"

	post := func(target, body string) (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/secretsmanager/region/"+region,
			strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-amz-json-1.1")
		req.Header.Set("X-Amz-Target", "secretsmanager."+target)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", target, err)
		}
		defer resp.Body.Close()
		return resp, readResponseBody(t, resp)
	}

	post("CreateSecret", `{"Name":"db/pwd","SecretString":"v1"}`)
	post("DeleteSecret", `{"SecretId":"db/pwd","ForceDeleteWithoutRecovery":true}`)

	resp, body := post("RestoreSecret", `{"SecretId":"db/pwd"}`)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("RestoreSecret on destroyed: got %d, want 409", resp.StatusCode)
	}
	if !strings.Contains(string(body), "InvalidRequestException") {
		t.Errorf("RestoreSecret terminal-state body: must carry InvalidRequestException, got: %s", body)
	}
}

// ----- test helpers (regression-suite local) -----

const regressionVersion = "2010-05-08"

func newTestServerForRegression(t *testing.T) *httptest.Server {
	t.Helper()
	app, err := handlers.NewApplication(":memory:", false)
	if err != nil {
		t.Fatalf("NewApplication: %v", err)
	}
	srv := httptest.NewServer(app.Router())
	t.Cleanup(func() {
		srv.Close()
		_ = app.Close()
	})
	return srv
}

func ec2PostRegression(t *testing.T, srv *httptest.Server, region, action string, params url.Values) (*http.Response, []byte) {
	t.Helper()
	if params == nil {
		params = url.Values{}
	}
	params.Set("Action", action)
	params.Set("Version", "2016-11-15")
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/ec2/region/"+region, strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /ec2/region/%s %s: %v", region, action, err)
	}
	defer resp.Body.Close()
	body := readResponseBody(t, resp)
	return resp, body
}

func xmlExtract(body []byte, tag string) string {
	start := "<" + tag + ">"
	end := "</" + tag + ">"
	s := strings.Index(string(body), start)
	if s < 0 {
		return ""
	}
	s += len(start)
	e := strings.Index(string(body)[s:], end)
	if e < 0 {
		return ""
	}
	return string(body)[s : s+e]
}

func iamPost(t *testing.T, srv *httptest.Server, action string, params url.Values) (*http.Response, []byte) {
	t.Helper()
	if params == nil {
		params = url.Values{}
	}
	params.Set("Action", action)
	params.Set("Version", regressionVersion)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/iam", strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /iam %s: %v", action, err)
	}
	defer resp.Body.Close()
	body := readResponseBody(t, resp)
	return resp, body
}

func readResponseBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	const max = 64 * 1024
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if len(buf) > max {
				return buf[:max]
			}
		}
		if err != nil {
			break
		}
	}
	return buf
}

func createRole(t *testing.T, srv *httptest.Server, name string) {
	t.Helper()
	resp, body := iamPost(t, srv, "CreateRole", url.Values{
		"RoleName":                 {name},
		"AssumeRolePolicyDocument": {`{"Version":"2012-10-17"}`},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("regression seed: createRole(%s): %d body=%s", name, resp.StatusCode, body)
	}
}

func createPolicy(t *testing.T, srv *httptest.Server, name string) {
	t.Helper()
	resp, body := iamPost(t, srv, "CreatePolicy", url.Values{
		"PolicyName":     {name},
		"PolicyDocument": {`{"Version":"2012-10-17"}`},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("regression seed: createPolicy(%s): %d body=%s", name, resp.StatusCode, body)
	}
}
