// awsproto_test covers the load-bearing acceptance criteria of S43-T2:
//
//   - 5 wire shapes × 4 error sentinels = 20 cells minimum, each with a
//     distinct (shape, sentinel) → (status, content-type, body shape)
//     tuple asserted. Per concepts.md § "Anti-patterns explicitly
//     forbidden" — no untested error-shape mappings.
//
//   - Per-service ARN builders match the format documented for each
//     service (M39 fold-in: IAM omits region, S3 is bucket-scoped,
//     Route53 is global, RDS uses ':' separator, etc.).
//
//   - Wire-format parsers (Query-RPC body, X-Amz-Target header) handle
//     the success and error paths.
package awsproto

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/redscaresu/fakeaws/models"
)

// TestErrorMatrixCoversEveryWireShapeSentinelCell is the load-bearing
// audit. For each (wire shape × error sentinel) cell, assert:
//   - HTTP status is the documented one for the sentinel.
//   - Content-Type matches the wire-shape's expected MIME.
//   - Body contains the AWS-spec error code.
//
// 5 shapes × 4 sentinels = 20 cells. The test is table-driven so
// adding a sixth shape or fifth sentinel is one row each.
func TestErrorMatrixCoversEveryWireShapeSentinelCell(t *testing.T) {
	shapes := []struct {
		shape       WireShape
		contentType string
		bodyHas     []string // substrings the body MUST contain
	}{
		{ShapeXML, "application/xml", []string{"<Error>", "<Code>", "<Message>"}},
		{ShapeQueryRPC, "text/xml", []string{"<ErrorResponse>", "<Code>", "<Type>"}},
		{ShapeJSON10, "application/x-amz-json-1.0", []string{`"__type"`, `"message"`}},
		{ShapeJSON11, "application/x-amz-json-1.1", []string{`"__type"`, `"message"`}},
		{ShapeJSONREST, "application/json", []string{`"__type"`, `"message"`}},
	}
	sentinels := []struct {
		err    error
		status int
		code   string // AWS-spec error code that must appear in body
	}{
		{models.ErrNotFound, http.StatusNotFound, "ResourceNotFoundException"},
		{models.ErrInUse, http.StatusConflict, "ResourceInUseException"},
		{models.ErrTerminalState, http.StatusConflict, "InvalidRequestException"},
		{models.ErrConflict, http.StatusConflict, "ConflictException"},
	}

	cells := 0
	for _, s := range shapes {
		for _, e := range sentinels {
			cells++
			t.Run(s.shape.String()+"_"+e.err.Error(), func(t *testing.T) {
				w := httptest.NewRecorder()
				WriteAWSError(w, s.shape, e.err)

				if w.Code != e.status {
					t.Errorf("status: got %d want %d", w.Code, e.status)
				}
				if got := w.Header().Get("Content-Type"); got != s.contentType {
					t.Errorf("content-type: got %q want %q", got, s.contentType)
				}
				body := w.Body.String()
				if !strings.Contains(body, e.code) {
					t.Errorf("body missing error code %q: %s", e.code, body)
				}
				for _, want := range s.bodyHas {
					if !strings.Contains(body, want) {
						t.Errorf("body missing wire-shape marker %q: %s", want, body)
					}
				}
			})
		}
	}
	if cells < 20 {
		t.Fatalf("only exercised %d (shape × sentinel) cells; S43-T2 acceptance requires ≥20", cells)
	}
}

// TestErrorMatrixCellsAreDistinct asserts that two different sentinels
// for the same shape produce distinguishable bodies. Caught a real
// regression in fakegcp where two distinct sentinels collapsed to the
// same wire payload because the writer was dispatching on Status alone.
func TestErrorMatrixCellsAreDistinct(t *testing.T) {
	for _, shape := range []WireShape{ShapeXML, ShapeQueryRPC, ShapeJSON10, ShapeJSON11, ShapeJSONREST} {
		_, _, body1 := formatError(shape, models.ErrInUse)
		_, _, body2 := formatError(shape, models.ErrTerminalState)
		if bytes.Equal(body1, body2) {
			t.Errorf("shape=%s: ErrInUse and ErrTerminalState produced identical bodies; one should be ResourceInUseException, the other InvalidRequestException", shape)
		}
	}
}

// TestErrorMatrixUnknownSentinelFallsBackToInternalFailure pins the
// graceful-degradation path. An error that isn't one of our four known
// sentinels still produces a structured response, not a panic.
func TestErrorMatrixUnknownSentinelFallsBackToInternalFailure(t *testing.T) {
	w := httptest.NewRecorder()
	WriteAWSError(w, ShapeJSON11, errors.New("something unexpected"))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 InternalFailure, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "InternalFailure") {
		t.Errorf("expected InternalFailure in body: %s", w.Body.String())
	}
}

// ----- Wire-format parsers -----

func TestParseQueryRPCExtractsActionAndVersion(t *testing.T) {
	body := strings.NewReader("Action=DescribeInstances&Version=2016-11-15&InstanceId.1=i-abc&InstanceId.2=i-def")
	r := httptest.NewRequest(http.MethodPost, "/", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	got, err := ParseQueryRPC(r)
	if err != nil {
		t.Fatalf("ParseQueryRPC: %v", err)
	}
	if got.Action != "DescribeInstances" {
		t.Errorf("Action: got %q want DescribeInstances", got.Action)
	}
	if got.Version != "2016-11-15" {
		t.Errorf("Version: got %q want 2016-11-15", got.Version)
	}
	if got.Params.Get("InstanceId.1") != "i-abc" {
		t.Errorf("Params.InstanceId.1: got %q want i-abc", got.Params.Get("InstanceId.1"))
	}
	if got.Params.Get("Action") != "" {
		t.Errorf("Params should not still contain Action after parse")
	}
}

func TestParseQueryRPCRejectsMissingAction(t *testing.T) {
	body := strings.NewReader("Version=2016-11-15")
	r := httptest.NewRequest(http.MethodPost, "/", body)
	if _, err := ParseQueryRPC(r); err == nil {
		t.Errorf("expected error when Action is missing")
	}
}

func TestParseXAmzTargetSplitsServiceAndOperation(t *testing.T) {
	body := strings.NewReader(`{"TableName":"foo"}`)
	r := httptest.NewRequest(http.MethodPost, "/", body)
	r.Header.Set("X-Amz-Target", "DynamoDB_20120810.PutItem")
	r.Header.Set("Content-Type", "application/x-amz-json-1.0")

	got, err := ParseXAmzTarget(r)
	if err != nil {
		t.Fatalf("ParseXAmzTarget: %v", err)
	}
	if got.Service != "DynamoDB_20120810" {
		t.Errorf("Service: got %q want DynamoDB_20120810", got.Service)
	}
	if got.Operation != "PutItem" {
		t.Errorf("Operation: got %q want PutItem", got.Operation)
	}
	if string(got.Body) != `{"TableName":"foo"}` {
		t.Errorf("Body: got %q want %q", string(got.Body), `{"TableName":"foo"}`)
	}
}

func TestParseXAmzTargetRejectsMalformedHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}"))
	r.Header.Set("X-Amz-Target", "MalformedNoDot")
	if _, err := ParseXAmzTarget(r); err == nil {
		t.Errorf("expected error for malformed X-Amz-Target")
	}
}

// ----- Response writers (XML success path) -----

func TestWriteXMLResponseRoundTrips(t *testing.T) {
	type Body struct {
		XMLName xml.Name `xml:"Bucket"`
		Name    string   `xml:"Name"`
	}
	w := httptest.NewRecorder()
	WriteXMLResponse(w, http.StatusOK, Body{Name: "test-bucket"})

	if got := w.Header().Get("Content-Type"); got != "application/xml" {
		t.Errorf("Content-Type: got %q", got)
	}
	if !strings.Contains(w.Body.String(), "<?xml") {
		t.Errorf("expected XML declaration: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "<Bucket>") {
		t.Errorf("expected <Bucket> element: %s", w.Body.String())
	}
}

func TestWriteJSON11ResponseRoundTrips(t *testing.T) {
	w := httptest.NewRecorder()
	WriteJSON11Response(w, http.StatusOK, map[string]any{"TableName": "foo"})

	if got := w.Header().Get("Content-Type"); got != "application/x-amz-json-1.1" {
		t.Errorf("Content-Type: got %q", got)
	}
	var parsed map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("response not valid JSON: %v", err)
	}
	if parsed["TableName"] != "foo" {
		t.Errorf("payload not preserved: %v", parsed)
	}
}

// ----- Per-service ARN builders (M39 fold-in) -----

func TestARNBuildersMatchAWSReferenceFormats(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		// IAM is global — no region, account is "" between two colons
		{"iam-role", BuildIAMRoleARN("admin"), "arn:aws:iam::000000000000:role/admin"},
		{"iam-policy", BuildIAMPolicyARN("policy-1"), "arn:aws:iam::000000000000:policy/policy-1"},
		{"iam-instance-profile", BuildIAMInstanceProfileARN("profile-1"), "arn:aws:iam::000000000000:instance-profile/profile-1"},
		{"iam-user", BuildIAMUserARN("alice"), "arn:aws:iam::000000000000:user/alice"},
		// S3 — no region or account
		{"s3-bucket", BuildS3BucketARN("my-bucket"), "arn:aws:s3:::my-bucket"},
		{"s3-object", BuildS3ObjectARN("my-bucket", "path/to/key.txt"), "arn:aws:s3:::my-bucket/path/to/key.txt"},
		// EC2 — region+account, '/' separator
		{"ec2-instance", BuildEC2InstanceARN("us-east-1", "i-abc"), "arn:aws:ec2:us-east-1:000000000000:instance/i-abc"},
		{"ec2-vpc", BuildEC2VPCARN("us-east-1", "vpc-1"), "arn:aws:ec2:us-east-1:000000000000:vpc/vpc-1"},
		{"ec2-subnet", BuildEC2SubnetARN("us-east-1", "subnet-1"), "arn:aws:ec2:us-east-1:000000000000:subnet/subnet-1"},
		{"ec2-sg", BuildEC2SecurityGroupARN("us-east-1", "sg-1"), "arn:aws:ec2:us-east-1:000000000000:security-group/sg-1"},
		// RDS — region+account, ':' separator (NOT '/')
		{"rds-db", BuildRDSDBARN("us-east-1", "db-1"), "arn:aws:rds:us-east-1:000000000000:db:db-1"},
		{"rds-cluster", BuildRDSClusterARN("us-east-1", "cluster-1"), "arn:aws:rds:us-east-1:000000000000:cluster:cluster-1"},
		{"rds-subnet-group", BuildRDSSubnetGroupARN("us-east-1", "subg-1"), "arn:aws:rds:us-east-1:000000000000:subgrp:subg-1"},
		// EKS — region+account, '/' separator, nodegroup has trailing /<id>
		{"eks-cluster", BuildEKSClusterARN("us-east-1", "demo"), "arn:aws:eks:us-east-1:000000000000:cluster/demo"},
		{"eks-nodegroup", BuildEKSNodegroupARN("us-east-1", "demo", "ng1", "abc-123"), "arn:aws:eks:us-east-1:000000000000:nodegroup/demo/ng1/abc-123"},
		// SQS — no resource-type prefix
		{"sqs-queue", BuildSQSQueueARN("us-east-1", "my-queue"), "arn:aws:sqs:us-east-1:000000000000:my-queue"},
		// Secrets Manager — random suffix
		{"sm-secret", BuildSecretsManagerSecretARN("us-east-1", "db-creds", "AbCdEf"), "arn:aws:secretsmanager:us-east-1:000000000000:secret:db-creds-AbCdEf"},
		// DynamoDB
		{"ddb-table", BuildDynamoDBTableARN("us-east-1", "Users"), "arn:aws:dynamodb:us-east-1:000000000000:table/Users"},
		// Route53 — global
		{"route53-zone", BuildRoute53HostedZoneARN("Z123"), "arn:aws:route53:::hostedzone/Z123"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.got != c.want {
				t.Errorf("got %q want %q", c.got, c.want)
			}
		})
	}
}

// TestARNBuildersUseSyntheticAccount asserts no builder hardcodes a
// real AWS account number. If the FakeAccountID constant moves, every
// builder picks up the change.
func TestARNBuildersUseSyntheticAccount(t *testing.T) {
	if FakeAccountID != "000000000000" {
		t.Fatalf("FakeAccountID changed without test update: %s", FakeAccountID)
	}
	// IAM ARN must contain the synthetic account.
	if !strings.Contains(BuildIAMRoleARN("x"), FakeAccountID) {
		t.Errorf("IAM ARN missing synthetic account")
	}
	// S3 ARN must NOT contain the account (S3 ARNs omit account).
	if strings.Contains(BuildS3BucketARN("x"), FakeAccountID) {
		t.Errorf("S3 ARN must not contain account; got %q", BuildS3BucketARN("x"))
	}
	// Route53 ARN must NOT contain the account (Route53 is global).
	if strings.Contains(BuildRoute53HostedZoneARN("x"), FakeAccountID) {
		t.Errorf("Route53 ARN must not contain account; got %q", BuildRoute53HostedZoneARN("x"))
	}
}
