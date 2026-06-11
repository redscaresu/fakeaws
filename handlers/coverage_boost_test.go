package handlers_test

// coverage_boost_test.go — handler tests that fill gaps the per-service
// suites don't reach. Per S48-T7 acceptance: aggregate coverage must
// be ≥80% on the `total:` line. These tests target the unexercised
// Delete/Modify/Describe paths.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCoverage_EC2DeleteSubnetAndRouteTable(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"

	// Setup VPC + subnet + RT.
	_, body := ec2Call(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
	vpcID := extractEC2Tag(body, "vpcId")
	_, body = ec2Call(t, srv, region, "CreateSubnet", url.Values{"VpcId": {vpcID}, "CidrBlock": {"10.0.1.0/24"}})
	subnetID := extractEC2Tag(body, "subnetId")
	_, body = ec2Call(t, srv, region, "CreateRouteTable", url.Values{"VpcId": {vpcID}})
	rtbID := extractEC2Tag(body, "routeTableId")

	// DeleteSubnet (covers the un-tested handler path).
	resp, _ := ec2Call(t, srv, region, "DeleteSubnet", url.Values{"SubnetId": {subnetID}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DeleteSubnet")
	// DeleteRouteTable.
	resp, _ = ec2Call(t, srv, region, "DeleteRouteTable", url.Values{"RouteTableId": {rtbID}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DeleteRouteTable")
}

func TestCoverage_EC2InstanceModifyAttribute(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"
	_, body := ec2Call(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
	vpcID := extractEC2Tag(body, "vpcId")
	_, body = ec2Call(t, srv, region, "CreateSubnet", url.Values{"VpcId": {vpcID}, "CidrBlock": {"10.0.1.0/24"}})
	subnetID := extractEC2Tag(body, "subnetId")
	_, body = ec2Call(t, srv, region, "RunInstances", url.Values{
		"SubnetId": {subnetID}, "ImageId": {"ami-0abcd1234"}, "InstanceType": {"t3.micro"},
	})
	instID := extractEC2Tag(body, "instanceId")

	resp, _ := ec2Call(t, srv, region, "ModifyInstanceAttribute", url.Values{"InstanceId": {instID}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "ModifyInstanceAttribute")

	// Missing instance → 404.
	resp, _ = ec2Call(t, srv, region, "ModifyInstanceAttribute", url.Values{"InstanceId": {"i-missing"}})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "ModifyInstanceAttribute missing")
}

func TestCoverage_EC2DetachInternetGateway(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"
	_, body := ec2Call(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
	vpcID := extractEC2Tag(body, "vpcId")
	_, body = ec2Call(t, srv, region, "CreateInternetGateway", nil)
	igwID := extractEC2Tag(body, "internetGatewayId")
	ec2Call(t, srv, region, "AttachInternetGateway", url.Values{
		"InternetGatewayId": {igwID}, "VpcId": {vpcID},
	})
	resp, _ := ec2Call(t, srv, region, "DetachInternetGateway", url.Values{"InternetGatewayId": {igwID}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DetachInternetGateway")
}

func TestCoverage_EC2DeleteRoute(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"
	_, body := ec2Call(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
	vpcID := extractEC2Tag(body, "vpcId")
	_, body = ec2Call(t, srv, region, "CreateRouteTable", url.Values{"VpcId": {vpcID}})
	rtbID := extractEC2Tag(body, "routeTableId")
	ec2Call(t, srv, region, "CreateRoute", url.Values{
		"RouteTableId": {rtbID}, "DestinationCidrBlock": {"0.0.0.0/0"}, "GatewayId": {"igw-stub"},
	})
	resp, _ := ec2Call(t, srv, region, "DeleteRoute", url.Values{
		"RouteTableId": {rtbID}, "DestinationCidrBlock": {"0.0.0.0/0"},
	})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DeleteRoute")
}

func TestCoverage_DynamoDBUpdateItem(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	ddbCall(t, srv, "us-east-1", "CreateTable", `{
		"TableName":"Users",
		"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],
		"KeySchema":[{"AttributeName":"id","KeyType":"HASH"}]
	}`)
	ddbCall(t, srv, "us-east-1", "PutItem", `{"TableName":"Users","Item":{"id":{"S":"a"},"v":{"N":"1"}}}`)

	resp, _ := ddbCall(t, srv, "us-east-1", "UpdateItem", `{
		"TableName":"Users",
		"Key":{"id":{"S":"a"}},
		"AttributeUpdates":{"v":{"Action":"PUT","Value":{"N":"2"}}}
	}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "UpdateItem")

	// Verify update applied.
	_, body := ddbCall(t, srv, "us-east-1", "GetItem", `{"TableName":"Users","Key":{"id":{"S":"a"}}}`)
	assert.Contains(t, string(body), `"2"`, "UpdateItem didn't apply: %s", body)
}

func TestCoverage_RDSParameterGroupDescribe(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	rdsCall(t, srv, "us-east-1", "CreateDBParameterGroup", url.Values{
		"DBParameterGroupName": {"pg15"}, "DBParameterGroupFamily": {"postgres15"}, "Description": {"d"},
	})
	rdsCall(t, srv, "us-east-1", "CreateDBClusterParameterGroup", url.Values{
		"DBClusterParameterGroupName": {"aurora-pg"}, "DBParameterGroupFamily": {"aurora-postgresql15"}, "Description": {"d"},
	})
	resp, body := rdsCall(t, srv, "us-east-1", "DescribeDBParameterGroups", url.Values{"DBParameterGroupName": {"pg15"}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DescribeDBParameterGroups status")
	assert.Contains(t, string(body), "pg15", "DescribeDBParameterGroups: %s", body)
	resp, body = rdsCall(t, srv, "us-east-1", "DescribeDBClusterParameterGroups", url.Values{"DBClusterParameterGroupName": {"aurora-pg"}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DescribeDBClusterParameterGroups status")
	assert.Contains(t, string(body), "aurora-pg", "DescribeDBClusterParameterGroups: %s", body)
	rdsCall(t, srv, "us-east-1", "DeleteDBClusterParameterGroup", url.Values{"DBClusterParameterGroupName": {"aurora-pg"}})
}

func TestCoverage_RDSCluster(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"
	_, sa, sb := rdsCreateVPCAndSubnets(t, srv, region)
	rdsCall(t, srv, region, "CreateDBSubnetGroup", url.Values{
		"DBSubnetGroupName":        {"default"},
		"DBSubnetGroupDescription": {"d"},
		"SubnetIds.member.1":       {sa},
		"SubnetIds.member.2":       {sb},
	})
	resp, body := rdsCall(t, srv, region, "CreateDBCluster", url.Values{
		"DBClusterIdentifier": {"aurora-1"}, "Engine": {"aurora-postgresql"},
		"DBSubnetGroupName": {"default"}, "MasterUsername": {"admin"},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateDBCluster: %s", body)
	resp, _ = rdsCall(t, srv, region, "DescribeDBClusters", url.Values{"DBClusterIdentifier": {"aurora-1"}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DescribeDBClusters")
	resp, _ = rdsCall(t, srv, region, "DeleteDBCluster", url.Values{"DBClusterIdentifier": {"aurora-1"}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DeleteDBCluster")
}

func TestCoverage_RDSModifyAndDescribeAll(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"
	_, sa, sb := rdsCreateVPCAndSubnets(t, srv, region)
	rdsCall(t, srv, region, "CreateDBSubnetGroup", url.Values{
		"DBSubnetGroupName":        {"default"},
		"DBSubnetGroupDescription": {"d"},
		"SubnetIds.member.1":       {sa},
		"SubnetIds.member.2":       {sb},
	})
	rdsCall(t, srv, region, "CreateDBInstance", url.Values{
		"DBInstanceIdentifier": {"db1"}, "Engine": {"postgres"},
		"DBInstanceClass": {"db.t3.micro"}, "DBSubnetGroupName": {"default"},
	})

	// ModifyDBInstance.
	resp, _ := rdsCall(t, srv, region, "ModifyDBInstance", url.Values{"DBInstanceIdentifier": {"db1"}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "ModifyDBInstance")
	// ModifyDBInstance on missing → 404.
	resp, _ = rdsCall(t, srv, region, "ModifyDBInstance", url.Values{"DBInstanceIdentifier": {"missing"}})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "ModifyDBInstance missing")

	// DescribeDBSubnetGroups by name.
	resp, body := rdsCall(t, srv, region, "DescribeDBSubnetGroups", url.Values{"DBSubnetGroupName": {"default"}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DescribeDBSubnetGroups status")
	assert.Contains(t, string(body), "default", "DescribeDBSubnetGroups: %s", body)

	// DescribeDBInstances unfiltered (covers ListDBInstances path).
	_, body = rdsCall(t, srv, region, "DescribeDBInstances", nil)
	assert.Contains(t, string(body), "db1", "DescribeDBInstances unfiltered missing db1: %s", body)

	// DeleteDBInstance + DeleteDBSubnetGroup + DeleteDBParameterGroup tail.
	rdsCall(t, srv, region, "DeleteDBInstance", url.Values{"DBInstanceIdentifier": {"db1"}})
	resp, _ = rdsCall(t, srv, region, "DeleteDBSubnetGroup", url.Values{"DBSubnetGroupName": {"default"}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DeleteDBSubnetGroup")
}

func TestCoverage_EKSNodeGroupAndDescribe(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"
	clusterRole, nodeRole, sa, sb := eksSetupPrereqs(t, srv, region)
	eksRequest(t, srv, http.MethodPost, "/eks/region/"+region+"/clusters", `{
		"name":"demo","roleArn":"`+clusterRole+`","resourcesVpcConfig":{"subnetIds":["`+sa+`","`+sb+`"]}
	}`)
	resp, _ := eksRequest(t, srv, http.MethodPost, "/eks/region/"+region+"/clusters/demo/node-groups", `{
		"nodegroupName":"ng1","nodeRole":"`+nodeRole+`","subnets":["`+sa+`"]
	}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateNodeGroup")
	resp, _ = eksRequest(t, srv, http.MethodGet, "/eks/region/"+region+"/clusters/demo/node-groups/ng1", "")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DescribeNodeGroup")
	resp, _ = eksRequest(t, srv, http.MethodDelete, "/eks/region/"+region+"/clusters/demo/node-groups/ng1", "")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DeleteNodeGroup")
}

func TestCoverage_IAMInstanceProfileAndUser(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	// Instance profile lifecycle.
	resp, _ := iamCall(t, srv, "CreateInstanceProfile", url.Values{"InstanceProfileName": {"prof"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateInstanceProfile")
	resp, _ = iamCall(t, srv, "ListInstanceProfiles", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "ListInstanceProfiles")
	resp, _ = iamCall(t, srv, "DeleteInstanceProfile", url.Values{"InstanceProfileName": {"prof"}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DeleteInstanceProfile")

	// User lifecycle.
	resp, _ = iamCall(t, srv, "CreateUser", url.Values{"UserName": {"alice"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateUser")
	resp, body := iamCall(t, srv, "GetUser", url.Values{"UserName": {"alice"}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "GetUser status")
	assert.Contains(t, string(body), "alice", "GetUser: %s", body)
	resp, body = iamCall(t, srv, "ListUsers", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "ListUsers status")
	assert.Contains(t, string(body), "alice", "ListUsers: %s", body)

	// Access key lifecycle.
	resp, body = iamCall(t, srv, "CreateAccessKey", url.Values{"UserName": {"alice"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateAccessKey: %s", body)
	idStart := strings.Index(string(body), "<AccessKeyId>") + len("<AccessKeyId>")
	idEnd := strings.Index(string(body)[idStart:], "</AccessKeyId>") + idStart
	keyID := string(body)[idStart:idEnd]
	resp, _ = iamCall(t, srv, "DeleteAccessKey", url.Values{"UserName": {"alice"}, "AccessKeyId": {keyID}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DeleteAccessKey")
}

// readBody is used by SQS tests in this file. Re-exposing the helper.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	out, _ := io.ReadAll(resp.Body)
	return string(out)
}

func TestCoverage_SQSQueueAttributesAndDelete(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, body := sqsCall(t, srv, "CreateQueue", `{"QueueName":"q","Attributes":{"VisibilityTimeout":"60"}}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateQueue: %s", body)
	urlStart := strings.Index(string(body), `"QueueUrl":"`) + len(`"QueueUrl":"`)
	urlEnd := strings.Index(string(body)[urlStart:], `"`) + urlStart
	queueURL := string(body)[urlStart:urlEnd]

	resp, body = sqsCall(t, srv, "GetQueueAttributes", `{"QueueUrl":"`+queueURL+`"}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "GetQueueAttributes status")
	assert.Contains(t, string(body), "VisibilityTimeout", "GetQueueAttributes: %s", body)

	resp, _ = sqsCall(t, srv, "DeleteQueue", `{"QueueUrl":"`+queueURL+`"}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DeleteQueue")
}

func TestCoverage_SQSDeleteMessage(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, body := sqsCall(t, srv, "CreateQueue", `{"QueueName":"jobs"}`)
	urlStart := strings.Index(string(body), `"QueueUrl":"`) + len(`"QueueUrl":"`)
	urlEnd := strings.Index(string(body)[urlStart:], `"`) + urlStart
	queueURL := string(body)[urlStart:urlEnd]

	sqsCall(t, srv, "SendMessage", `{"QueueUrl":"`+queueURL+`","MessageBody":"x"}`)
	_, rb := sqsCall(t, srv, "ReceiveMessage", `{"QueueUrl":"`+queueURL+`"}`)
	rhStart := strings.Index(string(rb), `"ReceiptHandle":"`) + len(`"ReceiptHandle":"`)
	rhEnd := strings.Index(string(rb)[rhStart:], `"`) + rhStart
	rh := string(rb)[rhStart:rhEnd]
	resp, _ := sqsCall(t, srv, "DeleteMessage", `{"QueueUrl":"`+queueURL+`","ReceiptHandle":"`+rh+`"}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DeleteMessage")
}

func TestCoverage_Route53GetChange(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, body := r53Request(t, srv, http.MethodPost, "/route53/2013-04-01/hostedzone",
		`<CreateHostedZoneRequest><Name>x.invalid.</Name><CallerReference>r</CallerReference></CreateHostedZoneRequest>`)
	idStart := strings.Index(string(body), "<Id>/change/") + len("<Id>/change/")
	idEnd := strings.Index(string(body)[idStart:], "</Id>") + idStart
	changeID := string(body)[idStart:idEnd]
	resp, body := r53Request(t, srv, http.MethodGet, "/route53/2013-04-01/change/"+changeID, "")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "GetChange status")
	assert.Contains(t, string(body), "INSYNC", "GetChange: %s", body)
}

func TestCoverage_SecretsManagerListAndDescribe(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	smCall(t, srv, "CreateSecret", `{"Name":"s","SecretString":"x"}`)
	resp, body := smCall(t, srv, "DescribeSecret", `{"SecretId":"s"}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DescribeSecret status")
	assert.Contains(t, string(body), "s", "DescribeSecret: %s", body)
	resp, body = smCall(t, srv, "ListSecrets", `{}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "ListSecrets status")
	assert.Contains(t, string(body), "s", "ListSecrets: %s", body)
}

// silence unused-import in the few cases readBody isn't called.
var _ = httptest.NewServer
var _ = readBody

// ----- Error-path coverage: exercise the 404 / ErrNotFound branches
// that the success-path tests miss. Each Delete/Describe handler has
// a "missing id" sub-test below.

func TestCoverage_EC2ErrorPaths(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"

	// Most EC2 delete handlers wrap repo errors via WriteAWSError.
	// Hit the ErrNotFound branches.
	for _, op := range []string{
		"DeleteSubnet",
		"DeleteRouteTable",
		"DeleteInternetGateway",
		"DetachInternetGateway",
		"DeleteSecurityGroup",
		"DeleteVpc",
	} {
		params := url.Values{}
		switch op {
		case "DeleteSubnet":
			params.Set("SubnetId", "subnet-x")
		case "DeleteRouteTable":
			params.Set("RouteTableId", "rtb-x")
		case "DeleteInternetGateway", "DetachInternetGateway":
			params.Set("InternetGatewayId", "igw-x")
		case "DeleteSecurityGroup":
			params.Set("GroupId", "sg-x")
		case "DeleteVpc":
			params.Set("VpcId", "vpc-x")
		}
		resp, _ := ec2Call(t, srv, region, op, params)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, "%s missing id", op)
	}

	// CreateRoute on missing route table → 404.
	resp, _ := ec2Call(t, srv, region, "CreateRoute", url.Values{
		"RouteTableId": {"rtb-missing"}, "DestinationCidrBlock": {"0.0.0.0/0"},
	})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "CreateRoute missing rt")

	// DescribeKeyPairs on a missing name → 404.
	resp, _ = ec2Call(t, srv, region, "DescribeKeyPairs", url.Values{"KeyName.1": {"missing"}})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "DescribeKeyPairs missing")

	// DeleteKeyPair on missing → 404.
	resp, _ = ec2Call(t, srv, region, "DeleteKeyPair", url.Values{"KeyName": {"missing"}})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "DeleteKeyPair missing")

	// DescribeSecurityGroups missing GroupId.<n> filter → 409.
	resp, _ = ec2Call(t, srv, region, "DescribeSecurityGroups", nil)
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "DescribeSecurityGroups no filter")

	// Authorize on missing GroupId → 409 (no body).
	resp, _ = ec2Call(t, srv, region, "AuthorizeSecurityGroupIngress", nil)
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "AuthorizeSecurityGroupIngress no GroupId")

	// Authorize with no IpPermissions → 409.
	resp, _ = ec2Call(t, srv, region, "AuthorizeSecurityGroupIngress", url.Values{"GroupId": {"sg-x"}})
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "Authorize no rules")

	// CreateRouteTable missing VpcId → 409.
	resp, _ = ec2Call(t, srv, region, "CreateRouteTable", nil)
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "CreateRouteTable no vpc")

	// AssociateRouteTable missing args → 409.
	resp, _ = ec2Call(t, srv, region, "AssociateRouteTable", nil)
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "AssociateRouteTable no args")

	// DisassociateRouteTable missing → 404.
	resp, _ = ec2Call(t, srv, region, "DisassociateRouteTable", url.Values{"AssociationId": {"missing"}})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "DisassociateRouteTable missing")

	// AllocateAddress with bad domain → 409.
	resp, _ = ec2Call(t, srv, region, "AllocateAddress", url.Values{"Domain": {"standard"}})
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "AllocateAddress bad domain")

	// ReleaseAddress missing → 404.
	resp, _ = ec2Call(t, srv, region, "ReleaseAddress", url.Values{"AllocationId": {"missing"}})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "ReleaseAddress missing")

	// RunInstances missing required fields → 409.
	resp, _ = ec2Call(t, srv, region, "RunInstances", nil)
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "RunInstances no args")

	// TerminateInstances missing InstanceId.<n> → 409.
	resp, _ = ec2Call(t, srv, region, "TerminateInstances", nil)
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "TerminateInstances no ids")

	// ImportKeyPair missing → 409.
	resp, _ = ec2Call(t, srv, region, "ImportKeyPair", nil)
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "ImportKeyPair no args")

	// DescribeImages with unknown ImageId → 404.
	resp, _ = ec2Call(t, srv, region, "DescribeImages", url.Values{"ImageId.1": {"ami-not-real"}})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "DescribeImages unknown")
}

func TestCoverage_DynamoDBErrorPaths(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	// CreateTable missing args → 409.
	resp, _ := ddbCall(t, srv, "us-east-1", "CreateTable", `{}`)
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "CreateTable no args")
	// CreateTable missing HASH → 409.
	resp, _ = ddbCall(t, srv, "us-east-1", "CreateTable", `{"TableName":"t","KeySchema":[]}`)
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "CreateTable no HASH")
	// DeleteTable on missing → 404.
	resp, _ = ddbCall(t, srv, "us-east-1", "DeleteTable", `{"TableName":"missing"}`)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "DeleteTable missing")
	// DeleteItem on missing table → 404.
	resp, _ = ddbCall(t, srv, "us-east-1", "DeleteItem", `{"TableName":"missing","Key":{"id":{"S":"x"}}}`)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "DeleteItem missing table")
	// UpdateItem on missing table → 404.
	resp, _ = ddbCall(t, srv, "us-east-1", "UpdateItem", `{"TableName":"missing","Key":{"id":{"S":"x"}}}`)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "UpdateItem missing table")
}

func TestCoverage_RDSErrorPaths(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, _ := rdsCall(t, srv, "us-east-1", "CreateDBSubnetGroup", url.Values{"DBSubnetGroupName": {"x"}, "DBSubnetGroupDescription": {"d"}})
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "CreateDBSubnetGroup <2 subnets")
	resp, _ = rdsCall(t, srv, "us-east-1", "CreateDBSubnetGroup", nil)
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "CreateDBSubnetGroup empty")
	resp, _ = rdsCall(t, srv, "us-east-1", "DescribeDBSubnetGroups", url.Values{"DBSubnetGroupName": {"missing"}})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "Describe missing subnet group")
	resp, _ = rdsCall(t, srv, "us-east-1", "DescribeDBClusters", url.Values{"DBClusterIdentifier": {"missing"}})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "Describe missing cluster")
	resp, _ = rdsCall(t, srv, "us-east-1", "CreateDBCluster", nil)
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "CreateDBCluster no args")
	resp, _ = rdsCall(t, srv, "us-east-1", "CreateDBInstance", nil)
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "CreateDBInstance no args")
	resp, _ = rdsCall(t, srv, "us-east-1", "DescribeDBInstances", url.Values{"DBInstanceIdentifier": {"missing"}})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "Describe missing instance")
	resp, _ = rdsCall(t, srv, "us-east-1", "BogusOperation", nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "RDS unknown op")
}

func TestCoverage_SQSErrorPaths(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, _ := sqsCall(t, srv, "CreateQueue", `{}`)
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "CreateQueue no name")
	resp, _ = sqsCall(t, srv, "DeleteQueue", `{"QueueUrl":"http://x.fakeaws.local/000000000000/missing"}`)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "DeleteQueue missing")
	resp, _ = sqsCall(t, srv, "GetQueueAttributes", `{"QueueUrl":"http://x.fakeaws.local/000000000000/missing"}`)
	// M68 fix: GetQueueAttributes against a missing queue returns
	// 400 AWS.SimpleQueueService.NonExistentQueue (the service-
	// specific code terraform-provider-aws's delete-wait checks for),
	// not the generic 404 ResourceNotFoundException.
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "GetQueueAttributes missing: want 400 (NonExistentQueue)")
	resp, _ = sqsCall(t, srv, "SendMessage", `{"QueueUrl":"http://x.fakeaws.local/000000000000/missing","MessageBody":"x"}`)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "SendMessage missing")
	resp, _ = sqsCall(t, srv, "ReceiveMessage", `{"QueueUrl":"http://x.fakeaws.local/000000000000/missing"}`)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "ReceiveMessage missing")
}

func TestCoverage_EKSErrorPaths(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"
	// CreateCluster missing required → 409.
	resp, _ := eksRequest(t, srv, http.MethodPost, "/eks/region/"+region+"/clusters", `{"name":"x"}`)
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "CreateCluster missing")
	// Describe missing → 404.
	resp, _ = eksRequest(t, srv, http.MethodGet, "/eks/region/"+region+"/clusters/missing", "")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "DescribeCluster missing")
	resp, _ = eksRequest(t, srv, http.MethodDelete, "/eks/region/"+region+"/clusters/missing", "")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "DeleteCluster missing")
	resp, _ = eksRequest(t, srv, http.MethodPost, "/eks/region/"+region+"/clusters/missing/node-groups", `{"nodegroupName":"x"}`)
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "CreateNodeGroup missing args")
	resp, _ = eksRequest(t, srv, http.MethodGet, "/eks/region/"+region+"/clusters/x/node-groups/missing", "")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "DescribeNodeGroup missing")
	resp, _ = eksRequest(t, srv, http.MethodDelete, "/eks/region/"+region+"/clusters/x/node-groups/missing", "")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "DeleteNodeGroup missing")
	resp, _ = eksRequest(t, srv, http.MethodPost, "/eks/region/"+region+"/clusters/missing/addons", `{}`)
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "CreateAddon empty")
	resp, _ = eksRequest(t, srv, http.MethodGet, "/eks/region/"+region+"/clusters/x/addons/missing", "")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "DescribeAddon missing")
	resp, _ = eksRequest(t, srv, http.MethodDelete, "/eks/region/"+region+"/clusters/x/addons/missing", "")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "DeleteAddon missing")
}

func TestCoverage_Route53ErrorPaths(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, _ := r53Request(t, srv, http.MethodPost, "/route53/2013-04-01/hostedzone",
		`<CreateHostedZoneRequest></CreateHostedZoneRequest>`)
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "CreateHostedZone empty")
	resp, _ = r53Request(t, srv, http.MethodGet, "/route53/2013-04-01/hostedzone/Zmissing", "")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "GetHostedZone missing")
	resp, _ = r53Request(t, srv, http.MethodPost, "/route53/2013-04-01/hostedzone/Zmissing/rrset/",
		`<ChangeResourceRecordSetsRequest><ChangeBatch><Changes></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>`)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "ChangeRRset on missing zone")
	resp, _ = r53Request(t, srv, http.MethodGet, "/route53/2013-04-01/change/missing", "")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "GetChange missing")
}

func TestCoverage_SecretsManagerErrorPaths(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, _ := smCall(t, srv, "CreateSecret", `{}`)
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "CreateSecret empty")
	resp, _ = smCall(t, srv, "GetSecretValue", `{"SecretId":"missing"}`)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "GetSecretValue missing")
	resp, _ = smCall(t, srv, "BogusOp", `{}`)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "Unknown SM op")
}

func TestCoverage_S3OwnershipAndEncryption(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	// PutBucket.
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/s3/test-cov-bucket/", nil)
	req.Header.Set("Content-Type", "application/xml")
	resp, _ := srv.Client().Do(req)
	resp.Body.Close()

	// PutOwnershipControls + GetOwnershipControls.
	body := `<OwnershipControls><Rule><ObjectOwnership>BucketOwnerEnforced</ObjectOwnership></Rule></OwnershipControls>`
	req, _ = http.NewRequest(http.MethodPut, srv.URL+"/s3/test-cov-bucket/?ownershipControls", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/xml")
	resp, _ = srv.Client().Do(req)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "PutOwnershipControls")

	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/s3/test-cov-bucket/?ownershipControls", nil)
	resp, _ = srv.Client().Do(req)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "GetOwnershipControls")

	// PutEncryption + GetEncryption.
	encBody := `<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`
	req, _ = http.NewRequest(http.MethodPut, srv.URL+"/s3/test-cov-bucket/?encryption", strings.NewReader(encBody))
	req.Header.Set("Content-Type", "application/xml")
	resp, _ = srv.Client().Do(req)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "PutEncryption")

	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/s3/test-cov-bucket/?encryption", nil)
	resp, _ = srv.Client().Do(req)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "GetEncryption")
}

func TestCoverage_S3HeadObject(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/s3/cov-head-bucket/", nil)
	resp, _ := srv.Client().Do(req)
	resp.Body.Close()
	// PutObject.
	req, _ = http.NewRequest(http.MethodPut, srv.URL+"/s3/cov-head-bucket/key.txt", strings.NewReader("body"))
	resp, _ = srv.Client().Do(req)
	resp.Body.Close()
	// HeadObject — v1 doesn't store object payloads, so always 404
	// (handler comment: "v1: we don't store objects, so HEAD always 404s").
	req, _ = http.NewRequest(http.MethodHead, srv.URL+"/s3/cov-head-bucket/key.txt", nil)
	resp, _ = srv.Client().Do(req)
	resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "HeadObject v1 contract")
}
