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
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DeleteSubnet: %d", resp.StatusCode)
	}
	// DeleteRouteTable.
	resp, _ = ec2Call(t, srv, region, "DeleteRouteTable", url.Values{"RouteTableId": {rtbID}})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DeleteRouteTable: %d", resp.StatusCode)
	}
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
	if resp.StatusCode != http.StatusOK {
		t.Errorf("ModifyInstanceAttribute: %d", resp.StatusCode)
	}

	// Missing instance → 404.
	resp, _ = ec2Call(t, srv, region, "ModifyInstanceAttribute", url.Values{"InstanceId": {"i-missing"}})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("ModifyInstanceAttribute missing: %d, want 404", resp.StatusCode)
	}
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
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DetachInternetGateway: %d", resp.StatusCode)
	}
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
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DeleteRoute: %d", resp.StatusCode)
	}
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
	if resp.StatusCode != http.StatusOK {
		t.Errorf("UpdateItem: %d", resp.StatusCode)
	}

	// Verify update applied.
	_, body := ddbCall(t, srv, "us-east-1", "GetItem", `{"TableName":"Users","Key":{"id":{"S":"a"}}}`)
	if !strings.Contains(string(body), `"2"`) {
		t.Errorf("UpdateItem didn't apply: %s", body)
	}
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
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "pg15") {
		t.Errorf("DescribeDBParameterGroups: %s", body)
	}
	resp, body = rdsCall(t, srv, "us-east-1", "DescribeDBClusterParameterGroups", url.Values{"DBClusterParameterGroupName": {"aurora-pg"}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "aurora-pg") {
		t.Errorf("DescribeDBClusterParameterGroups: %s", body)
	}
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
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateDBCluster: %d %s", resp.StatusCode, body)
	}
	resp, _ = rdsCall(t, srv, region, "DescribeDBClusters", url.Values{"DBClusterIdentifier": {"aurora-1"}})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DescribeDBClusters: %d", resp.StatusCode)
	}
	resp, _ = rdsCall(t, srv, region, "DeleteDBCluster", url.Values{"DBClusterIdentifier": {"aurora-1"}})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DeleteDBCluster: %d", resp.StatusCode)
	}
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
	if resp.StatusCode != http.StatusOK {
		t.Errorf("ModifyDBInstance: %d", resp.StatusCode)
	}
	// ModifyDBInstance on missing → 404.
	resp, _ = rdsCall(t, srv, region, "ModifyDBInstance", url.Values{"DBInstanceIdentifier": {"missing"}})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("ModifyDBInstance missing: %d", resp.StatusCode)
	}

	// DescribeDBSubnetGroups by name.
	resp, body := rdsCall(t, srv, region, "DescribeDBSubnetGroups", url.Values{"DBSubnetGroupName": {"default"}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "default") {
		t.Errorf("DescribeDBSubnetGroups: %s", body)
	}

	// DescribeDBInstances unfiltered (covers ListDBInstances path).
	_, body = rdsCall(t, srv, region, "DescribeDBInstances", nil)
	if !strings.Contains(string(body), "db1") {
		t.Errorf("DescribeDBInstances unfiltered missing db1: %s", body)
	}

	// DeleteDBInstance + DeleteDBSubnetGroup + DeleteDBParameterGroup tail.
	rdsCall(t, srv, region, "DeleteDBInstance", url.Values{"DBInstanceIdentifier": {"db1"}})
	resp, _ = rdsCall(t, srv, region, "DeleteDBSubnetGroup", url.Values{"DBSubnetGroupName": {"default"}})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DeleteDBSubnetGroup: %d", resp.StatusCode)
	}
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
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateNodeGroup: %d", resp.StatusCode)
	}
	resp, _ = eksRequest(t, srv, http.MethodGet, "/eks/region/"+region+"/clusters/demo/node-groups/ng1", "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DescribeNodeGroup: %d", resp.StatusCode)
	}
	resp, _ = eksRequest(t, srv, http.MethodDelete, "/eks/region/"+region+"/clusters/demo/node-groups/ng1", "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DeleteNodeGroup: %d", resp.StatusCode)
	}
}

func TestCoverage_IAMInstanceProfileAndUser(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	// Instance profile lifecycle.
	resp, _ := iamCall(t, srv, "CreateInstanceProfile", url.Values{"InstanceProfileName": {"prof"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateInstanceProfile: %d", resp.StatusCode)
	}
	resp, _ = iamCall(t, srv, "ListInstanceProfiles", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("ListInstanceProfiles: %d", resp.StatusCode)
	}
	resp, _ = iamCall(t, srv, "DeleteInstanceProfile", url.Values{"InstanceProfileName": {"prof"}})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DeleteInstanceProfile: %d", resp.StatusCode)
	}

	// User lifecycle.
	resp, _ = iamCall(t, srv, "CreateUser", url.Values{"UserName": {"alice"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateUser: %d", resp.StatusCode)
	}
	resp, body := iamCall(t, srv, "GetUser", url.Values{"UserName": {"alice"}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "alice") {
		t.Errorf("GetUser: %s", body)
	}
	resp, body = iamCall(t, srv, "ListUsers", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "alice") {
		t.Errorf("ListUsers: %s", body)
	}

	// Access key lifecycle.
	resp, body = iamCall(t, srv, "CreateAccessKey", url.Values{"UserName": {"alice"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateAccessKey: %d %s", resp.StatusCode, body)
	}
	idStart := strings.Index(string(body), "<AccessKeyId>") + len("<AccessKeyId>")
	idEnd := strings.Index(string(body)[idStart:], "</AccessKeyId>") + idStart
	keyID := string(body)[idStart:idEnd]
	resp, _ = iamCall(t, srv, "DeleteAccessKey", url.Values{"UserName": {"alice"}, "AccessKeyId": {keyID}})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DeleteAccessKey: %d", resp.StatusCode)
	}
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
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateQueue: %d %s", resp.StatusCode, body)
	}
	urlStart := strings.Index(string(body), `"QueueUrl":"`) + len(`"QueueUrl":"`)
	urlEnd := strings.Index(string(body)[urlStart:], `"`) + urlStart
	queueURL := string(body)[urlStart:urlEnd]

	resp, body = sqsCall(t, srv, "GetQueueAttributes", `{"QueueUrl":"`+queueURL+`"}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "VisibilityTimeout") {
		t.Errorf("GetQueueAttributes: %s", body)
	}

	resp, _ = sqsCall(t, srv, "DeleteQueue", `{"QueueUrl":"`+queueURL+`"}`)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DeleteQueue: %d", resp.StatusCode)
	}
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
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DeleteMessage: %d", resp.StatusCode)
	}
}

func TestCoverage_Route53GetChange(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, body := r53Request(t, srv, http.MethodPost, "/route53/2013-04-01/hostedzone",
		`<CreateHostedZoneRequest><Name>x.invalid.</Name><CallerReference>r</CallerReference></CreateHostedZoneRequest>`)
	idStart := strings.Index(string(body), "<Id>/change/") + len("<Id>/change/")
	idEnd := strings.Index(string(body)[idStart:], "</Id>") + idStart
	changeID := string(body)[idStart:idEnd]
	resp, body := r53Request(t, srv, http.MethodGet, "/route53/2013-04-01/change/"+changeID, "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "INSYNC") {
		t.Errorf("GetChange: %s", body)
	}
}

func TestCoverage_SecretsManagerListAndDescribe(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	smCall(t, srv, "CreateSecret", `{"Name":"s","SecretString":"x"}`)
	resp, body := smCall(t, srv, "DescribeSecret", `{"SecretId":"s"}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "s") {
		t.Errorf("DescribeSecret: %s", body)
	}
	resp, body = smCall(t, srv, "ListSecrets", `{}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "s") {
		t.Errorf("ListSecrets: %s", body)
	}
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
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s missing id: got %d, want 404", op, resp.StatusCode)
		}
	}

	// CreateRoute on missing route table → 404.
	resp, _ := ec2Call(t, srv, region, "CreateRoute", url.Values{
		"RouteTableId": {"rtb-missing"}, "DestinationCidrBlock": {"0.0.0.0/0"},
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("CreateRoute missing rt: %d", resp.StatusCode)
	}

	// DescribeKeyPairs on a missing name → 404.
	resp, _ = ec2Call(t, srv, region, "DescribeKeyPairs", url.Values{"KeyName.1": {"missing"}})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("DescribeKeyPairs missing: %d", resp.StatusCode)
	}

	// DeleteKeyPair on missing → 404.
	resp, _ = ec2Call(t, srv, region, "DeleteKeyPair", url.Values{"KeyName": {"missing"}})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("DeleteKeyPair missing: %d", resp.StatusCode)
	}

	// DescribeSecurityGroups missing GroupId.<n> filter → 409.
	resp, _ = ec2Call(t, srv, region, "DescribeSecurityGroups", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("DescribeSecurityGroups no filter: %d", resp.StatusCode)
	}

	// Authorize on missing GroupId → 409 (no body).
	resp, _ = ec2Call(t, srv, region, "AuthorizeSecurityGroupIngress", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("AuthorizeSecurityGroupIngress no GroupId: %d", resp.StatusCode)
	}

	// Authorize with no IpPermissions → 409.
	resp, _ = ec2Call(t, srv, region, "AuthorizeSecurityGroupIngress", url.Values{"GroupId": {"sg-x"}})
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("Authorize no rules: %d", resp.StatusCode)
	}

	// CreateRouteTable missing VpcId → 409.
	resp, _ = ec2Call(t, srv, region, "CreateRouteTable", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("CreateRouteTable no vpc: %d", resp.StatusCode)
	}

	// AssociateRouteTable missing args → 409.
	resp, _ = ec2Call(t, srv, region, "AssociateRouteTable", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("AssociateRouteTable no args: %d", resp.StatusCode)
	}

	// DisassociateRouteTable missing → 404.
	resp, _ = ec2Call(t, srv, region, "DisassociateRouteTable", url.Values{"AssociationId": {"missing"}})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("DisassociateRouteTable missing: %d", resp.StatusCode)
	}

	// AllocateAddress with bad domain → 409.
	resp, _ = ec2Call(t, srv, region, "AllocateAddress", url.Values{"Domain": {"standard"}})
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("AllocateAddress bad domain: %d", resp.StatusCode)
	}

	// ReleaseAddress missing → 404.
	resp, _ = ec2Call(t, srv, region, "ReleaseAddress", url.Values{"AllocationId": {"missing"}})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("ReleaseAddress missing: %d", resp.StatusCode)
	}

	// RunInstances missing required fields → 409.
	resp, _ = ec2Call(t, srv, region, "RunInstances", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("RunInstances no args: %d", resp.StatusCode)
	}

	// TerminateInstances missing InstanceId.<n> → 409.
	resp, _ = ec2Call(t, srv, region, "TerminateInstances", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("TerminateInstances no ids: %d", resp.StatusCode)
	}

	// ImportKeyPair missing → 409.
	resp, _ = ec2Call(t, srv, region, "ImportKeyPair", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("ImportKeyPair no args: %d", resp.StatusCode)
	}

	// DescribeImages with unknown ImageId → 404.
	resp, _ = ec2Call(t, srv, region, "DescribeImages", url.Values{"ImageId.1": {"ami-not-real"}})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("DescribeImages unknown: %d", resp.StatusCode)
	}
}

func TestCoverage_DynamoDBErrorPaths(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	// CreateTable missing args → 409.
	resp, _ := ddbCall(t, srv, "us-east-1", "CreateTable", `{}`)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("CreateTable no args: %d", resp.StatusCode)
	}
	// CreateTable missing HASH → 409.
	resp, _ = ddbCall(t, srv, "us-east-1", "CreateTable", `{"TableName":"t","KeySchema":[]}`)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("CreateTable no HASH: %d", resp.StatusCode)
	}
	// DeleteTable on missing → 404.
	resp, _ = ddbCall(t, srv, "us-east-1", "DeleteTable", `{"TableName":"missing"}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("DeleteTable missing: %d", resp.StatusCode)
	}
	// DeleteItem on missing table → 404.
	resp, _ = ddbCall(t, srv, "us-east-1", "DeleteItem", `{"TableName":"missing","Key":{"id":{"S":"x"}}}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("DeleteItem missing table: %d", resp.StatusCode)
	}
	// UpdateItem on missing table → 404.
	resp, _ = ddbCall(t, srv, "us-east-1", "UpdateItem", `{"TableName":"missing","Key":{"id":{"S":"x"}}}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("UpdateItem missing table: %d", resp.StatusCode)
	}
}

func TestCoverage_RDSErrorPaths(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, _ := rdsCall(t, srv, "us-east-1", "CreateDBSubnetGroup", url.Values{"DBSubnetGroupName": {"x"}, "DBSubnetGroupDescription": {"d"}})
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("CreateDBSubnetGroup <2 subnets: %d", resp.StatusCode)
	}
	resp, _ = rdsCall(t, srv, "us-east-1", "CreateDBSubnetGroup", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("CreateDBSubnetGroup empty: %d", resp.StatusCode)
	}
	resp, _ = rdsCall(t, srv, "us-east-1", "DescribeDBSubnetGroups", url.Values{"DBSubnetGroupName": {"missing"}})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Describe missing subnet group: %d", resp.StatusCode)
	}
	resp, _ = rdsCall(t, srv, "us-east-1", "DescribeDBClusters", url.Values{"DBClusterIdentifier": {"missing"}})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Describe missing cluster: %d", resp.StatusCode)
	}
	resp, _ = rdsCall(t, srv, "us-east-1", "CreateDBCluster", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("CreateDBCluster no args: %d", resp.StatusCode)
	}
	resp, _ = rdsCall(t, srv, "us-east-1", "CreateDBInstance", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("CreateDBInstance no args: %d", resp.StatusCode)
	}
	resp, _ = rdsCall(t, srv, "us-east-1", "DescribeDBInstances", url.Values{"DBInstanceIdentifier": {"missing"}})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Describe missing instance: %d", resp.StatusCode)
	}
	resp, _ = rdsCall(t, srv, "us-east-1", "BogusOperation", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("RDS unknown op: %d", resp.StatusCode)
	}
}

func TestCoverage_SQSErrorPaths(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, _ := sqsCall(t, srv, "CreateQueue", `{}`)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("CreateQueue no name: %d", resp.StatusCode)
	}
	resp, _ = sqsCall(t, srv, "DeleteQueue", `{"QueueUrl":"http://x.fakeaws.local/000000000000/missing"}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("DeleteQueue missing: %d", resp.StatusCode)
	}
	resp, _ = sqsCall(t, srv, "GetQueueAttributes", `{"QueueUrl":"http://x.fakeaws.local/000000000000/missing"}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GetQueueAttributes missing: %d", resp.StatusCode)
	}
	resp, _ = sqsCall(t, srv, "SendMessage", `{"QueueUrl":"http://x.fakeaws.local/000000000000/missing","MessageBody":"x"}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("SendMessage missing: %d", resp.StatusCode)
	}
	resp, _ = sqsCall(t, srv, "ReceiveMessage", `{"QueueUrl":"http://x.fakeaws.local/000000000000/missing"}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("ReceiveMessage missing: %d", resp.StatusCode)
	}
}

func TestCoverage_EKSErrorPaths(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"
	// CreateCluster missing required → 409.
	resp, _ := eksRequest(t, srv, http.MethodPost, "/eks/region/"+region+"/clusters", `{"name":"x"}`)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("CreateCluster missing: %d", resp.StatusCode)
	}
	// Describe missing → 404.
	resp, _ = eksRequest(t, srv, http.MethodGet, "/eks/region/"+region+"/clusters/missing", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("DescribeCluster missing: %d", resp.StatusCode)
	}
	resp, _ = eksRequest(t, srv, http.MethodDelete, "/eks/region/"+region+"/clusters/missing", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("DeleteCluster missing: %d", resp.StatusCode)
	}
	resp, _ = eksRequest(t, srv, http.MethodPost, "/eks/region/"+region+"/clusters/missing/node-groups", `{"nodegroupName":"x"}`)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("CreateNodeGroup missing args: %d", resp.StatusCode)
	}
	resp, _ = eksRequest(t, srv, http.MethodGet, "/eks/region/"+region+"/clusters/x/node-groups/missing", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("DescribeNodeGroup missing: %d", resp.StatusCode)
	}
	resp, _ = eksRequest(t, srv, http.MethodDelete, "/eks/region/"+region+"/clusters/x/node-groups/missing", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("DeleteNodeGroup missing: %d", resp.StatusCode)
	}
	resp, _ = eksRequest(t, srv, http.MethodPost, "/eks/region/"+region+"/clusters/missing/addons", `{}`)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("CreateAddon empty: %d", resp.StatusCode)
	}
	resp, _ = eksRequest(t, srv, http.MethodGet, "/eks/region/"+region+"/clusters/x/addons/missing", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("DescribeAddon missing: %d", resp.StatusCode)
	}
	resp, _ = eksRequest(t, srv, http.MethodDelete, "/eks/region/"+region+"/clusters/x/addons/missing", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("DeleteAddon missing: %d", resp.StatusCode)
	}
}

func TestCoverage_Route53ErrorPaths(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, _ := r53Request(t, srv, http.MethodPost, "/route53/2013-04-01/hostedzone",
		`<CreateHostedZoneRequest></CreateHostedZoneRequest>`)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("CreateHostedZone empty: %d", resp.StatusCode)
	}
	resp, _ = r53Request(t, srv, http.MethodGet, "/route53/2013-04-01/hostedzone/Zmissing", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GetHostedZone missing: %d", resp.StatusCode)
	}
	resp, _ = r53Request(t, srv, http.MethodPost, "/route53/2013-04-01/hostedzone/Zmissing/rrset/",
		`<ChangeResourceRecordSetsRequest><ChangeBatch><Changes></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>`)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("ChangeRRset on missing zone: %d", resp.StatusCode)
	}
	resp, _ = r53Request(t, srv, http.MethodGet, "/route53/2013-04-01/change/missing", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GetChange missing: %d", resp.StatusCode)
	}
}

func TestCoverage_SecretsManagerErrorPaths(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, _ := smCall(t, srv, "CreateSecret", `{}`)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("CreateSecret empty: %d", resp.StatusCode)
	}
	resp, _ = smCall(t, srv, "GetSecretValue", `{"SecretId":"missing"}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GetSecretValue missing: %d", resp.StatusCode)
	}
	resp, _ = smCall(t, srv, "BogusOp", `{}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Unknown SM op: %d", resp.StatusCode)
	}
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
	if resp.StatusCode != http.StatusOK {
		t.Errorf("PutOwnershipControls: %d", resp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/s3/test-cov-bucket/?ownershipControls", nil)
	resp, _ = srv.Client().Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GetOwnershipControls: %d", resp.StatusCode)
	}

	// PutEncryption + GetEncryption.
	encBody := `<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>`
	req, _ = http.NewRequest(http.MethodPut, srv.URL+"/s3/test-cov-bucket/?encryption", strings.NewReader(encBody))
	req.Header.Set("Content-Type", "application/xml")
	resp, _ = srv.Client().Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("PutEncryption: %d", resp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/s3/test-cov-bucket/?encryption", nil)
	resp, _ = srv.Client().Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GetEncryption: %d", resp.StatusCode)
	}
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
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("HeadObject v1 contract: got %d, want 404", resp.StatusCode)
	}
}
