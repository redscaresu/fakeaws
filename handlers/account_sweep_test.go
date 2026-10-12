package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/redscaresu/fakeaws/handlers"
	"github.com/redscaresu/fakeaws/handlers/awsproto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestContract_responses_carry_the_stored_account creates and reads one
// resource per modelled service under a stored account and asserts no
// response body, nor GET /mock/state, carries the default account, and
// that every body naming an account names the stored one.
// TestAccountSourceScan finds the literal in source; this checks the wire.
func TestContract_responses_carry_the_stored_account(t *testing.T) {
	_, srv := newOptionsApp(t, handlers.Options{DBPath: ":memory:", AccountID: otherAccount})
	const region = "us-east-1"
	check := func(call string, namesAccount bool) func(*http.Response, []byte) []byte {
		return func(resp *http.Response, body []byte) []byte {
			t.Helper()
			require.Equal(t, http.StatusOK, resp.StatusCode, "%s: %s", call, body)
			assert.NotContains(t, string(body), awsproto.FakeAccountID, "%s: %s", call, body)
			if namesAccount {
				assert.Contains(t, string(body), otherAccount, "%s: %s", call, body)
			}
			return body
		}
	}
	swept := func(call string) func(*http.Response, []byte) []byte { return check(call, true) }
	// noAccount is for a body that names no account: S3 PutBucket (empty),
	// EC2 CreateSecurityGroup (the group id only), SSM PutParameter
	// (Version and Tier) and all of Route53, whose zone ARNs are
	// account-less. Each is read back below where the service has an
	// account to name.
	noAccount := func(call string) func(*http.Response, []byte) []byte { return check(call, false) }

	swept("IAM CreateRole")(iamCall(t, srv, "CreateRole", url.Values{
		"RoleName": {"sweep"}, "AssumeRolePolicyDocument": {`{"Version":"2012-10-17"}`},
	}))
	roleARN := xmlExtract(swept("IAM GetRole")(iamCall(t, srv, "GetRole", url.Values{"RoleName": {"sweep"}})), "Arn")

	noAccount("S3 PutBucket")(s3Do(t, srv, http.MethodPut, "/s3/sweep/", "", ""))
	swept("S3 ListBuckets")(s3Do(t, srv, http.MethodGet, "/s3/", "", ""))

	vpcID := extractEC2Tag(swept("EC2 CreateVpc")(ec2Call(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})), "vpcId")
	swept("EC2 DescribeVpcs")(ec2Call(t, srv, region, "DescribeVpcs", url.Values{"VpcId.1": {vpcID}}))
	var subnets []string
	for _, s := range []struct{ az, cidr string }{{"a", "10.0.1.0/24"}, {"b", "10.0.2.0/24"}} {
		body := swept("EC2 CreateSubnet")(ec2Call(t, srv, region, "CreateSubnet", url.Values{
			"VpcId": {vpcID}, "CidrBlock": {s.cidr}, "AvailabilityZone": {region + s.az},
		}))
		subnets = append(subnets, extractEC2Tag(body, "subnetId"))
	}
	swept("EC2 DescribeSubnets")(ec2Call(t, srv, region, "DescribeSubnets", url.Values{"SubnetId.1": {subnets[0]}}))
	sgID := extractEC2Tag(noAccount("EC2 CreateSecurityGroup")(ec2Call(t, srv, region, "CreateSecurityGroup", url.Values{
		"GroupName": {"sweep"}, "GroupDescription": {"sweep"}, "VpcId": {vpcID},
	})), "groupId")
	swept("EC2 DescribeSecurityGroups")(ec2Call(t, srv, region, "DescribeSecurityGroups", url.Values{"GroupId.1": {sgID}}))
	instID := extractEC2Tag(swept("EC2 RunInstances")(ec2Call(t, srv, region, "RunInstances", topLevelParams(subnets[0], []string{sgID}))), "instanceId")
	swept("EC2 DescribeInstances")(ec2Call(t, srv, region, "DescribeInstances", url.Values{"InstanceId.1": {instID}}))

	swept("RDS CreateDBSubnetGroup")(rdsCall(t, srv, region, "CreateDBSubnetGroup", url.Values{
		"DBSubnetGroupName": {"sweep"}, "DBSubnetGroupDescription": {"d"},
		"SubnetIds.member.1": {subnets[0]}, "SubnetIds.member.2": {subnets[1]},
	}))
	swept("RDS CreateDBInstance")(rdsCall(t, srv, region, "CreateDBInstance", url.Values{
		"DBInstanceIdentifier": {"sweep"}, "Engine": {"postgres"},
		"DBInstanceClass": {"db.t3.micro"}, "DBSubnetGroupName": {"sweep"},
	}))
	swept("RDS DescribeDBInstances")(rdsCall(t, srv, region, "DescribeDBInstances", url.Values{"DBInstanceIdentifier": {"sweep"}}))

	swept("DynamoDB CreateTable")(ddbCall(t, srv, region, "CreateTable", `{"TableName":"sweep",
		"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],
		"KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"BillingMode":"PAY_PER_REQUEST"}`))
	swept("DynamoDB DescribeTable")(ddbCall(t, srv, region, "DescribeTable", `{"TableName":"sweep"}`))

	swept("EKS CreateCluster")(eksRequest(t, srv, http.MethodPost, "/eks/region/"+region+"/clusters",
		`{"name":"sweep","roleArn":"`+roleARN+`","resourcesVpcConfig":{"subnetIds":["`+subnets[0]+`","`+subnets[1]+`"]}}`))
	swept("EKS DescribeCluster")(eksRequest(t, srv, http.MethodGet, "/eks/region/"+region+"/clusters/sweep", ""))

	var queue struct{ QueueUrl string }
	require.NoError(t, json.Unmarshal(swept("SQS CreateQueue")(sqsCall(t, srv, "CreateQueue", `{"QueueName":"sweep"}`)), &queue))
	swept("SQS GetQueueAttributes")(sqsCall(t, srv, "GetQueueAttributes", `{"QueueUrl":"`+queue.QueueUrl+`","AttributeNames":["All"]}`))

	zone := noAccount("Route53 CreateHostedZone")(r53Request(t, srv, http.MethodPost, "/route53/2013-04-01/hostedzone",
		`<CreateHostedZoneRequest><Name>sweep.example.</Name><CallerReference>sweep</CallerReference></CreateHostedZoneRequest>`))
	zoneID := strings.TrimPrefix(xmlExtract(zone, "Id"), "/hostedzone/")
	noAccount("Route53 GetHostedZone")(r53Request(t, srv, http.MethodGet, "/route53/2013-04-01/hostedzone/"+zoneID, ""))

	swept("Secrets Manager CreateSecret")(smCall(t, srv, "CreateSecret", `{"Name":"sweep","SecretString":"s"}`))
	swept("Secrets Manager DescribeSecret")(smCall(t, srv, "DescribeSecret", `{"SecretId":"sweep"}`))

	var key struct{ KeyMetadata struct{ KeyId string } }
	require.NoError(t, json.Unmarshal(swept("KMS CreateKey")(kmsCall(t, srv, region, "CreateKey", `{}`)), &key))
	swept("KMS DescribeKey")(kmsCall(t, srv, region, "DescribeKey", `{"KeyId":"`+key.KeyMetadata.KeyId+`"}`))
	swept("KMS ListKeys")(kmsCall(t, srv, region, "ListKeys", `{}`))
	swept("KMS GetKeyPolicy")(kmsCall(t, srv, region, "GetKeyPolicy", `{"KeyId":"`+key.KeyMetadata.KeyId+`","PolicyName":"default"}`))

	noAccount("SSM PutParameter")(ssmCall(t, srv, "PutParameter", `{"Name":"/sweep","Type":"String","Value":"v"}`))
	swept("SSM GetParameter")(ssmCall(t, srv, "GetParameter", `{"Name":"/sweep"}`))

	swept("STS GetCallerIdentity")(stsCall(t, srv, "GetCallerIdentity"))

	// Each gathered block whose rows hold an account must name the stored
	// one. S3's and Route53's ARNs are account-less and SSM's block holds
	// no ARN.
	var state map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(swept("GET /mock/state")(doGet(t, srv, "/mock/state")), &state))
	for _, service := range []string{"iam", "ec2", "rds", "dynamodb", "eks", "sqs", "secretsmanager", "kms"} {
		assert.Contains(t, string(state[service]), otherAccount, "/mock/state %s: %s", service, state[service])
	}
}
