package handlers_test

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestARNsAtDefaultAccount creates one resource per ARN-builder call
// site and pins each emitted ARN to the default account 000000000000.
// IAM tag ops and SQS tag ops build ARNs only as tag keys; their
// round-trip tests (TestIAM_TagsRoundTrip, TestSQS_TagsRoundTrip) fail
// if those ARNs drift from the ones built at create.
func TestARNsAtDefaultAccount(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"
	clusterRole, nodeRole, subnetA, subnetB := eksSetupPrereqs(t, srv, region)
	vpcID := extractEC2Tag(mustOK(t)(ec2Call(t, srv, region, "DescribeSubnets", url.Values{"SubnetId.1": {subnetA}})), "vpcId")

	mustOK(t)(iamCall(t, srv, "CreatePolicy", url.Values{"PolicyName": {"arn-default"}, "PolicyDocument": {`{"Version":"2012-10-17"}`}}))
	mustOK(t)(iamCall(t, srv, "CreateInstanceProfile", url.Values{"InstanceProfileName": {"arn-default"}}))
	mustOK(t)(iamCall(t, srv, "CreateUser", url.Values{"UserName": {"arn-default"}}))

	igwID := extractEC2Tag(mustOK(t)(ec2Call(t, srv, region, "CreateInternetGateway", nil)), "internetGatewayId")
	rtbID := extractEC2Tag(mustOK(t)(ec2Call(t, srv, region, "CreateRouteTable", url.Values{"VpcId": {vpcID}})), "routeTableId")
	sgID := extractEC2Tag(mustOK(t)(ec2Call(t, srv, region, "CreateSecurityGroup", url.Values{
		"GroupName": {"arn-default"}, "GroupDescription": {"d"}, "VpcId": {vpcID},
	})), "groupId")
	eipID := extractEC2Tag(mustOK(t)(ec2Call(t, srv, region, "AllocateAddress", url.Values{"Domain": {"vpc"}})), "allocationId")
	instanceID := runInstance(t, srv, region, url.Values{
		"ImageId": {"ami-0abcd1234"}, "InstanceType": {"t3.micro"}, "SubnetId": {subnetA},
		"IamInstanceProfile.Name": {"arn-default"},
	})

	mustOK(t)(rdsCall(t, srv, region, "CreateDBSubnetGroup", url.Values{
		"DBSubnetGroupName": {"arn-default"}, "DBSubnetGroupDescription": {"d"},
		"SubnetIds.member.1": {subnetA}, "SubnetIds.member.2": {subnetB},
	}))
	mustOK(t)(rdsCall(t, srv, region, "CreateDBParameterGroup", url.Values{
		"DBParameterGroupName": {"arn-default"}, "DBParameterGroupFamily": {"postgres15"}, "Description": {"d"},
	}))
	mustOK(t)(rdsCall(t, srv, region, "CreateDBClusterParameterGroup", url.Values{
		"DBClusterParameterGroupName": {"arn-default"}, "DBParameterGroupFamily": {"aurora-postgresql15"}, "Description": {"d"},
	}))
	mustOK(t)(rdsCall(t, srv, region, "CreateDBCluster", url.Values{"DBClusterIdentifier": {"arn-default"}, "Engine": {"aurora-postgresql"}}))
	mustOK(t)(rdsCall(t, srv, region, "CreateDBInstance", url.Values{
		"DBInstanceIdentifier": {"arn-default"}, "Engine": {"postgres"},
		"DBInstanceClass": {"db.t3.micro"}, "DBSubnetGroupName": {"arn-default"},
	}))

	mustOK(t)(eksRequest(t, srv, http.MethodPost, "/eks/region/"+region+"/clusters",
		`{"name":"arn-default","roleArn":"`+clusterRole+`","resourcesVpcConfig":{"subnetIds":["`+subnetA+`","`+subnetB+`"]}}`))
	mustOK(t)(eksRequest(t, srv, http.MethodPost, "/eks/region/"+region+"/clusters/arn-default/node-groups",
		`{"nodegroupName":"ng","nodeRole":"`+nodeRole+`","subnets":["`+subnetA+`"]}`))

	mustOK(t)(sqsCall(t, srv, "CreateQueue", `{"QueueName":"arn-default"}`))
	mustOK(t)(ddbCall(t, srv, region, "CreateTable", `{"TableName":"arn-default",
		"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],
		"KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"BillingMode":"PAY_PER_REQUEST"}`))
	var secret struct{ ARN string }
	require.NoError(t, json.Unmarshal(mustOK(t)(smCall(t, srv, "CreateSecret", `{"Name":"arn-default","SecretString":"s"}`)), &secret))

	stateARNs := arnsIn(t, srv)
	for _, want := range []string{
		"arn:aws:iam::000000000000:role/eks-cluster-role",
		"arn:aws:iam::000000000000:policy/arn-default",
		"arn:aws:iam::000000000000:instance-profile/arn-default",
		"arn:aws:iam::000000000000:user/arn-default",
		"arn:aws:ec2:us-east-1:000000000000:vpc/" + vpcID,
		"arn:aws:ec2:us-east-1:000000000000:subnet/" + subnetA,
		"arn:aws:ec2:us-east-1:000000000000:internet-gateway/" + igwID,
		"arn:aws:ec2:us-east-1:000000000000:route-table/" + rtbID,
		"arn:aws:ec2:us-east-1:000000000000:security-group/" + sgID,
		"arn:aws:ec2:us-east-1:000000000000:instance/" + instanceID,
		"arn:aws:ec2:us-east-1:000000000000:elastic-ip/" + eipID,
		"arn:aws:rds:us-east-1:000000000000:subgrp:arn-default",
		"arn:aws:rds:us-east-1:000000000000:pg:arn-default",
		"arn:aws:rds:us-east-1:000000000000:cluster-pg:arn-default",
		"arn:aws:rds:us-east-1:000000000000:cluster:arn-default",
		"arn:aws:rds:us-east-1:000000000000:db:arn-default",
		"arn:aws:eks:us-east-1:000000000000:cluster/arn-default",
		"arn:aws:eks:us-east-1:000000000000:nodegroup/arn-default/ng/deterministic",
		"arn:aws:sqs:us-east-1:000000000000:arn-default",
		"arn:aws:dynamodb:us-east-1:000000000000:table/arn-default",
	} {
		assert.Contains(t, stateARNs, want, "/mock/state ARNs")
	}
	assert.Regexp(t, `^arn:aws:secretsmanager:us-east-1:000000000000:secret:arn-default-[A-Za-z0-9]{6}$`, secret.ARN)

	var inst struct {
		ProfileARN string `xml:"reservationSet>item>instancesSet>item>iamInstanceProfile>arn"`
	}
	require.NoError(t, xml.Unmarshal(mustOK(t)(ec2Call(t, srv, region, "DescribeInstances", url.Values{"InstanceId.1": {instanceID}})), &inst))
	assert.Equal(t, "arn:aws:iam::000000000000:instance-profile/arn-default", inst.ProfileARN, "DescribeInstances iamInstanceProfile")

	var caller struct {
		Arn string `xml:"GetCallerIdentityResult>Arn"`
	}
	require.NoError(t, xml.Unmarshal(mustOK(t)(stsCall(t, srv, "GetCallerIdentity")), &caller))
	assert.Equal(t, "arn:aws:iam::000000000000:user/fakeaws", caller.Arn, "GetCallerIdentity")
}

// mustOK fails the test unless a helper call answered 200, and returns
// its body.
func mustOK(t *testing.T) func(*http.Response, []byte) []byte {
	return func(resp *http.Response, body []byte) []byte {
		t.Helper()
		require.Equal(t, http.StatusOK, resp.StatusCode, "%s", body)
		return body
	}
}

// arnsIn returns every "arn" value anywhere in /mock/state.
func arnsIn(t *testing.T, srv *httptest.Server) []string {
	t.Helper()
	var state any
	require.NoError(t, json.Unmarshal(mustOK(t)(doGet(t, srv, "/mock/state")), &state))
	var out []string
	var walk func(any)
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			for k, child := range v {
				if s, ok := child.(string); ok && k == "arn" {
					out = append(out, s)
				}
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(state)
	return out
}
