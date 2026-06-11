package handlers_test

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

const rdsVersion = "2014-10-31"

func rdsCall(t *testing.T, srv *httptest.Server, region, action string, params url.Values) (*http.Response, []byte) {
	t.Helper()
	if params == nil {
		params = url.Values{}
	}
	params.Set("Action", action)
	params.Set("Version", rdsVersion)
	path := "/rds/region/" + region
	req, _ := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err, "POST %s %s", path, action)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

// rdsCreateVPCAndSubnets is a helper — every RDS test needs an EC2
// VPC + 2 subnets to back the DBSubnetGroup.
func rdsCreateVPCAndSubnets(t *testing.T, srv *httptest.Server, region string) (vpcID string, subnetA, subnetB string) {
	t.Helper()
	_, body := ec2Call(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
	vpcID = extractEC2Tag(body, "vpcId")
	_, body = ec2Call(t, srv, region, "CreateSubnet", url.Values{
		"VpcId": {vpcID}, "CidrBlock": {"10.0.1.0/24"}, "AvailabilityZone": {region + "a"},
	})
	subnetA = extractEC2Tag(body, "subnetId")
	_, body = ec2Call(t, srv, region, "CreateSubnet", url.Values{
		"VpcId": {vpcID}, "CidrBlock": {"10.0.2.0/24"}, "AvailabilityZone": {region + "b"},
	})
	subnetB = extractEC2Tag(body, "subnetId")
	return vpcID, subnetA, subnetB
}

func TestRDS_DBSubnetGroupCRUD(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"
	_, sa, sb := rdsCreateVPCAndSubnets(t, srv, region)

	resp, body := rdsCall(t, srv, region, "CreateDBSubnetGroup", url.Values{
		"DBSubnetGroupName":        {"default"},
		"DBSubnetGroupDescription": {"default subnet group"},
		"SubnetIds.member.1":       {sa},
		"SubnetIds.member.2":       {sb},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateDBSubnetGroup: %s", body)
	assert.Contains(t, string(body), "<DBSubnetGroupName>default</DBSubnetGroupName>", "CreateDBSubnetGroup body missing name: %s", body)

	// Single subnet → ErrConflict (≥2 required).
	resp, _ = rdsCall(t, srv, region, "CreateDBSubnetGroup", url.Values{
		"DBSubnetGroupName":        {"x"},
		"DBSubnetGroupDescription": {"x"},
		"SubnetIds.member.1":       {sa},
	})
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "single-subnet group")

	// Describe by name.
	_, body = rdsCall(t, srv, region, "DescribeDBSubnetGroups", url.Values{"DBSubnetGroupName": {"default"}})
	assert.Contains(t, string(body), "<DBSubnetGroupName>default</DBSubnetGroupName>", "Describe: %s", body)

	// Delete.
	resp, _ = rdsCall(t, srv, region, "DeleteDBSubnetGroup", url.Values{"DBSubnetGroupName": {"default"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "DeleteDBSubnetGroup")
}

func TestRDS_DBInstance_FullChain(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"
	_, sa, sb := rdsCreateVPCAndSubnets(t, srv, region)

	rdsCall(t, srv, region, "CreateDBSubnetGroup", url.Values{
		"DBSubnetGroupName":        {"default"},
		"DBSubnetGroupDescription": {"d"},
		"SubnetIds.member.1":       {sa},
		"SubnetIds.member.2":       {sb},
	})
	rdsCall(t, srv, region, "CreateDBParameterGroup", url.Values{
		"DBParameterGroupName":   {"pg15"},
		"DBParameterGroupFamily": {"postgres15"},
		"Description":            {"pg15 family"},
	})

	// CreateDBInstance.
	resp, body := rdsCall(t, srv, region, "CreateDBInstance", url.Values{
		"DBInstanceIdentifier": {"db-1"},
		"Engine":               {"postgres"},
		"DBInstanceClass":      {"db.t3.micro"},
		"DBSubnetGroupName":    {"default"},
		"DBParameterGroupName": {"pg15"},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateDBInstance: %s", body)
	assert.Contains(t, string(body), "<DBInstanceIdentifier>db-1</DBInstanceIdentifier>", "CreateDBInstance body missing id: %s", body)

	// Missing subnet group → 404.
	resp, _ = rdsCall(t, srv, region, "CreateDBInstance", url.Values{
		"DBInstanceIdentifier": {"db-2"},
		"Engine":               {"postgres"},
		"DBInstanceClass":      {"db.t3.micro"},
		"DBSubnetGroupName":    {"missing"},
	})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "missing subnet group")

	// DeleteDBInstance with deletion_protection=true → 409.
	rdsCall(t, srv, region, "CreateDBInstance", url.Values{
		"DBInstanceIdentifier": {"db-prot"},
		"Engine":               {"postgres"},
		"DBInstanceClass":      {"db.t3.micro"},
		"DBSubnetGroupName":    {"default"},
		"DeletionProtection":   {"true"},
	})
	resp, _ = rdsCall(t, srv, region, "DeleteDBInstance", url.Values{"DBInstanceIdentifier": {"db-prot"}})
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "DeleteDBInstance with deletion_protection")
}

func TestRDS_ReadReplicaChainRESTRICT(t *testing.T) {
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
		"DBInstanceIdentifier": {"src"},
		"Engine":               {"postgres"},
		"DBInstanceClass":      {"db.t3.micro"},
		"DBSubnetGroupName":    {"default"},
	})
	rdsCall(t, srv, region, "CreateDBInstance", url.Values{
		"DBInstanceIdentifier": {"replica"},
		"Engine":               {"postgres"},
		"DBInstanceClass":      {"db.t3.micro"},
		"DBSubnetGroupName":    {"default"},
		"ReplicateSourceDB":    {"src"},
	})
	// Source delete with replica → 409.
	resp, _ := rdsCall(t, srv, region, "DeleteDBInstance", url.Values{"DBInstanceIdentifier": {"src"}})
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "DeleteDBInstance src-with-replicas")

	// After replica delete, source delete proceeds.
	rdsCall(t, srv, region, "DeleteDBInstance", url.Values{"DBInstanceIdentifier": {"replica"}})
	resp, _ = rdsCall(t, srv, region, "DeleteDBInstance", url.Values{"DBInstanceIdentifier": {"src"}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DeleteDBInstance src after replica gone")
}

func TestRDS_ParameterGroupCRUD(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, body := rdsCall(t, srv, "us-east-1", "CreateDBParameterGroup", url.Values{
		"DBParameterGroupName":   {"pg15"},
		"DBParameterGroupFamily": {"postgres15"},
		"Description":            {"pg15"},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateDBParameterGroup: %s", body)
	resp, _ = rdsCall(t, srv, "us-east-1", "DeleteDBParameterGroup", url.Values{"DBParameterGroupName": {"pg15"}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DeleteDBParameterGroup")
}

// TestContract_rds_dbi_resource_id_distinct_from_identifier lives in
// handlers/rds_internal_test.go because it exercises the unexported
// dbiResourceIDFor helper directly.
