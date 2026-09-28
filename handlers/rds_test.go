package handlers_test

import (
	"encoding/xml"
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

// rdsClusterRead is the part of a DescribeDBClusters member
// aws_rds_cluster compares with its config.
type rdsClusterRead struct {
	EngineMode            string   `xml:"EngineMode"`
	Port                  int      `xml:"Port"`
	BackupRetentionPeriod int      `xml:"BackupRetentionPeriod"`
	PreferredBackupWindow string   `xml:"PreferredBackupWindow"`
	DatabaseName          string   `xml:"DatabaseName"`
	StorageEncrypted      bool     `xml:"StorageEncrypted"`
	AvailabilityZones     []string `xml:"AvailabilityZones>AvailabilityZone"`
	VpcSecurityGroupIds   []string `xml:"VpcSecurityGroups>VpcSecurityGroupMembership>VpcSecurityGroupId"`
}

func describeCluster(t *testing.T, srv *httptest.Server, id string) rdsClusterRead {
	t.Helper()
	resp, body := rdsCall(t, srv, "us-east-1", "DescribeDBClusters", url.Values{"DBClusterIdentifier": {id}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeDBClusters: %s", body)
	var out struct {
		Clusters []rdsClusterRead `xml:"DescribeDBClustersResult>DBClusters>DBCluster"`
	}
	require.NoError(t, xml.Unmarshal(body, &out), "%s", body)
	require.Len(t, out.Clusters, 1, "%s", body)
	return out.Clusters[0]
}

// TestRDS_ClusterReadsBackWhatCreateSet: aws_rds_cluster plans a diff
// on each of these that reads back other than it set, and replaces the
// cluster over engine_mode; left unset, RDS's defaults come back.
func TestRDS_ClusterReadsBackWhatCreateSet(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, body := rdsCall(t, srv, "us-east-1", "CreateDBCluster", url.Values{
		"DBClusterIdentifier": {"set"}, "Engine": {"aurora-postgresql"},
		"Port": {"5433"}, "BackupRetentionPeriod": {"7"}, "PreferredBackupWindow": {"03:00-04:00"},
		"DatabaseName": {"app"}, "StorageEncrypted": {"true"},
		"AvailabilityZones.AvailabilityZone.1":     {"us-east-1a"},
		"VpcSecurityGroupIds.VpcSecurityGroupId.1": {"sg-1"},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateDBCluster: %s", body)
	assert.Equal(t, rdsClusterRead{
		EngineMode: "provisioned", Port: 5433, BackupRetentionPeriod: 7, PreferredBackupWindow: "03:00-04:00",
		DatabaseName: "app", StorageEncrypted: true,
		AvailabilityZones: []string{"us-east-1a"}, VpcSecurityGroupIds: []string{"sg-1"},
	}, describeCluster(t, srv, "set"))

	resp, body = rdsCall(t, srv, "us-east-1", "CreateDBCluster", url.Values{"DBClusterIdentifier": {"defaults"}, "Engine": {"aurora-mysql"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateDBCluster: %s", body)
	assert.Equal(t, rdsClusterRead{
		EngineMode: "provisioned", Port: 3306, BackupRetentionPeriod: 1, PreferredBackupWindow: "07:00-08:00",
	}, describeCluster(t, srv, "defaults"))
}

// TestRDS_ClusterReadAndDeletePaths: the calls aws_rds_cluster and
// aws_rds_cluster_parameter_group make around their reads and deletes.
func TestRDS_ClusterReadAndDeletePaths(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"
	rdsCall(t, srv, region, "CreateDBClusterParameterGroup", url.Values{
		"DBClusterParameterGroupName": {"cpg"}, "DBParameterGroupFamily": {"aurora-postgresql15"}, "Description": {"d"},
	})
	resp, body := rdsCall(t, srv, region, "DescribeDBClusterParameters", url.Values{"DBClusterParameterGroupName": {"cpg"}, "Source": {"user"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeDBClusterParameters: %s", body)
	assert.Contains(t, string(body), "<DescribeDBClusterParametersResult>", "%s", body)
	resp, body = rdsCall(t, srv, region, "DescribeDBClusterParameters", url.Values{"DBClusterParameterGroupName": {"nope"}})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "DescribeDBClusterParameters missing")
	assert.Contains(t, string(body), "<Code>DBParameterGroupNotFound</Code>", "%s", body)

	resp, body = rdsCall(t, srv, region, "DescribeGlobalClusters", url.Values{"Filters.Filter.1.Name": {"db-cluster-id"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeGlobalClusters: %s", body)
	assert.NotContains(t, string(body), "<GlobalClusterMember>", "%s", body)

	resp, body = rdsCall(t, srv, region, "CreateDBCluster", url.Values{
		"DBClusterIdentifier": {"c"}, "Engine": {"aurora-postgresql"}, "DBClusterParameterGroupName": {"cpg"},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateDBCluster: %s", body)
	resp, body = rdsCall(t, srv, region, "DeleteDBClusterParameterGroup", url.Values{"DBClusterParameterGroupName": {"cpg"}})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "DeleteDBClusterParameterGroup in use")
	assert.Contains(t, string(body), "<Code>InvalidDBParameterGroupState</Code>", "%s", body)

	resp, body = rdsCall(t, srv, region, "DeleteDBCluster", url.Values{"DBClusterIdentifier": {"c"}, "SkipFinalSnapshot": {"true"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "DeleteDBCluster: %s", body)
	assert.Contains(t, string(body), "<Status>deleting</Status>", "DeleteDBCluster returns the deleting cluster: %s", body)
	resp, body = rdsCall(t, srv, region, "DeleteDBCluster", url.Values{"DBClusterIdentifier": {"c"}})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "DeleteDBCluster missing")
	assert.Contains(t, string(body), "<Code>DBClusterNotFoundFault</Code>", "%s", body)

	resp, _ = rdsCall(t, srv, region, "DeleteDBClusterParameterGroup", url.Values{"DBClusterParameterGroupName": {"cpg"}})
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DeleteDBClusterParameterGroup")
	resp, body = rdsCall(t, srv, region, "DeleteDBClusterParameterGroup", url.Values{"DBClusterParameterGroupName": {"cpg"}})
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "DeleteDBClusterParameterGroup missing")
	assert.Contains(t, string(body), "<Code>DBParameterGroupNotFound</Code>", "%s", body)
}
