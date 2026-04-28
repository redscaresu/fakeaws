package handlers_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
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
	if err != nil {
		t.Fatalf("POST %s %s: %v", path, action, err)
	}
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
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateDBSubnetGroup: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "<DBSubnetGroupName>default</DBSubnetGroupName>") {
		t.Errorf("CreateDBSubnetGroup body missing name: %s", body)
	}

	// Single subnet → ErrConflict (≥2 required).
	resp, _ = rdsCall(t, srv, region, "CreateDBSubnetGroup", url.Values{
		"DBSubnetGroupName":        {"x"},
		"DBSubnetGroupDescription": {"x"},
		"SubnetIds.member.1":       {sa},
	})
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("single-subnet group: got %d, want 409", resp.StatusCode)
	}

	// Describe by name.
	_, body = rdsCall(t, srv, region, "DescribeDBSubnetGroups", url.Values{"DBSubnetGroupName": {"default"}})
	if !strings.Contains(string(body), "<DBSubnetGroupName>default</DBSubnetGroupName>") {
		t.Errorf("Describe: %s", body)
	}

	// Delete.
	resp, _ = rdsCall(t, srv, region, "DeleteDBSubnetGroup", url.Values{"DBSubnetGroupName": {"default"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DeleteDBSubnetGroup: %d", resp.StatusCode)
	}
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
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateDBInstance: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "<DBInstanceIdentifier>db-1</DBInstanceIdentifier>") {
		t.Errorf("CreateDBInstance body missing id: %s", body)
	}

	// Missing subnet group → 404.
	resp, _ = rdsCall(t, srv, region, "CreateDBInstance", url.Values{
		"DBInstanceIdentifier": {"db-2"},
		"Engine":               {"postgres"},
		"DBInstanceClass":      {"db.t3.micro"},
		"DBSubnetGroupName":    {"missing"},
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing subnet group: got %d, want 404", resp.StatusCode)
	}

	// DeleteDBInstance with deletion_protection=true → 409.
	rdsCall(t, srv, region, "CreateDBInstance", url.Values{
		"DBInstanceIdentifier": {"db-prot"},
		"Engine":               {"postgres"},
		"DBInstanceClass":      {"db.t3.micro"},
		"DBSubnetGroupName":    {"default"},
		"DeletionProtection":   {"true"},
	})
	resp, _ = rdsCall(t, srv, region, "DeleteDBInstance", url.Values{"DBInstanceIdentifier": {"db-prot"}})
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("DeleteDBInstance with deletion_protection: got %d, want 409", resp.StatusCode)
	}
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
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("DeleteDBInstance src-with-replicas: got %d, want 409", resp.StatusCode)
	}

	// After replica delete, source delete proceeds.
	rdsCall(t, srv, region, "DeleteDBInstance", url.Values{"DBInstanceIdentifier": {"replica"}})
	resp, _ = rdsCall(t, srv, region, "DeleteDBInstance", url.Values{"DBInstanceIdentifier": {"src"}})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DeleteDBInstance src after replica gone: got %d", resp.StatusCode)
	}
}

func TestRDS_ParameterGroupCRUD(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, body := rdsCall(t, srv, "us-east-1", "CreateDBParameterGroup", url.Values{
		"DBParameterGroupName":   {"pg15"},
		"DBParameterGroupFamily": {"postgres15"},
		"Description":            {"pg15"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateDBParameterGroup: %d %s", resp.StatusCode, body)
	}
	resp, _ = rdsCall(t, srv, "us-east-1", "DeleteDBParameterGroup", url.Values{"DBParameterGroupName": {"pg15"}})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DeleteDBParameterGroup: %d", resp.StatusCode)
	}
}
