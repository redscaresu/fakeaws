package handlers_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func eksRequest(t *testing.T, srv *httptest.Server, method, path, body string) (*http.Response, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, srv.URL+path, rd)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

// eksSetupPrereqs creates an IAM role, VPC + 2 subnets, returning
// the arn + subnet ids.
func eksSetupPrereqs(t *testing.T, srv *httptest.Server, region string) (clusterRoleARN, nodeRoleARN, subnetA, subnetB string) {
	t.Helper()

	// IAM cluster role.
	iamCall(t, srv, "CreateRole", url.Values{
		"RoleName": {"eks-cluster-role"},
		"AssumeRolePolicyDocument": {`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"eks.amazonaws.com"},"Action":"sts:AssumeRole"}]}`},
	})
	iamCall(t, srv, "CreateRole", url.Values{
		"RoleName": {"eks-node-role"},
		"AssumeRolePolicyDocument": {`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`},
	})
	clusterRoleARN = "arn:aws:iam::000000000000:role/eks-cluster-role"
	nodeRoleARN = "arn:aws:iam::000000000000:role/eks-node-role"

	_, body := ec2Call(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
	vpcID := extractEC2Tag(body, "vpcId")
	_, body = ec2Call(t, srv, region, "CreateSubnet", url.Values{"VpcId": {vpcID}, "CidrBlock": {"10.0.1.0/24"}, "AvailabilityZone": {region + "a"}})
	subnetA = extractEC2Tag(body, "subnetId")
	_, body = ec2Call(t, srv, region, "CreateSubnet", url.Values{"VpcId": {vpcID}, "CidrBlock": {"10.0.2.0/24"}, "AvailabilityZone": {region + "b"}})
	subnetB = extractEC2Tag(body, "subnetId")
	return
}

func TestEKS_ClusterLifecycle(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"
	clusterRole, _, sa, sb := eksSetupPrereqs(t, srv, region)

	resp, body := eksRequest(t, srv, http.MethodPost, "/eks/region/"+region+"/clusters", `{
		"name": "demo",
		"roleArn": "`+clusterRole+`",
		"resourcesVpcConfig": {"subnetIds":["`+sa+`","`+sb+`"]},
		"version": "1.29"
	}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateCluster: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `"name":"demo"`) {
		t.Errorf("CreateCluster body: %s", body)
	}

	// Describe.
	resp, body = eksRequest(t, srv, http.MethodGet, "/eks/region/"+region+"/clusters/demo", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"status":"ACTIVE"`) {
		t.Errorf("DescribeCluster: %d %s", resp.StatusCode, body)
	}

	// List.
	_, body = eksRequest(t, srv, http.MethodGet, "/eks/region/"+region+"/clusters", "")
	if !strings.Contains(string(body), `"demo"`) {
		t.Errorf("ListClusters: %s", body)
	}

	// Delete.
	resp, _ = eksRequest(t, srv, http.MethodDelete, "/eks/region/"+region+"/clusters/demo", "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DeleteCluster: %d", resp.StatusCode)
	}
}

func TestEKS_ClusterCrossAccountRoleARN404(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"
	_, _, sa, sb := eksSetupPrereqs(t, srv, region)

	resp, _ := eksRequest(t, srv, http.MethodPost, "/eks/region/"+region+"/clusters", `{
		"name": "x",
		"roleArn": "arn:aws:iam::999999999999:role/eks-cluster-role",
		"resourcesVpcConfig": {"subnetIds":["`+sa+`","`+sb+`"]}
	}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("cross-account roleArn: got %d, want 404", resp.StatusCode)
	}
}

func TestEKS_NodeGroupSubnetMustBeInCluster(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"
	clusterRole, nodeRole, sa, sb := eksSetupPrereqs(t, srv, region)

	// Cluster with only subnet A.
	eksRequest(t, srv, http.MethodPost, "/eks/region/"+region+"/clusters", `{
		"name": "demo",
		"roleArn": "`+clusterRole+`",
		"resourcesVpcConfig": {"subnetIds":["`+sa+`"]}
	}`)

	// Nodegroup with subnet B → 409 (not in cluster's set).
	resp, _ := eksRequest(t, srv, http.MethodPost, "/eks/region/"+region+"/clusters/demo/node-groups", `{
		"nodegroupName": "ng-1",
		"nodeRole": "`+nodeRole+`",
		"subnets": ["`+sb+`"]
	}`)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("nodegroup subnet outside cluster: got %d, want 409", resp.StatusCode)
	}
}

func TestEKS_AddonLifecycle(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"
	clusterRole, _, sa, sb := eksSetupPrereqs(t, srv, region)
	eksRequest(t, srv, http.MethodPost, "/eks/region/"+region+"/clusters", `{
		"name": "demo",
		"roleArn": "`+clusterRole+`",
		"resourcesVpcConfig": {"subnetIds":["`+sa+`","`+sb+`"]}
	}`)

	resp, _ := eksRequest(t, srv, http.MethodPost, "/eks/region/"+region+"/clusters/demo/addons", `{
		"addonName": "vpc-cni",
		"addonVersion": "v1.18.0"
	}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateAddon: %d", resp.StatusCode)
	}

	resp, _ = eksRequest(t, srv, http.MethodGet, "/eks/region/"+region+"/clusters/demo/addons/vpc-cni", "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DescribeAddon: %d", resp.StatusCode)
	}

	resp, _ = eksRequest(t, srv, http.MethodDelete, "/eks/region/"+region+"/clusters/demo/addons/vpc-cni", "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DeleteAddon: %d", resp.StatusCode)
	}
}
