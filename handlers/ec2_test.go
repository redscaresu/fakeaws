package handlers_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// EC2 handler tests — networking surface that landed in S44-T4.
//
// Wire format: Query-RPC POST /ec2/region/<region> with form body
// Action=<op>&Version=2016-11-15&<params>; XML response. Per concepts.md
// "Coverage requirements" rule 1: each in-scope endpoint has a
// success-path test plus a 404 / FK-violation test where applicable.

const ec2Version = "2016-11-15"

func ec2Call(t *testing.T, srv *httptest.Server, region, action string, params url.Values) (*http.Response, []byte) {
	t.Helper()
	if params == nil {
		params = url.Values{}
	}
	params.Set("Action", action)
	params.Set("Version", ec2Version)
	path := "/ec2/region/" + region
	req, err := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(params.Encode()))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("POST %s %s: %v", path, action, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

// extractEC2Tag returns the contents of the first <tag>...</tag> in body
// — sufficient for asserting server-stamped ids in handler tests
// without pulling a full XML decoder for the per-shape result types.
func extractEC2Tag(body []byte, tag string) string {
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

func TestEC2_CreateDescribeDeleteVPC(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"

	// CreateVpc.
	resp, body := ec2Call(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateVpc: got %d body=%s", resp.StatusCode, body)
	}
	vpcID := extractEC2Tag(body, "vpcId")
	if !strings.HasPrefix(vpcID, "vpc-") {
		t.Fatalf("CreateVpc body missing vpcId or wrong prefix: %s", body)
	}
	if !strings.Contains(string(body), "<cidrBlock>10.0.0.0/16</cidrBlock>") {
		t.Errorf("CreateVpc body missing cidrBlock: %s", body)
	}

	// DescribeVpcs returns the new VPC.
	resp, body = ec2Call(t, srv, region, "DescribeVpcs", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DescribeVpcs: got %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), vpcID) {
		t.Errorf("DescribeVpcs missing %s: %s", vpcID, body)
	}

	// DeleteVpc.
	resp, body = ec2Call(t, srv, region, "DeleteVpc", url.Values{"VpcId": {vpcID}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DeleteVpc: got %d body=%s", resp.StatusCode, body)
	}

	// DeleteVpc on missing VPC → 404.
	resp, body = ec2Call(t, srv, region, "DeleteVpc", url.Values{"VpcId": {"vpc-missing"}})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("DeleteVpc on missing vpc: got %d body=%s, want 404", resp.StatusCode, body)
	}
}

func TestEC2_CreateVPC_MissingCidr(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, _ := ec2Call(t, srv, "us-east-1", "CreateVpc", nil)
	// Missing required CidrBlock surfaces as ErrConflict → 409.
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("CreateVpc with no CidrBlock: got %d, want 409", resp.StatusCode)
	}
}

func TestEC2_SubnetCRUDAndFK(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"

	// Subnet without VPC → 404 (FK enforcement at the handler layer).
	resp, _ := ec2Call(t, srv, region, "CreateSubnet", url.Values{
		"VpcId":     {"vpc-missing"},
		"CidrBlock": {"10.0.1.0/24"},
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("CreateSubnet missing vpc: got %d, want 404", resp.StatusCode)
	}

	// Create the VPC then the subnet.
	_, body := ec2Call(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
	vpcID := extractEC2Tag(body, "vpcId")
	if vpcID == "" {
		t.Fatalf("setup CreateVpc failed: %s", body)
	}

	resp, body = ec2Call(t, srv, region, "CreateSubnet", url.Values{
		"VpcId":     {vpcID},
		"CidrBlock": {"10.0.1.0/24"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateSubnet: got %d body=%s", resp.StatusCode, body)
	}
	subnetID := extractEC2Tag(body, "subnetId")
	if !strings.HasPrefix(subnetID, "subnet-") {
		t.Fatalf("CreateSubnet missing subnetId: %s", body)
	}
	// AvailabilityZone defaults to <region>+"a" when unspecified.
	if !strings.Contains(string(body), "<availabilityZone>us-east-1a</availabilityZone>") {
		t.Errorf("CreateSubnet should default AZ to <region>a: %s", body)
	}

	// DescribeSubnets unfiltered.
	resp, body = ec2Call(t, srv, region, "DescribeSubnets", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), subnetID) {
		t.Errorf("DescribeSubnets missing %s: %d %s", subnetID, resp.StatusCode, body)
	}

	// DescribeSubnets with vpc-id filter.
	params := url.Values{}
	params.Set("Filter.1.Name", "vpc-id")
	params.Set("Filter.1.Value.1", vpcID)
	resp, body = ec2Call(t, srv, region, "DescribeSubnets", params)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), subnetID) {
		t.Errorf("DescribeSubnets filtered: %d %s", resp.StatusCode, body)
	}

	// DescribeSubnets with non-matching vpc-id → no subnets in list.
	params.Set("Filter.1.Value.1", "vpc-other")
	_, body = ec2Call(t, srv, region, "DescribeSubnets", params)
	if strings.Contains(string(body), subnetID) {
		t.Errorf("DescribeSubnets vpc-other should not return %s: %s", subnetID, body)
	}

	// DeleteVpc cascades to subnet (repository CASCADE).
	if resp, body := ec2Call(t, srv, region, "DeleteVpc", url.Values{"VpcId": {vpcID}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("DeleteVpc: %d %s", resp.StatusCode, body)
	}
	_, body = ec2Call(t, srv, region, "DescribeSubnets", nil)
	if strings.Contains(string(body), subnetID) {
		t.Errorf("subnet should be cascade-deleted with vpc: %s", body)
	}
}

func TestEC2_UnknownAction(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, body := ec2Call(t, srv, "us-east-1", "CreateNatGateway", nil)
	// Unimplemented EC2 actions surface as ErrNotFound → 404 with a
	// log-line marker; per concepts.md "Anti-patterns explicitly
	// forbidden", silent 200 is unacceptable.
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Unknown EC2 action: got %d, want 404; body=%s", resp.StatusCode, body)
	}
}
