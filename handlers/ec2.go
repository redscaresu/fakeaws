package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/redscaresu/fakeaws/handlers/awsproto"
	"github.com/redscaresu/fakeaws/models"
	"github.com/redscaresu/fakeaws/repository"
)

// EC2 dispatcher. Per fakeaws/PLAN.md § "Phase 2 — Networking + compute":
// EC2 routes at POST /ec2/region/<region>; same Query-RPC family as
// IAM. Single dispatcher parses Action and dispatches to per-resource
// handlers split across ec2_network.go (this file's networking
// endpoints), ec2_security.go (security groups, S44-T5), and
// ec2_instance.go (instance lifecycle, S44-T7).
//
// At S44-T4 only the networking endpoints are wired; the rest log
// UNIMPLEMENTED via the unimplementedHandler fallback.

func (app *Application) registerEC2Routes(r chi.Router) {
	r.Post("/ec2/region/{region}", app.handleEC2)
}

func (app *Application) handleEC2(w http.ResponseWriter, r *http.Request) {
	region := chi.URLParam(r, "region")
	req, err := awsproto.ParseQueryRPC(r)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC,
			fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}
	const account = awsproto.FakeAccountID

	switch req.Action {
	// ----- VPC -----
	case "CreateVpc":
		app.ec2CreateVpc(w, account, region, req)
	case "DescribeVpcs":
		app.ec2DescribeVpcs(w, account, region, req)
	case "DeleteVpc":
		app.ec2DeleteVpc(w, account, req)

	// ----- Subnet -----
	case "CreateSubnet":
		app.ec2CreateSubnet(w, account, region, req)
	case "DescribeSubnets":
		app.ec2DescribeSubnets(w, account, region, req)
	case "DeleteSubnet":
		app.ec2DeleteSubnet(w, account, req)

	// Future actions (IGW, RouteTable, Route, EIP, SG, Instance, etc.)
	// land in incremental commits. The dispatcher returns 501 with a
	// log line so caller sees what's missing — per concepts.md
	// § "Anti-patterns explicitly forbidden", no silent 200.
	default:
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC,
			fmt.Errorf("EC2 action %q not yet implemented in fakeaws v1: %w", req.Action, models.ErrNotFound))
	}
}

// ----- VPC handlers -----

type ec2VpcXML struct {
	XMLName   xml.Name `xml:"vpc"`
	VpcId     string   `xml:"vpcId"`
	State     string   `xml:"state"`
	CidrBlock string   `xml:"cidrBlock"`
	IsDefault bool     `xml:"isDefault"`
}

type ec2DescribeVpcsResult struct {
	XMLName xml.Name    `xml:"DescribeVpcsResult"`
	VpcSet  []ec2VpcXML `xml:"vpcSet>item"`
}

type ec2CreateVpcResult struct {
	XMLName xml.Name  `xml:"CreateVpcResult"`
	Vpc     ec2VpcXML `xml:"vpc"`
}

func (app *Application) ec2CreateVpc(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	cidr := req.Params.Get("CidrBlock")
	if cidr == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC,
			fmt.Errorf("CidrBlock required: %w", models.ErrConflict))
		return
	}
	id := "vpc-" + ec2RandID()
	v := newEC2VPC(account, region, id, cidr)
	if err := app.repo.CreateVPC(account, v); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	out := ec2CreateVpcResult{Vpc: ec2VpcToXML(v)}
	awsproto.WriteQueryRPCResponse(w, "CreateVpc", &out)
}

func (app *Application) ec2DescribeVpcs(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	vpcs, err := app.repo.ListVPCs(account, region)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	out := ec2DescribeVpcsResult{VpcSet: make([]ec2VpcXML, 0, len(vpcs))}
	for _, v := range vpcs {
		out.VpcSet = append(out.VpcSet, ec2VpcToXML(v))
	}
	awsproto.WriteQueryRPCResponse(w, "DescribeVpcs", &out)
}

func (app *Application) ec2DeleteVpc(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	if err := app.repo.DeleteVPC(account, req.Params.Get("VpcId")); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "DeleteVpc", nil)
}

// ----- Subnet handlers -----

type ec2SubnetXML struct {
	XMLName          xml.Name `xml:"subnet"`
	SubnetId         string   `xml:"subnetId"`
	VpcId            string   `xml:"vpcId"`
	State            string   `xml:"state"`
	CidrBlock        string   `xml:"cidrBlock"`
	AvailabilityZone string   `xml:"availabilityZone"`
}

type ec2DescribeSubnetsResult struct {
	XMLName   xml.Name       `xml:"DescribeSubnetsResult"`
	SubnetSet []ec2SubnetXML `xml:"subnetSet>item"`
}

type ec2CreateSubnetResult struct {
	XMLName xml.Name     `xml:"CreateSubnetResult"`
	Subnet  ec2SubnetXML `xml:"subnet"`
}

func (app *Application) ec2CreateSubnet(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	vpcID := req.Params.Get("VpcId")
	cidr := req.Params.Get("CidrBlock")
	if vpcID == "" || cidr == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC,
			fmt.Errorf("VpcId and CidrBlock required: %w", models.ErrConflict))
		return
	}
	az := req.Params.Get("AvailabilityZone")
	if az == "" {
		az = region + "a"
	}
	id := "subnet-" + ec2RandID()
	s := newEC2Subnet(account, region, id, vpcID, cidr, az)
	if err := app.repo.CreateSubnet(account, s); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	out := ec2CreateSubnetResult{Subnet: ec2SubnetToXML(s)}
	awsproto.WriteQueryRPCResponse(w, "CreateSubnet", &out)
}

func (app *Application) ec2DescribeSubnets(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	// VpcId.<n> filter is the most common — we accept VpcId.1 as a
	// single-VPC filter; full filter parsing is deferred.
	vpcFilter := ""
	for k, vs := range req.Params {
		if strings.HasPrefix(k, "Filter.") && strings.HasSuffix(k, ".Name") && len(vs) > 0 && vs[0] == "vpc-id" {
			// Look for the matching Filter.N.Value.1
			prefix := strings.TrimSuffix(k, ".Name")
			if v := req.Params.Get(prefix + ".Value.1"); v != "" {
				vpcFilter = v
			}
		}
	}
	subnets, err := app.repo.ListSubnets(account, vpcFilter)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	out := ec2DescribeSubnetsResult{SubnetSet: make([]ec2SubnetXML, 0, len(subnets))}
	for _, s := range subnets {
		out.SubnetSet = append(out.SubnetSet, ec2SubnetToXML(s))
	}
	awsproto.WriteQueryRPCResponse(w, "DescribeSubnets", &out)
}

func (app *Application) ec2DeleteSubnet(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	if err := app.repo.DeleteSubnet(account, req.Params.Get("SubnetId")); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "DeleteSubnet", nil)
}

// ----- helpers -----

func ec2RandID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newEC2VPC(account, region, id, cidr string) *repository.EC2VPC {
	return &repository.EC2VPC{
		ID: id, CidrBlock: cidr, Region: region,
		ARN:       awsproto.BuildEC2VPCARN(region, id),
		State:     "available",
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

func newEC2Subnet(account, region, id, vpcID, cidr, az string) *repository.EC2Subnet {
	return &repository.EC2Subnet{
		ID: id, VPCID: vpcID, CidrBlock: cidr, AvailabilityZone: az,
		Region: region,
		ARN:    awsproto.BuildEC2SubnetARN(region, id),
		State:  "available", CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

func ec2VpcToXML(v *repository.EC2VPC) ec2VpcXML {
	return ec2VpcXML{VpcId: v.ID, State: v.State, CidrBlock: v.CidrBlock, IsDefault: false}
}

func ec2SubnetToXML(s *repository.EC2Subnet) ec2SubnetXML {
	return ec2SubnetXML{
		SubnetId: s.ID, VpcId: s.VPCID, State: s.State,
		CidrBlock: s.CidrBlock, AvailabilityZone: s.AvailabilityZone,
	}
}
