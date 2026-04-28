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

	// ----- InternetGateway -----
	case "CreateInternetGateway":
		app.ec2CreateInternetGateway(w, account, region, req)
	case "DescribeInternetGateways":
		app.ec2DescribeInternetGateways(w, account, req)
	case "AttachInternetGateway":
		app.ec2AttachInternetGateway(w, account, req)
	case "DetachInternetGateway":
		app.ec2DetachInternetGateway(w, account, req)
	case "DeleteInternetGateway":
		app.ec2DeleteInternetGateway(w, account, req)

	// ----- RouteTable + Route -----
	case "CreateRouteTable":
		app.ec2CreateRouteTable(w, account, region, req)
	case "DeleteRouteTable":
		app.ec2DeleteRouteTable(w, account, req)
	case "AssociateRouteTable":
		app.ec2AssociateRouteTable(w, account, req)
	case "DisassociateRouteTable":
		app.ec2DisassociateRouteTable(w, account, req)
	case "CreateRoute":
		app.ec2CreateRoute(w, account, req)
	case "DeleteRoute":
		app.ec2DeleteRoute(w, account, req)

	// ----- EIP -----
	case "AllocateAddress":
		app.ec2AllocateAddress(w, account, region, req)
	case "DescribeAddresses":
		app.ec2DescribeAddresses(w, account, region, req)
	case "ReleaseAddress":
		app.ec2ReleaseAddress(w, account, req)

	// Remaining actions (SG in S44-T5, Instance / KeyPair / AMI in
	// S44-T7) hit the default arm and surface as 404 with a log line
	// — per concepts.md "Anti-patterns explicitly forbidden", no
	// silent 200.
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

// ----- InternetGateway handlers -----

type ec2IgwAttachmentXML struct {
	XMLName xml.Name `xml:"item"`
	VpcId   string   `xml:"vpcId"`
	State   string   `xml:"state"`
}

type ec2IgwXML struct {
	XMLName           xml.Name              `xml:"internetGateway"`
	InternetGatewayId string                `xml:"internetGatewayId"`
	Attachments       []ec2IgwAttachmentXML `xml:"attachmentSet>item,omitempty"`
}

type ec2CreateIgwResult struct {
	XMLName         xml.Name  `xml:"CreateInternetGatewayResult"`
	InternetGateway ec2IgwXML `xml:"internetGateway"`
}

type ec2DescribeIgwsResult struct {
	XMLName            xml.Name    `xml:"DescribeInternetGatewaysResult"`
	InternetGatewaySet []ec2IgwXML `xml:"internetGatewaySet>item"`
}

func ec2IgwToXML(igw *repository.EC2InternetGateway) ec2IgwXML {
	out := ec2IgwXML{InternetGatewayId: igw.ID}
	if igw.VPCID != "" {
		out.Attachments = []ec2IgwAttachmentXML{{VpcId: igw.VPCID, State: "available"}}
	}
	return out
}

func (app *Application) ec2CreateInternetGateway(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	id := "igw-" + ec2RandID()
	igw := &repository.EC2InternetGateway{
		ID: id, Region: region,
		ARN:       awsproto.BuildEC2InternetGatewayARN(region, id),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := app.repo.CreateInternetGateway(account, igw); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "CreateInternetGateway", &ec2CreateIgwResult{InternetGateway: ec2IgwToXML(igw)})
}

func (app *Application) ec2DescribeInternetGateways(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	igws, err := app.repo.ListInternetGateways(account)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	out := ec2DescribeIgwsResult{InternetGatewaySet: make([]ec2IgwXML, 0, len(igws))}
	for _, igw := range igws {
		out.InternetGatewaySet = append(out.InternetGatewaySet, ec2IgwToXML(igw))
	}
	awsproto.WriteQueryRPCResponse(w, "DescribeInternetGateways", &out)
}

func (app *Application) ec2AttachInternetGateway(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	igwID := req.Params.Get("InternetGatewayId")
	vpcID := req.Params.Get("VpcId")
	if igwID == "" || vpcID == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC,
			fmt.Errorf("InternetGatewayId and VpcId required: %w", models.ErrConflict))
		return
	}
	if err := app.repo.AttachInternetGateway(account, igwID, vpcID); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "AttachInternetGateway", nil)
}

func (app *Application) ec2DetachInternetGateway(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	if err := app.repo.DetachInternetGateway(account, req.Params.Get("InternetGatewayId")); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "DetachInternetGateway", nil)
}

func (app *Application) ec2DeleteInternetGateway(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	if err := app.repo.DeleteInternetGateway(account, req.Params.Get("InternetGatewayId")); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "DeleteInternetGateway", nil)
}

// ----- RouteTable + Route handlers -----

type ec2RouteTableXML struct {
	XMLName      xml.Name `xml:"routeTable"`
	RouteTableId string   `xml:"routeTableId"`
	VpcId        string   `xml:"vpcId"`
}

type ec2CreateRouteTableResult struct {
	XMLName    xml.Name         `xml:"CreateRouteTableResult"`
	RouteTable ec2RouteTableXML `xml:"routeTable"`
}

type ec2AssociateRouteTableResult struct {
	XMLName       xml.Name `xml:"AssociateRouteTableResult"`
	AssociationId string   `xml:"associationId"`
}

type ec2CreateRouteResult struct {
	XMLName xml.Name `xml:"CreateRouteResult"`
	Return  bool     `xml:"return"`
}

func (app *Application) ec2CreateRouteTable(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	vpcID := req.Params.Get("VpcId")
	if vpcID == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC,
			fmt.Errorf("VpcId required: %w", models.ErrConflict))
		return
	}
	id := "rtb-" + ec2RandID()
	rt := &repository.EC2RouteTable{
		ID: id, VPCID: vpcID, Region: region,
		ARN:       awsproto.BuildEC2RouteTableARN(region, id),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := app.repo.CreateRouteTable(account, rt); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "CreateRouteTable",
		&ec2CreateRouteTableResult{RouteTable: ec2RouteTableXML{RouteTableId: rt.ID, VpcId: rt.VPCID}})
}

func (app *Application) ec2DeleteRouteTable(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	if err := app.repo.DeleteRouteTable(account, req.Params.Get("RouteTableId")); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "DeleteRouteTable", nil)
}

func (app *Application) ec2AssociateRouteTable(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	rtID := req.Params.Get("RouteTableId")
	subnetID := req.Params.Get("SubnetId")
	if rtID == "" || subnetID == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC,
			fmt.Errorf("RouteTableId and SubnetId required: %w", models.ErrConflict))
		return
	}
	assoc := &repository.EC2RouteTableAssociation{
		ID: "rtbassoc-" + ec2RandID(), RouteTableID: rtID, SubnetID: subnetID,
	}
	if err := app.repo.AssociateRouteTable(account, assoc); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "AssociateRouteTable",
		&ec2AssociateRouteTableResult{AssociationId: assoc.ID})
}

func (app *Application) ec2DisassociateRouteTable(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	if err := app.repo.DisassociateRouteTable(account, req.Params.Get("AssociationId")); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "DisassociateRouteTable", nil)
}

func (app *Application) ec2CreateRoute(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	rt := &repository.EC2Route{
		RouteTableID:         req.Params.Get("RouteTableId"),
		DestinationCidrBlock: req.Params.Get("DestinationCidrBlock"),
		GatewayID:            req.Params.Get("GatewayId"),
		NatGatewayID:         req.Params.Get("NatGatewayId"),
		InstanceID:           req.Params.Get("InstanceId"),
		NetworkInterfaceID:   req.Params.Get("NetworkInterfaceId"),
	}
	if rt.RouteTableID == "" || rt.DestinationCidrBlock == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC,
			fmt.Errorf("RouteTableId and DestinationCidrBlock required: %w", models.ErrConflict))
		return
	}
	if err := app.repo.CreateRoute(account, rt); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "CreateRoute", &ec2CreateRouteResult{Return: true})
}

func (app *Application) ec2DeleteRoute(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	if err := app.repo.DeleteRoute(account,
		req.Params.Get("RouteTableId"), req.Params.Get("DestinationCidrBlock")); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "DeleteRoute", nil)
}

// ----- EIP handlers -----

type ec2AddressXML struct {
	XMLName      xml.Name `xml:"item"`
	AllocationId string   `xml:"allocationId"`
	PublicIp     string   `xml:"publicIp"`
	Domain       string   `xml:"domain"`
}

type ec2AllocateAddressResult struct {
	XMLName      xml.Name `xml:"AllocateAddressResult"`
	AllocationId string   `xml:"allocationId"`
	PublicIp     string   `xml:"publicIp"`
	Domain       string   `xml:"domain"`
}

type ec2DescribeAddressesResult struct {
	XMLName    xml.Name        `xml:"DescribeAddressesResult"`
	AddressSet []ec2AddressXML `xml:"addressesSet>item"`
}

// ec2DerivePublicIP synthesises a deterministic-looking public IP from
// the allocation id so DescribeAddresses returns something stable.
// Using the documentation/test-net 203.0.113.0/24 (TEST-NET-3, RFC 5737)
// per concepts.md "Standing patterns" item 8 — never expose a real
// routable IP.
func ec2DerivePublicIP(allocID string) string {
	sum := 0
	for _, b := range []byte(allocID) {
		sum = (sum*31 + int(b)) & 0xff
	}
	return fmt.Sprintf("203.0.113.%d", sum)
}

func (app *Application) ec2AllocateAddress(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	domain := req.Params.Get("Domain")
	if domain == "" {
		domain = "vpc"
	}
	if domain != "vpc" {
		// classic EIPs are out of scope at v1 per PLAN.md S44.
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC,
			fmt.Errorf("Domain=%q not supported (v1 supports 'vpc' only): %w", domain, models.ErrConflict))
		return
	}
	allocID := "eipalloc-" + ec2RandID()
	eip := &repository.EC2EIP{
		AllocationID: allocID, Domain: domain,
		PublicIP:  ec2DerivePublicIP(allocID),
		Region:    region,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := app.repo.CreateEIP(account, eip); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "AllocateAddress",
		&ec2AllocateAddressResult{AllocationId: eip.AllocationID, PublicIp: eip.PublicIP, Domain: eip.Domain})
}

func (app *Application) ec2DescribeAddresses(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	// AllocationId.<n> filter — most common shape from the AWS provider.
	wanted := map[string]bool{}
	for k, vs := range req.Params {
		if strings.HasPrefix(k, "AllocationId.") && len(vs) > 0 {
			wanted[vs[0]] = true
		}
	}
	out := ec2DescribeAddressesResult{AddressSet: []ec2AddressXML{}}
	if len(wanted) == 0 {
		// No filter — describe nothing (full list scan deferred; AWS
		// provider's import path always supplies the AllocationId).
		awsproto.WriteQueryRPCResponse(w, "DescribeAddresses", &out)
		return
	}
	for id := range wanted {
		eip, err := app.repo.GetEIP(account, id)
		if err != nil {
			awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
			return
		}
		out.AddressSet = append(out.AddressSet, ec2AddressXML{
			AllocationId: eip.AllocationID, PublicIp: eip.PublicIP, Domain: eip.Domain,
		})
	}
	awsproto.WriteQueryRPCResponse(w, "DescribeAddresses", &out)
}

func (app *Application) ec2ReleaseAddress(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	if err := app.repo.DeleteEIP(account, req.Params.Get("AllocationId")); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "ReleaseAddress", nil)
}
