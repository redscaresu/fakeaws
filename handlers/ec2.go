package handlers

import (
	"cmp"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
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
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
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
	case "DescribeVpcAttribute":
		app.ec2DescribeVpcAttribute(w, account, region, req)
	case "ModifyVpcAttribute":
		app.ec2ModifyVpcAttribute(w, account, region, req)
	case "DeleteVpc":
		app.ec2DeleteVpc(w, account, region, req)

	// ----- Subnet -----
	case "CreateSubnet":
		app.ec2CreateSubnet(w, account, region, req)
	case "DescribeSubnets":
		app.ec2DescribeSubnets(w, account, region, req)
	case "DeleteSubnet":
		app.ec2DeleteSubnet(w, account, region, req)
	case "ModifySubnetAttribute":
		app.ec2ModifySubnetAttribute(w, account, region, req)

	// ----- NetworkInterface (instance primary ENIs) -----
	case "DescribeNetworkInterfaces":
		app.ec2DescribeNetworkInterfaces(w, account, region, req)
	case "ModifyNetworkInterfaceAttribute":
		app.ec2ModifyNetworkInterfaceAttribute(w, account, region, req)

	// ----- InternetGateway -----
	case "CreateInternetGateway":
		app.ec2CreateInternetGateway(w, account, region, req)
	case "DescribeInternetGateways":
		app.ec2DescribeInternetGateways(w, account, region, req)
	case "AttachInternetGateway":
		app.ec2AttachInternetGateway(w, account, region, req)
	case "DetachInternetGateway":
		app.ec2DetachInternetGateway(w, account, region, req)
	case "DeleteInternetGateway":
		app.ec2DeleteInternetGateway(w, account, region, req)

	// ----- RouteTable + Route -----
	case "CreateRouteTable":
		app.ec2CreateRouteTable(w, account, region, req)
	case "DescribeRouteTables":
		app.ec2DescribeRouteTables(w, account, region, req)
	case "DeleteRouteTable":
		app.ec2DeleteRouteTable(w, account, region, req)
	case "AssociateRouteTable":
		app.ec2AssociateRouteTable(w, account, region, req)
	case "DisassociateRouteTable":
		app.ec2DisassociateRouteTable(w, account, req)
	case "CreateRoute":
		app.ec2CreateRoute(w, account, region, req)
	case "DeleteRoute":
		app.ec2DeleteRoute(w, account, region, req)

	// ----- EIP -----
	case "AllocateAddress":
		app.ec2AllocateAddress(w, account, region, req)
	case "DescribeAddresses":
		app.ec2DescribeAddresses(w, account, region, req)
	case "ReleaseAddress":
		app.ec2ReleaseAddress(w, account, region, req)
	case "DescribeAddressesAttribute":
		app.ec2DescribeAddressesAttribute(w, account, region, req)
	case "AssociateAddress":
		app.ec2AssociateAddress(w, account, region, req)
	case "DisassociateAddress":
		app.ec2DisassociateAddress(w, account, region, req)

	// ----- Instance -----
	case "RunInstances":
		app.ec2RunInstances(w, account, region, req)
	case "DescribeInstances":
		app.ec2DescribeInstances(w, account, region, req)
	case "ModifyInstanceAttribute":
		app.ec2ModifyInstanceAttribute(w, account, region, req)
	case "TerminateInstances":
		app.ec2TerminateInstances(w, account, region, req)

	// ----- KeyPair -----
	case "ImportKeyPair":
		app.ec2ImportKeyPair(w, account, region, req)
	case "DescribeKeyPairs":
		app.ec2DescribeKeyPairs(w, account, region, req)
	case "DeleteKeyPair":
		app.ec2DeleteKeyPair(w, account, region, req)

	// ----- AMI (read-only fixture) -----
	case "DescribeImages":
		app.ec2DescribeImages(w, account, region, req)

	// ----- Resources fakeaws never creates (the scope sweep lists them) -----
	case "DescribeVolumes", "DescribeNatGateways", "DescribeSnapshots", "DescribeLaunchTemplates":
		ec2DescribeNone(w, req)

	// ----- InstanceType (read-only fixture) -----
	// terraform-provider-aws calls DescribeInstanceTypes during the
	// read path of `aws_instance` to surface capacity fields back to
	// state. Without this handler the provider gets a 404 and the
	// apply fails *after* successful RunInstances — a confusing
	// post-create failure that the LLM can't act on.
	case "DescribeInstanceTypes":
		app.ec2DescribeInstanceTypes(w, account, region, req)

	// ----- Tags -----
	case "CreateTags":
		app.ec2CreateTags(w, account, region, req)
	case "DeleteTags":
		app.ec2DeleteTags(w, account, region, req)
	case "DescribeTags":
		app.ec2DescribeTags(w, account, region, req)

	// ----- InstanceAttribute (read-only) -----
	// terraform-provider-aws calls DescribeInstanceAttribute for each
	// scalar attribute on the read path (disableApiTermination,
	// instanceInitiatedShutdownBehavior, userData, etc.). We return
	// the AWS default for the requested attribute — these aren't
	// stored on our instance fixture.
	case "DescribeInstanceAttribute":
		app.ec2DescribeInstanceAttribute(w, account, region, req)

	// ----- SecurityGroup -----
	case "CreateSecurityGroup":
		app.ec2CreateSecurityGroup(w, account, region, req)
	case "DescribeSecurityGroups":
		app.ec2DescribeSecurityGroups(w, account, region, req)
	case "DeleteSecurityGroup":
		app.ec2DeleteSecurityGroup(w, account, region, req)
	case "AuthorizeSecurityGroupIngress":
		app.ec2AuthorizeSecurityGroupRules(w, account, region, "ingress", req)
	case "RevokeSecurityGroupIngress":
		app.ec2RevokeSecurityGroupRules(w, account, region, "ingress", req)
	case "AuthorizeSecurityGroupEgress":
		app.ec2AuthorizeSecurityGroupRules(w, account, region, "egress", req)
	case "RevokeSecurityGroupEgress":
		app.ec2RevokeSecurityGroupRules(w, account, region, "egress", req)

	// Any other Action hits the default arm and surfaces as 404 with
	// a log line — per concepts.md "Anti-patterns explicitly forbidden",
	// no silent 200.
	default:
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
			fmt.Errorf("EC2 action %q not yet implemented in fakeaws v1: %w", req.Action, models.ErrNotFound))
	}
}

// ----- VPC handlers -----

// ec2VpcXML mirrors the real EC2 CreateVpc/DescribeVpcs response
// shape. terraform-provider-aws's resourceVPCCreate (vpc_.go:235)
// iterates CidrBlockAssociationSet and reads OwnerId during Read;
// nil/missing values panic the provider plugin. We populate the
// associated CIDR block, owner id, default DHCP options id, and
// default tenancy so the standard EC2 schema fields the provider
// expects are all non-nil.
type ec2VpcXML struct {
	VpcId                       string                          `xml:"vpcId"`
	State                       string                          `xml:"state"`
	CidrBlock                   string                          `xml:"cidrBlock"`
	DhcpOptionsId               string                          `xml:"dhcpOptionsId"`
	InstanceTenancy             string                          `xml:"instanceTenancy"`
	OwnerId                     string                          `xml:"ownerId"`
	IsDefault                   bool                            `xml:"isDefault"`
	CidrBlockAssociationSet     []ec2VpcCidrBlockAssociationXML `xml:"cidrBlockAssociationSet>item"`
	Ipv6CidrBlockAssociationSet []ec2VpcIpv6BlockAssociationXML `xml:"ipv6CidrBlockAssociationSet>item,omitempty"`
	TagSet                      []ec2ResourceTagXML             `xml:"tagSet>item,omitempty"`
}

// ec2VpcCidrBlockAssociationXML mirrors the per-CIDR association
// entry. Every VPC has at least one (the primary block matching
// `cidrBlock`), and the provider treats the SET as the source of
// truth for IPv4 associations.
type ec2VpcCidrBlockAssociationXML struct {
	AssociationId  string                          `xml:"associationId"`
	CidrBlock      string                          `xml:"cidrBlock"`
	CidrBlockState ec2VpcCidrBlockAssociationState `xml:"cidrBlockState"`
}

type ec2VpcCidrBlockAssociationState struct {
	State string `xml:"state"`
}

type ec2VpcIpv6BlockAssociationXML struct {
	AssociationId  string                          `xml:"associationId"`
	Ipv6CidrBlock  string                          `xml:"ipv6CidrBlock"`
	CidrBlockState ec2VpcCidrBlockAssociationState `xml:"ipv6CidrBlockState"`
}

type ec2DescribeVpcsResult struct {
	VpcSet []ec2VpcXML `xml:"vpcSet>item"`
}

type ec2CreateVpcResult struct {
	Vpc ec2VpcXML `xml:"vpc"`
}

func (app *Application) ec2CreateVpc(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	cidr := req.Params.Get("CidrBlock")
	if cidr == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
			fmt.Errorf("CidrBlock required: %w", models.ErrConflict))
		return
	}
	specs, refused := refuseTagSpecifications(w, req.Params, "vpc")
	if refused {
		return
	}
	id := "vpc-" + ec2RandID()
	v := newEC2VPC(account, region, id, cidr)
	err := app.repo.CreateVPC(account, v)
	if err == nil {
		err = app.tagNew(account, region, onResource(specs["vpc"], id, "vpc"),
			func() error { return app.repo.DeleteVPC(account, region, id) })
	}
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	out := ec2CreateVpcResult{Vpc: ec2VpcToXML(v)}
	awsproto.WriteEC2QueryRPCResponse(w, "CreateVpc", &out)
}

// ec2DescribeVpcs answers VpcId.N with exactly those VPCs: the
// provider's lookup by id wants one result, so listing every VPC in
// the region breaks it as soon as a second VPC exists.
func (app *Application) ec2DescribeVpcs(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	var vpcs []*repository.EC2VPC
	ids := queryListValues(req.Params, "VpcId.")
	var err error
	if len(ids) == 0 {
		vpcs, err = app.repo.ListVPCs(account, region)
	}
	for _, id := range ids {
		var v *repository.EC2VPC
		v, err = app.repo.GetVPC(account, region, id)
		if errors.Is(err, models.ErrNotFound) {
			awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest,
				"InvalidVpcID.NotFound", fmt.Sprintf("The vpc ID '%s' does not exist", id))
			return
		}
		if err != nil {
			break
		}
		vpcs = append(vpcs, v)
	}
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	tags, ok := app.tagSets(w, account)
	if !ok {
		return
	}
	out := ec2DescribeVpcsResult{VpcSet: make([]ec2VpcXML, 0, len(vpcs))}
	for _, v := range vpcs {
		x := ec2VpcToXML(v)
		x.TagSet = tags[v.ID]
		out.VpcSet = append(out.VpcSet, x)
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DescribeVpcs", &out)
}

// ec2DescribeVpcAttribute models the real EC2 API: caller specifies
// one attribute (enableDnsHostnames / enableDnsSupport / etc.) via
// the `Attribute` parameter, response returns just that attribute's
// boolean value. terraform-provider-aws calls this twice as part of
// the aws_vpc Read flow (once per attribute) after CreateVpc.
//
// fakeaws doesn't persist per-VPC DNS settings; both attributes
// default to true (matching the AWS default for non-default VPCs).
func (app *Application) ec2DescribeVpcAttribute(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	if _, err := app.repo.GetVPC(account, region, req.Params.Get("VpcId")); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	attr := req.Params.Get("Attribute")
	out := ec2DescribeVpcAttributeResult{VpcId: req.Params.Get("VpcId")}
	switch attr {
	case "enableDnsSupport":
		out.EnableDnsSupport = &ec2BoolValue{Value: true}
	case "enableDnsHostnames":
		out.EnableDnsHostnames = &ec2BoolValue{Value: true}
	case "enableNetworkAddressUsageMetrics":
		out.EnableNetworkAddressUsageMetrics = &ec2BoolValue{Value: false}
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DescribeVpcAttribute", &out)
}

// ec2ModifyVpcAttribute accepts the provider's writes to DNS / hostname
// flags but doesn't persist them — fakeaws returns the same defaults
// from ec2DescribeVpcAttribute regardless. Accepts (silently) so the
// provider's apply doesn't error; revisit when a scenario actually
// depends on the persisted value.
func (app *Application) ec2ModifyVpcAttribute(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	if _, err := app.repo.GetVPC(account, region, req.Params.Get("VpcId")); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "ModifyVpcAttribute", nil)
}

type ec2DescribeVpcAttributeResult struct {
	VpcId                            string        `xml:"vpcId"`
	EnableDnsSupport                 *ec2BoolValue `xml:"enableDnsSupport,omitempty"`
	EnableDnsHostnames               *ec2BoolValue `xml:"enableDnsHostnames,omitempty"`
	EnableNetworkAddressUsageMetrics *ec2BoolValue `xml:"enableNetworkAddressUsageMetrics,omitempty"`
}

type ec2BoolValue struct {
	Value bool `xml:"value"`
}

func (app *Application) ec2DeleteVpc(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	if err := app.repo.DeleteVPC(account, region, req.Params.Get("VpcId")); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DeleteVpc", nil)
}

// ----- Subnet handlers -----

// ec2SubnetXML mirrors the real EC2 DescribeSubnets response shape.
// terraform-provider-aws's aws_subnet Read flow polls for several
// fields beyond the basic id/vpc/state/cidr/az set; a missing field
// shows up as the provider erroring "couldn't find resource (21
// retries)" because the unmarshaller can't construct the expected
// struct.
type ec2SubnetXML struct {
	SubnetId                      string                          `xml:"subnetId"`
	VpcId                         string                          `xml:"vpcId"`
	State                         string                          `xml:"state"`
	CidrBlock                     string                          `xml:"cidrBlock"`
	AvailabilityZone              string                          `xml:"availabilityZone"`
	AvailabilityZoneId            string                          `xml:"availabilityZoneId"`
	AvailableIpAddressCount       int                             `xml:"availableIpAddressCount"`
	OwnerId                       string                          `xml:"ownerId"`
	SubnetArn                     string                          `xml:"subnetArn"`
	DefaultForAz                  bool                            `xml:"defaultForAz"`
	MapPublicIpOnLaunch           bool                            `xml:"mapPublicIpOnLaunch"`
	MapCustomerOwnedIpOnLaunch    bool                            `xml:"mapCustomerOwnedIpOnLaunch"`
	AssignIpv6AddressOnCreation   bool                            `xml:"assignIpv6AddressOnCreation"`
	EnableDns64                   bool                            `xml:"enableDns64"`
	Ipv6Native                    bool                            `xml:"ipv6Native"`
	Ipv6CidrBlockAssociationSet   []ec2SubnetIpv6BlockAssociation `xml:"ipv6CidrBlockAssociationSet>item,omitempty"`
	PrivateDnsNameOptionsOnLaunch *ec2SubnetPrivateDnsOptionsXML  `xml:"privateDnsNameOptionsOnLaunch,omitempty"`
	TagSet                        []ec2ResourceTagXML             `xml:"tagSet>item,omitempty"`
}

type ec2SubnetIpv6BlockAssociation struct {
	AssociationId  string                          `xml:"associationId"`
	Ipv6CidrBlock  string                          `xml:"ipv6CidrBlock"`
	CidrBlockState ec2VpcCidrBlockAssociationState `xml:"ipv6CidrBlockState"`
}

type ec2SubnetPrivateDnsOptionsXML struct {
	HostnameType                    string `xml:"hostnameType"`
	EnableResourceNameDnsARecord    bool   `xml:"enableResourceNameDnsARecord"`
	EnableResourceNameDnsAAAARecord bool   `xml:"enableResourceNameDnsAAAARecord"`
}

type ec2DescribeSubnetsResult struct {
	SubnetSet []ec2SubnetXML `xml:"subnetSet>item"`
}

type ec2CreateSubnetResult struct {
	Subnet ec2SubnetXML `xml:"subnet"`
}

func (app *Application) ec2CreateSubnet(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	vpcID := req.Params.Get("VpcId")
	cidr := req.Params.Get("CidrBlock")
	if vpcID == "" || cidr == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
			fmt.Errorf("VpcId and CidrBlock required: %w", models.ErrConflict))
		return
	}
	az := req.Params.Get("AvailabilityZone")
	if az == "" {
		az = region + "a"
	}
	specs, refused := refuseTagSpecifications(w, req.Params, "subnet")
	if refused {
		return
	}
	id := "subnet-" + ec2RandID()
	s := newEC2Subnet(account, region, id, vpcID, cidr, az)
	err := app.repo.CreateSubnet(account, s)
	if err == nil {
		err = app.tagNew(account, region, onResource(specs["subnet"], id, "subnet"),
			func() error { return app.repo.DeleteSubnet(account, region, id) })
	}
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	out := ec2CreateSubnetResult{Subnet: ec2SubnetToXML(s)}
	awsproto.WriteEC2QueryRPCResponse(w, "CreateSubnet", &out)
}

func (app *Application) ec2DescribeSubnets(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	// terraform-provider-aws's Read flow sends SubnetId.N=<id> to look
	// up exactly one subnet (the one it just created), then expects
	// the response to contain that subnet and no others. Without the
	// filter, returning all subnets confuses the wait loop into
	// reporting "couldn't find resource (21 retries)" because the
	// match count is wrong. Filter.N.Name=vpc-id is the legacy filter
	// shape; SubnetId.N is the direct-by-id parameter that the v2 SDK
	// uses preferentially.
	subnetIDFilter := map[string]struct{}{}
	for k, vs := range req.Params {
		if strings.HasPrefix(k, "SubnetId.") && len(vs) > 0 {
			subnetIDFilter[vs[0]] = struct{}{}
		}
	}
	vpcFilter := ""
	for k, vs := range req.Params {
		if strings.HasPrefix(k, "Filter.") && strings.HasSuffix(k, ".Name") && len(vs) > 0 && vs[0] == "vpc-id" {
			prefix := strings.TrimSuffix(k, ".Name")
			if v := req.Params.Get(prefix + ".Value.1"); v != "" {
				vpcFilter = v
			}
		}
	}
	subnets, err := app.repo.ListSubnets(account, region, vpcFilter)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	tags, ok := app.tagSets(w, account)
	if !ok {
		return
	}
	out := ec2DescribeSubnetsResult{SubnetSet: make([]ec2SubnetXML, 0, len(subnets))}
	for _, s := range subnets {
		if len(subnetIDFilter) > 0 {
			if _, ok := subnetIDFilter[s.ID]; !ok {
				continue
			}
		}
		x := ec2SubnetToXML(s)
		x.TagSet = tags[s.ID]
		out.SubnetSet = append(out.SubnetSet, x)
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DescribeSubnets", &out)
}

// ec2ModifySubnetAttribute stores MapPublicIpOnLaunch, which the
// provider waits to read back from DescribeSubnets. The other
// attributes it sends (AssignIpv6AddressOnCreation, EnableDns64, ...)
// are accepted and not stored: no scenario reads them back.
func (app *Application) ec2ModifySubnetAttribute(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	v := req.Params.Get("MapPublicIpOnLaunch.Value")
	err := app.repo.UpdateSubnet(account, region, req.Params.Get("SubnetId"), func(s *repository.EC2Subnet) {
		if v != "" {
			s.MapPublicIPOnLaunch = v == "true"
		}
	})
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	app.ec2NoOpSuccess(w, "ModifySubnetAttribute")
}

func (app *Application) ec2DeleteSubnet(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	subnetID := req.Params.Get("SubnetId")
	// Lazily GC any terminated instances in this subnet so the FK
	// constraint doesn't block the delete. Real AWS does this on a
	// ~60min timer; in the mock we mirror that semantics on demand.
	// terraform-provider-aws calls DeleteSubnet only after it has
	// already TerminateInstances'd everything that referenced it, so
	// purging terminated-state rows here is the right scope.
	instances, _ := app.repo.ListInstances(account, region)
	for _, inst := range instances {
		if inst.SubnetID == subnetID && inst.State == "terminated" {
			_ = app.repo.DeleteInstance(account, region, inst.ID)
		}
	}
	if err := app.repo.DeleteSubnet(account, region, subnetID); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DeleteSubnet", nil)
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
	return ec2VpcXML{
		VpcId:           v.ID,
		State:           v.State,
		CidrBlock:       v.CidrBlock,
		DhcpOptionsId:   "dopt-fakeaws-default",
		InstanceTenancy: "default",
		OwnerId:         awsproto.FakeAccountID,
		IsDefault:       false,
		CidrBlockAssociationSet: []ec2VpcCidrBlockAssociationXML{
			{
				AssociationId:  "vpc-cidr-assoc-" + v.ID,
				CidrBlock:      v.CidrBlock,
				CidrBlockState: ec2VpcCidrBlockAssociationState{State: "associated"},
			},
		},
	}
}

func ec2SubnetToXML(s *repository.EC2Subnet) ec2SubnetXML {
	// availableIpAddressCount derived from CIDR mask: /24 → 251 usable
	// (256 − 5 reserved by AWS), /25 → 123, etc. Defaults to 251 if
	// we can't parse the CIDR — close enough for tests that just
	// assert non-zero.
	available := 251
	if i := strings.LastIndexByte(s.CidrBlock, '/'); i >= 0 {
		var mask int
		fmt.Sscanf(s.CidrBlock[i+1:], "%d", &mask)
		if mask >= 16 && mask <= 28 {
			// 2^(32-mask) - 5 (AWS reserves .0, .1, .2, .3, broadcast)
			total := 1 << uint(32-mask)
			available = total - 5
		}
	}
	return ec2SubnetXML{
		SubnetId:                s.ID,
		VpcId:                   s.VPCID,
		State:                   s.State,
		CidrBlock:               s.CidrBlock,
		AvailabilityZone:        s.AvailabilityZone,
		AvailabilityZoneId:      s.AvailabilityZone + "-az1",
		AvailableIpAddressCount: available,
		OwnerId:                 awsproto.FakeAccountID,
		SubnetArn:               s.ARN,
		MapPublicIpOnLaunch:     s.MapPublicIPOnLaunch,
		PrivateDnsNameOptionsOnLaunch: &ec2SubnetPrivateDnsOptionsXML{
			HostnameType:                 "ip-name",
			EnableResourceNameDnsARecord: false,
		},
	}
}

// ----- InternetGateway handlers -----

type ec2IgwAttachmentXML struct {
	VpcId string `xml:"vpcId"`
	State string `xml:"state"`
}

type ec2IgwXML struct {
	InternetGatewayId string                `xml:"internetGatewayId"`
	OwnerId           string                `xml:"ownerId"`
	Attachments       []ec2IgwAttachmentXML `xml:"attachmentSet>item,omitempty"`
	TagSet            []ec2ResourceTagXML   `xml:"tagSet>item,omitempty"`
}

type ec2CreateIgwResult struct {
	InternetGateway ec2IgwXML `xml:"internetGateway"`
}

type ec2DescribeIgwsResult struct {
	InternetGatewaySet []ec2IgwXML `xml:"internetGatewaySet>item"`
}

func ec2IgwToXML(igw *repository.EC2InternetGateway) ec2IgwXML {
	out := ec2IgwXML{InternetGatewayId: igw.ID, OwnerId: awsproto.FakeAccountID}
	if igw.VPCID != "" {
		out.Attachments = []ec2IgwAttachmentXML{{VpcId: igw.VPCID, State: "available"}}
	}
	return out
}

func (app *Application) ec2CreateInternetGateway(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	specs, refused := refuseTagSpecifications(w, req.Params, "internet-gateway")
	if refused {
		return
	}
	id := "igw-" + ec2RandID()
	igw := &repository.EC2InternetGateway{
		ID: id, Region: region,
		ARN:       awsproto.BuildEC2InternetGatewayARN(region, id),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	err := app.repo.CreateInternetGateway(account, igw)
	if err == nil {
		err = app.tagNew(account, region, onResource(specs["internet-gateway"], id, "internet-gateway"),
			func() error { return app.repo.DeleteInternetGateway(account, region, id) })
	}
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "CreateInternetGateway", &ec2CreateIgwResult{InternetGateway: ec2IgwToXML(igw)})
}

// ec2DescribeInternetGateways answers InternetGatewayId.N with exactly
// those gateways, as ec2DescribeVpcs does VpcId.N.
func (app *Application) ec2DescribeInternetGateways(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	var igws []*repository.EC2InternetGateway
	ids := queryListValues(req.Params, "InternetGatewayId.")
	var err error
	if len(ids) == 0 {
		igws, err = app.repo.ListInternetGateways(account, region)
	}
	for _, id := range ids {
		var igw *repository.EC2InternetGateway
		igw, err = app.repo.GetInternetGateway(account, region, id)
		if errors.Is(err, models.ErrNotFound) {
			awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest,
				"InvalidInternetGatewayID.NotFound", fmt.Sprintf("The internetGateway ID '%s' does not exist", id))
			return
		}
		if err != nil {
			break
		}
		igws = append(igws, igw)
	}
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	tags, ok := app.tagSets(w, account)
	if !ok {
		return
	}
	out := ec2DescribeIgwsResult{InternetGatewaySet: make([]ec2IgwXML, 0, len(igws))}
	for _, igw := range igws {
		x := ec2IgwToXML(igw)
		x.TagSet = tags[igw.ID]
		out.InternetGatewaySet = append(out.InternetGatewaySet, x)
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DescribeInternetGateways", &out)
}

func (app *Application) ec2AttachInternetGateway(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	igwID := req.Params.Get("InternetGatewayId")
	vpcID := req.Params.Get("VpcId")
	if igwID == "" || vpcID == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
			fmt.Errorf("InternetGatewayId and VpcId required: %w", models.ErrConflict))
		return
	}
	if err := app.repo.AttachInternetGateway(account, region, igwID, vpcID); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "AttachInternetGateway", nil)
}

func (app *Application) ec2DetachInternetGateway(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	if err := app.repo.DetachInternetGateway(account, region, req.Params.Get("InternetGatewayId")); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DetachInternetGateway", nil)
}

func (app *Application) ec2DeleteInternetGateway(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	if err := app.repo.DeleteInternetGateway(account, region, req.Params.Get("InternetGatewayId")); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DeleteInternetGateway", nil)
}

// ----- RouteTable + Route handlers -----

type ec2RouteTableXML struct {
	RouteTableId string `xml:"routeTableId"`
	VpcId        string `xml:"vpcId"`
	OwnerId      string `xml:"ownerId"`
	// routeSet must appear in DescribeRouteTables responses so the
	// provider's CreateRoute wait-loop can confirm the new entry
	// landed (otherwise: 5-minute timeout per iter).
	Routes []ec2RouteXML `xml:"routeSet>item,omitempty"`
	// associationSet — same wait-loop story for aws_route_table_association.
	// Provider polls DescribeRouteTables looking for the new association
	// in this set; without it the wait times out at 5 min.
	Associations []ec2RouteTableAssociationXML `xml:"associationSet>item,omitempty"`
	TagSet       []ec2ResourceTagXML           `xml:"tagSet>item,omitempty"`
}

type ec2RouteTableAssociationXML struct {
	AssociationId string `xml:"routeTableAssociationId"`
	RouteTableId  string `xml:"routeTableId"`
	SubnetId      string `xml:"subnetId"`
	// AssociationState is the structured indicator the provider uses
	// to decide whether the association is ready. "associated" is the
	// terminal state; nothing else exists in our model.
	AssociationState struct {
		State string `xml:"state"`
	} `xml:"associationState"`
}

type ec2CreateRouteTableResult struct {
	RouteTable ec2RouteTableXML `xml:"routeTable"`
}

// ec2RouteXML mirrors the per-route entry under <routeSet><item>. The
// provider's CreateRoute wait-loop polls DescribeRouteTables and looks
// for its destination CIDR in this set; without it, the wait times
// out after 5 minutes per iteration. Real EC2 also includes a State
// field ("active" once the route is installed) — we always emit
// "active" because there's no async install step in the mock.
type ec2RouteXML struct {
	DestinationCidrBlock string `xml:"destinationCidrBlock"`
	GatewayId            string `xml:"gatewayId,omitempty"`
	NatGatewayId         string `xml:"natGatewayId,omitempty"`
	InstanceId           string `xml:"instanceId,omitempty"`
	NetworkInterfaceId   string `xml:"networkInterfaceId,omitempty"`
	State                string `xml:"state"`
	Origin               string `xml:"origin"`
}

type ec2AssociateRouteTableResult struct {
	AssociationId string `xml:"associationId"`
}

type ec2CreateRouteResult struct {
	Return bool `xml:"return"`
}

func (app *Application) ec2CreateRouteTable(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	vpcID := req.Params.Get("VpcId")
	if vpcID == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
			fmt.Errorf("VpcId required: %w", models.ErrConflict))
		return
	}
	specs, refused := refuseTagSpecifications(w, req.Params, "route-table")
	if refused {
		return
	}
	id := "rtb-" + ec2RandID()
	rt := &repository.EC2RouteTable{
		ID: id, VPCID: vpcID, Region: region,
		ARN:       awsproto.BuildEC2RouteTableARN(region, id),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	err := app.repo.CreateRouteTable(account, rt)
	if err == nil {
		err = app.tagNew(account, region, onResource(specs["route-table"], id, "route-table"),
			func() error { return app.repo.DeleteRouteTable(account, region, id) })
	}
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "CreateRouteTable",
		&ec2CreateRouteTableResult{RouteTable: ec2RouteTableXML{RouteTableId: rt.ID, VpcId: rt.VPCID, OwnerId: awsproto.FakeAccountID}})
}

// ec2NoOpSuccess returns a minimal 200 response for EC2 actions we
// accept but don't model. Real EC2 returns an action-named envelope
// with a <return>true</return> child for these mutating actions —
// the provider just needs the envelope shape to parse successfully.
func (app *Application) ec2NoOpSuccess(w http.ResponseWriter, action string) {
	awsproto.WriteEC2QueryRPCResponse(w, action, &struct {
		Return bool `xml:"return"`
	}{Return: true})
}

// ec2DescribeRouteTablesResult mirrors the AWS EC2 DescribeRouteTables
// response. Provider's create wait-loop polls this right after
// CreateRouteTable to confirm the RT exists; without the handler the
// default-arm returned 404 and the wait timed out.
type ec2DescribeRouteTablesResult struct {
	RouteTableSet []ec2RouteTableXML `xml:"routeTableSet>item"`
}

// rtFilterValues are the DescribeRouteTables filters fakeaws models:
// the ones the provider's lookups by VPC and by association id send.
// fakeaws models no main route table, so every association is
// main=false.
var rtFilterValues = map[string]func(rt ec2RouteTableXML) []string{
	"vpc-id": func(rt ec2RouteTableXML) []string { return []string{rt.VpcId} },
	"association.route-table-association-id": func(rt ec2RouteTableXML) []string {
		var ids []string
		for _, a := range rt.Associations {
			ids = append(ids, a.AssociationId)
		}
		return ids
	},
	"association.main": func(rt ec2RouteTableXML) []string {
		if len(rt.Associations) == 0 {
			return nil
		}
		return []string{"false"}
	},
}

func (app *Application) ec2DescribeRouteTables(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	filters := ec2Filters(req.Params)
	for name := range filters {
		if rtFilterValues[name] == nil {
			awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
				fmt.Errorf("DescribeRouteTables filter %q not supported by fakeaws: %w", name, models.ErrConflict))
			return
		}
	}
	var wanted []string
	for k, vs := range req.Params {
		if strings.HasPrefix(k, "RouteTableId.") && len(vs) > 0 {
			wanted = append(wanted, vs[0])
		}
	}
	// Pre-load all routes once and key by route_table_id so the
	// per-RT lookup below is O(1). ListRoutes returns the union for
	// the account; we filter by RT id at populate time.
	allRoutes, _ := app.repo.ListRoutes(account)
	routesByRT := make(map[string][]ec2RouteXML, len(allRoutes))
	for _, rt := range allRoutes {
		routesByRT[rt.RouteTableID] = append(routesByRT[rt.RouteTableID], ec2RouteXML{
			DestinationCidrBlock: rt.DestinationCidrBlock,
			GatewayId:            rt.GatewayID,
			NatGatewayId:         rt.NatGatewayID,
			InstanceId:           rt.InstanceID,
			NetworkInterfaceId:   rt.NetworkInterfaceID,
			State:                "active",
			Origin:               "CreateRoute",
		})
	}
	// Same trick for associations — populate <associationSet> so the
	// CreateAssociation wait-loop terminates.
	allAssocs, _ := app.repo.ListRouteTableAssociations(account)
	assocsByRT := make(map[string][]ec2RouteTableAssociationXML, len(allAssocs))
	for _, a := range allAssocs {
		x := ec2RouteTableAssociationXML{
			AssociationId: a.ID, RouteTableId: a.RouteTableID, SubnetId: a.SubnetID,
		}
		x.AssociationState.State = "associated"
		assocsByRT[a.RouteTableID] = append(assocsByRT[a.RouteTableID], x)
	}
	tags, ok := app.tagSets(w, account)
	if !ok {
		return
	}
	out := ec2DescribeRouteTablesResult{RouteTableSet: []ec2RouteTableXML{}}
	if len(wanted) == 0 {
		rts, err := app.repo.ListRouteTables(account, region)
		if err != nil {
			awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
			return
		}
		for _, rt := range rts {
			out.RouteTableSet = append(out.RouteTableSet, ec2RouteTableXML{
				RouteTableId: rt.ID, VpcId: rt.VPCID, OwnerId: awsproto.FakeAccountID,
				Routes:       routesByRT[rt.ID],
				Associations: assocsByRT[rt.ID],
				TagSet:       tags[rt.ID],
			})
		}
	} else {
		for _, id := range wanted {
			rt, err := app.repo.GetRouteTable(account, region, id)
			if err != nil {
				// Mirror the SG fix: surface the AWS-specific code
				// terraform-provider-aws's destroy wait-loop expects
				// rather than the generic ResourceNotFoundException.
				if errors.Is(err, models.ErrNotFound) {
					awsproto.WriteServiceError(w, awsproto.ShapeEC2Query,
						http.StatusNotFound, "InvalidRouteTableID.NotFound",
						fmt.Sprintf("The route table ID '%s' does not exist", id))
					return
				}
				awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
				return
			}
			out.RouteTableSet = append(out.RouteTableSet, ec2RouteTableXML{
				RouteTableId: rt.ID, VpcId: rt.VPCID, OwnerId: awsproto.FakeAccountID,
				Routes:       routesByRT[rt.ID],
				Associations: assocsByRT[rt.ID],
				TagSet:       tags[rt.ID],
			})
		}
	}
	out.RouteTableSet = slices.DeleteFunc(out.RouteTableSet, func(rt ec2RouteTableXML) bool {
		for name, want := range filters {
			if !slices.ContainsFunc(rtFilterValues[name](rt), func(v string) bool { return slices.Contains(want, v) }) {
				return true
			}
		}
		return false
	})
	awsproto.WriteEC2QueryRPCResponse(w, "DescribeRouteTables", &out)
}

func (app *Application) ec2DeleteRouteTable(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	if err := app.repo.DeleteRouteTable(account, region, req.Params.Get("RouteTableId")); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DeleteRouteTable", nil)
}

func (app *Application) ec2AssociateRouteTable(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	rtID := req.Params.Get("RouteTableId")
	subnetID := req.Params.Get("SubnetId")
	if rtID == "" || subnetID == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
			fmt.Errorf("RouteTableId and SubnetId required: %w", models.ErrConflict))
		return
	}
	assoc := &repository.EC2RouteTableAssociation{
		ID: "rtbassoc-" + ec2RandID(), RouteTableID: rtID, SubnetID: subnetID,
	}
	if err := app.repo.AssociateRouteTable(account, region, assoc); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "AssociateRouteTable",
		&ec2AssociateRouteTableResult{AssociationId: assoc.ID})
}

func (app *Application) ec2DisassociateRouteTable(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	if err := app.repo.DisassociateRouteTable(account, req.Params.Get("AssociationId")); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DisassociateRouteTable", nil)
}

func (app *Application) ec2CreateRoute(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	rt := &repository.EC2Route{
		RouteTableID:         req.Params.Get("RouteTableId"),
		DestinationCidrBlock: req.Params.Get("DestinationCidrBlock"),
		GatewayID:            req.Params.Get("GatewayId"),
		NatGatewayID:         req.Params.Get("NatGatewayId"),
		InstanceID:           req.Params.Get("InstanceId"),
		NetworkInterfaceID:   req.Params.Get("NetworkInterfaceId"),
	}
	if rt.RouteTableID == "" || rt.DestinationCidrBlock == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
			fmt.Errorf("RouteTableId and DestinationCidrBlock required: %w", models.ErrConflict))
		return
	}
	if err := app.repo.CreateRoute(account, region, rt); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "CreateRoute", &ec2CreateRouteResult{Return: true})
}

func (app *Application) ec2DeleteRoute(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	if err := app.repo.DeleteRoute(account, region,
		req.Params.Get("RouteTableId"), req.Params.Get("DestinationCidrBlock")); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DeleteRoute", nil)
}

// ----- EIP handlers -----

type ec2AddressXML struct {
	AllocationId       string              `xml:"allocationId"`
	PublicIp           string              `xml:"publicIp"`
	Domain             string              `xml:"domain"`
	AssociationId      string              `xml:"associationId,omitempty"`
	InstanceId         string              `xml:"instanceId,omitempty"`
	NetworkInterfaceId string              `xml:"networkInterfaceId,omitempty"`
	PrivateIpAddress   string              `xml:"privateIpAddress,omitempty"`
	TagSet             []ec2ResourceTagXML `xml:"tagSet>item,omitempty"`
}

type ec2AllocateAddressResult struct {
	AllocationId string `xml:"allocationId"`
	PublicIp     string `xml:"publicIp"`
	Domain       string `xml:"domain"`
}

type ec2DescribeAddressesResult struct {
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
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
			fmt.Errorf("Domain=%q not supported (v1 supports 'vpc' only): %w", domain, models.ErrConflict))
		return
	}
	specs, refused := refuseTagSpecifications(w, req.Params, "elastic-ip")
	if refused {
		return
	}
	allocID := "eipalloc-" + ec2RandID()
	eip := &repository.EC2EIP{
		AllocationID: allocID, Domain: domain,
		PublicIP:  ec2DerivePublicIP(allocID),
		Region:    region,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	err := app.repo.CreateEIP(account, eip)
	if err == nil {
		err = app.tagNew(account, region, onResource(specs["elastic-ip"], allocID, "elastic-ip"),
			func() error { return app.repo.DeleteEIP(account, region, allocID) })
	}
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "AllocateAddress",
		&ec2AllocateAddressResult{AllocationId: eip.AllocationID, PublicIp: eip.PublicIP, Domain: eip.Domain})
}

// ec2FindAddresses looks up each AllocationId.N or, with none, lists
// every address in the region. It writes the error itself,
// InvalidAllocationID.NotFound for a missing one as EC2 does, and
// reports false.
func (app *Application) ec2FindAddresses(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) ([]*repository.EC2EIP, bool) {
	ids := queryListValues(req.Params, "AllocationId.")
	if len(ids) == 0 {
		eips, err := app.repo.ListEIPs(account, region)
		if err != nil {
			awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
			return nil, false
		}
		return eips, true
	}
	var out []*repository.EC2EIP
	for _, id := range ids {
		eip, err := app.repo.GetEIP(account, region, id)
		if err != nil {
			writeEIPError(w, id, err)
			return nil, false
		}
		out = append(out, eip)
	}
	return out, true
}

// writeEIPError answers a failed address lookup or release with the
// code EC2 uses: InvalidAllocationID.NotFound for a missing address,
// InvalidIPAddress.InUse for releasing an associated one.
func writeEIPError(w http.ResponseWriter, id string, err error) {
	switch {
	case errors.Is(err, models.ErrNotFound):
		awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest,
			"InvalidAllocationID.NotFound", fmt.Sprintf("The allocation ID '%s' does not exist", id))
	case errors.Is(err, models.ErrInUse):
		awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest,
			"InvalidIPAddress.InUse", fmt.Sprintf("Address '%s' is in use.", id))
	default:
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
	}
}

// ec2DescribeAddresses answers the AllocationId.N lookup the provider
// makes, its association-id filter after AssociateAddress and, with
// neither, the scope sweep's list of every address. Other filters and
// PublicIp.N are refused rather than ignored.
func (app *Application) ec2DescribeAddresses(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	if refuseUnmodelled(w, req, "PublicIp.") {
		return
	}
	filters := ec2Filters(req.Params)
	for name := range filters {
		if name != "association-id" {
			awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
				fmt.Errorf("DescribeAddresses filter %q not supported by fakeaws: %w", name, models.ErrConflict))
			return
		}
	}
	eips, ok := app.ec2FindAddresses(w, account, region, req)
	if !ok {
		return
	}
	tags, ok := app.tagSets(w, account)
	if !ok {
		return
	}
	out := ec2DescribeAddressesResult{AddressSet: []ec2AddressXML{}}
	for _, eip := range eips {
		if want, ok := filters["association-id"]; ok && !slices.Contains(want, eip.AssociationID) {
			continue
		}
		out.AddressSet = append(out.AddressSet, ec2AddressXML{
			AllocationId: eip.AllocationID, PublicIp: eip.PublicIP, Domain: eip.Domain,
			AssociationId: eip.AssociationID, InstanceId: eip.InstanceID,
			NetworkInterfaceId: eip.NetworkInterfaceID, PrivateIpAddress: eip.PrivateIP,
			TagSet: tags[eip.AllocationID],
		})
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DescribeAddresses", &out)
}

type ec2AddressAttributeXML struct {
	AllocationId string `xml:"allocationId"`
	PublicIp     string `xml:"publicIp"`
}

type ec2DescribeAddressesAttributeResult struct {
	AddressSet []ec2AddressAttributeXML `xml:"addressSet>item"`
}

// ec2DescribeAddressesAttribute answers aws_eip's read of its
// domain-name attribute: fakeaws sets no reverse DNS record, so each
// address comes back without a ptrRecord.
func (app *Application) ec2DescribeAddressesAttribute(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	eips, ok := app.ec2FindAddresses(w, account, region, req)
	if !ok {
		return
	}
	out := ec2DescribeAddressesAttributeResult{AddressSet: []ec2AddressAttributeXML{}}
	for _, eip := range eips {
		out.AddressSet = append(out.AddressSet, ec2AddressAttributeXML{AllocationId: eip.AllocationID, PublicIp: eip.PublicIP})
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DescribeAddressesAttribute", &out)
}

func (app *Application) ec2ReleaseAddress(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	id := req.Params.Get("AllocationId")
	if err := app.repo.DeleteEIP(account, region, id); err != nil {
		writeEIPError(w, id, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "ReleaseAddress", nil)
}

type ec2AssociateAddressResult struct {
	AssociationId string `xml:"associationId"`
}

// ec2AssociateAddress attaches an address to an instance's primary
// ENI, or to an ENI named directly: the association goes on the
// address and its public IP becomes the ENI's, as on EC2. An address
// already associated, or an ENI that already has one, is
// Resource.AlreadyAssociated.
// ponytail: AllowReassociation is refused, not modelled; the provider
// disassociates before it re-points an address.
func (app *Application) ec2AssociateAddress(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	allocID := req.Params.Get("AllocationId")
	eip, err := app.repo.GetEIP(account, region, allocID)
	if err != nil {
		writeEIPError(w, allocID, err)
		return
	}
	eni, ok := app.associationTarget(w, account, region, req)
	if !ok {
		return
	}
	if ip := req.Params.Get("PrivateIpAddress"); ip != "" && ip != eni.PrivateIP {
		awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest, "InvalidParameterValue",
			fmt.Sprintf("The private IP address %s is not assigned to network interface %s", ip, eni.ID))
		return
	}
	if req.Params.Get("AllowReassociation") == "true" {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
			fmt.Errorf("AssociateAddress AllowReassociation not supported by fakeaws: %w", models.ErrConflict))
		return
	}
	eip.AssociationID = "eipassoc-" + ec2RandID()
	eip.InstanceID, eip.NetworkInterfaceID, eip.PrivateIP = eni.InstanceID, eni.ID, eni.PrivateIP
	eni.PublicIP = eip.PublicIP
	err = app.repo.AssociateEIP(account, eip, eni)
	if errors.Is(err, models.ErrConflict) {
		awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest, "Resource.AlreadyAssociated",
			fmt.Sprintf("resource %s or network interface %s is already associated with an Elastic IP", allocID, eni.ID))
		return
	}
	if err != nil {
		writeEIPError(w, allocID, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "AssociateAddress", &ec2AssociateAddressResult{AssociationId: eip.AssociationID})
}

// associationTarget resolves AssociateAddress's InstanceId (to its
// primary ENI) or NetworkInterfaceId. It writes the error itself, a
// missing id as 400 as EC2 does, and reports false.
func (app *Application) associationTarget(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) (*repository.EC2NetworkInterface, bool) {
	instanceID, eniID := req.Params.Get("InstanceId"), req.Params.Get("NetworkInterfaceId")
	if eniID != "" {
		eni, err := app.repo.GetNetworkInterface(account, region, eniID)
		if errors.Is(err, models.ErrNotFound) {
			awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest,
				"InvalidNetworkInterfaceID.NotFound", fmt.Sprintf("The networkInterface ID '%s' does not exist", eniID))
			return nil, false
		}
		if err != nil {
			awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
			return nil, false
		}
		if instanceID != "" && instanceID != eni.InstanceID {
			awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest, "InvalidParameterCombination",
				fmt.Sprintf("Network interface %s is not attached to instance %s", eniID, instanceID))
			return nil, false
		}
		return eni, true
	}
	if instanceID == "" {
		awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest, "MissingParameter",
			"Either an instance ID or a network interface ID must be specified")
		return nil, false
	}
	_, err := app.repo.GetInstance(account, region, instanceID)
	if errors.Is(err, models.ErrNotFound) {
		awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest,
			"InvalidInstanceID.NotFound", fmt.Sprintf("The instance ID '%s' does not exist", instanceID))
		return nil, false
	}
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return nil, false
	}
	enis, err := app.instanceENIs(account)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return nil, false
	}
	eni := enis[instanceID]
	if eni == nil { // terminated: its ENI is gone
		awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest, "InvalidInstanceID",
			fmt.Sprintf("The instance '%s' is not in a valid state for this operation", instanceID))
		return nil, false
	}
	return eni, true
}

// ec2DisassociateAddress clears the association AssociationId names,
// and the ENI gets back the public IP its launch gave it, if any. An
// unknown association is InvalidAssociationID.NotFound, which the
// provider reads as already detached.
func (app *Application) ec2DisassociateAddress(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	assocID := req.Params.Get("AssociationId")
	eips, err := app.repo.ListEIPs(account, region)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	i := slices.IndexFunc(eips, func(e *repository.EC2EIP) bool { return assocID != "" && e.AssociationID == assocID })
	if i < 0 {
		awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest, "InvalidAssociationID.NotFound",
			fmt.Sprintf("The association ID '%s' does not exist", assocID))
		return
	}
	eip := eips[i]
	eni, err := app.repo.GetNetworkInterface(account, region, eip.NetworkInterfaceID)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	eni.PublicIP = ""
	if eni.AutoPublicIP {
		eni.PublicIP = ec2DerivePublicIP(eni.ID)
	}
	eip.AssociationID, eip.InstanceID, eip.NetworkInterfaceID, eip.PrivateIP = "", "", "", ""
	if err := app.repo.DisassociateEIP(account, eip, eni); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DisassociateAddress", nil)
}

// ----- SecurityGroup handlers -----
//
// AWS SG rules are passed as flattened Query params:
//   IpPermissions.1.IpProtocol = tcp
//   IpPermissions.1.FromPort   = 443
//   IpPermissions.1.ToPort     = 443
//   IpPermissions.1.IpRanges.1.CidrIp             = 0.0.0.0/0
//   IpPermissions.1.Ipv6Ranges.1.CidrIpv6         = ::/0
//   IpPermissions.1.Groups.1.GroupId              = sg-...  (UserIdGroupPairs)
//   IpPermissions.1.PrefixListIds.1.PrefixListId  = pl-...
// and every source may carry a .Description. We persist them as JSON
// in the ingress/egress columns; the json tags are the stored keys and
// the xml tags are the DescribeSecurityGroups element names.
//
// CRITICAL[ec2-sg-rule-source-descriptions-round-trip]: every source
// (IpRanges, Ipv6Ranges, Groups, PrefixListIds) MUST come back from
// DescribeSecurityGroups on its own item with its own Description.
// terraform-provider-aws's securityGroupIPPermGather groups remote
// sources into rules keyed by (protocol, ports, description); a
// dropped source or description reads back as a different rule and
// `plan` shows a diff that never converges.

type ec2IpRange struct {
	CidrIp      string `json:"CidrIp" xml:"cidrIp"`
	Description string `json:"Description,omitempty" xml:"description,omitempty"`
}

type ec2Ipv6Range struct {
	CidrIpv6    string `json:"CidrIpv6" xml:"cidrIpv6"`
	Description string `json:"Description,omitempty" xml:"description,omitempty"`
}

type ec2UserIdGroupPair struct {
	GroupId     string `json:"GroupId" xml:"groupId"`
	UserId      string `json:"UserId,omitempty" xml:"userId,omitempty"`
	Description string `json:"Description,omitempty" xml:"description,omitempty"`
}

type ec2PrefixListId struct {
	PrefixListId string `json:"PrefixListId" xml:"prefixListId"`
	Description  string `json:"Description,omitempty" xml:"description,omitempty"`
}

type ec2IpPermission struct {
	IpProtocol       string               `json:"IpProtocol" xml:"ipProtocol"`
	FromPort         int                  `json:"FromPort" xml:"fromPort"`
	ToPort           int                  `json:"ToPort" xml:"toPort"`
	IpRanges         []ec2IpRange         `json:"IpRanges,omitempty" xml:"ipRanges>item,omitempty"`
	Ipv6Ranges       []ec2Ipv6Range       `json:"Ipv6Ranges,omitempty" xml:"ipv6Ranges>item,omitempty"`
	UserIdGroupPairs []ec2UserIdGroupPair `json:"UserIdGroupPairs,omitempty" xml:"groups>item,omitempty"`
	PrefixListIds    []ec2PrefixListId    `json:"PrefixListIds,omitempty" xml:"prefixListIds>item,omitempty"`
}

// ec2RuleSource is one source inside a permission. key is what AWS
// matches on for Authorize dedupe and Revoke; state is the snake_case
// /mock/state rendering.
type ec2RuleSource interface {
	key() string
	state() map[string]any
}

func (r ec2IpRange) key() string { return r.CidrIp }
func (r ec2IpRange) state() map[string]any {
	return map[string]any{"cidr_ip": r.CidrIp, "description": r.Description}
}

func (r ec2Ipv6Range) key() string { return r.CidrIpv6 }
func (r ec2Ipv6Range) state() map[string]any {
	return map[string]any{"cidr_ipv6": r.CidrIpv6, "description": r.Description}
}

func (g ec2UserIdGroupPair) key() string { return g.GroupId }
func (g ec2UserIdGroupPair) state() map[string]any {
	return map[string]any{"group_id": g.GroupId, "user_id": g.UserId, "description": g.Description}
}

func (p ec2PrefixListId) key() string { return p.PrefixListId }
func (p ec2PrefixListId) state() map[string]any {
	return map[string]any{"prefix_list_id": p.PrefixListId, "description": p.Description}
}

type ec2SecurityGroupXML struct {
	GroupId       string              `xml:"groupId"`
	GroupName     string              `xml:"groupName"`
	GroupDesc     string              `xml:"groupDescription"`
	VpcId         string              `xml:"vpcId"`
	OwnerId       string              `xml:"ownerId"`
	IpPermissions []ec2IpPermission   `xml:"ipPermissions>item,omitempty"`
	IpPermsEgress []ec2IpPermission   `xml:"ipPermissionsEgress>item,omitempty"`
	TagSet        []ec2ResourceTagXML `xml:"tagSet>item,omitempty"`
}

type ec2CreateSecurityGroupResult struct {
	GroupId string `xml:"groupId"`
}

type ec2DescribeSecurityGroupsResult struct {
	SecurityGroupSet []ec2SecurityGroupXML `xml:"securityGroupInfo>item"`
}

// queryListItems returns the item prefixes ("<prefix><n>.") of a
// flattened Query-RPC list, in numeric <n> order so stored rules keep
// the order the caller sent.
func queryListItems(params url.Values, prefix string) []string {
	seen := map[string]bool{}
	var ns []string
	for k := range params {
		rest, ok := strings.CutPrefix(k, prefix)
		if !ok {
			continue
		}
		if i := strings.Index(rest, "."); i > 0 && !seen[rest[:i]] {
			seen[rest[:i]] = true
			ns = append(ns, rest[:i])
		}
	}
	slices.SortFunc(ns, func(a, b string) int {
		return cmp.Or(cmp.Compare(len(a), len(b)), strings.Compare(a, b))
	})
	items := make([]string, len(ns))
	for i, n := range ns {
		items[i] = prefix + n + "."
	}
	return items
}

// parseIpPermissions reads the flattened IpPermissions.<n>.* params
// out of the Query-RPC body.
func parseIpPermissions(req awsproto.QueryRPCRequest) []ec2IpPermission {
	var out []ec2IpPermission
	for _, base := range queryListItems(req.Params, "IpPermissions.") {
		out = append(out, parseIpPermission(req.Params, base))
	}
	return out
}

func parseIpPermission(p url.Values, base string) ec2IpPermission {
	perm := ec2IpPermission{IpProtocol: p.Get(base + "IpProtocol")}
	perm.FromPort, _ = strconv.Atoi(p.Get(base + "FromPort"))
	perm.ToPort, _ = strconv.Atoi(p.Get(base + "ToPort"))
	for _, it := range queryListItems(p, base+"IpRanges.") {
		if v := p.Get(it + "CidrIp"); v != "" {
			perm.IpRanges = append(perm.IpRanges, ec2IpRange{CidrIp: v, Description: p.Get(it + "Description")})
		}
	}
	for _, it := range queryListItems(p, base+"Ipv6Ranges.") {
		if v := p.Get(it + "CidrIpv6"); v != "" {
			perm.Ipv6Ranges = append(perm.Ipv6Ranges, ec2Ipv6Range{CidrIpv6: v, Description: p.Get(it + "Description")})
		}
	}
	for _, it := range queryListItems(p, base+"Groups.") {
		if v := p.Get(it + "GroupId"); v != "" {
			perm.UserIdGroupPairs = append(perm.UserIdGroupPairs, ec2UserIdGroupPair{
				GroupId: v, UserId: p.Get(it + "UserId"), Description: p.Get(it + "Description"),
			})
		}
	}
	for _, it := range queryListItems(p, base+"PrefixListIds.") {
		if v := p.Get(it + "PrefixListId"); v != "" {
			perm.PrefixListIds = append(perm.PrefixListIds, ec2PrefixListId{PrefixListId: v, Description: p.Get(it + "Description")})
		}
	}
	return perm
}

// decodeSGRules unmarshals an ingress/egress column.
func decodeSGRules(raw []byte) ([]ec2IpPermission, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var perms []ec2IpPermission
	if err := json.Unmarshal(raw, &perms); err != nil {
		return nil, err
	}
	return perms, nil
}

func (app *Application) ec2CreateSecurityGroup(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	groupName := req.Params.Get("GroupName")
	desc := req.Params.Get("GroupDescription")
	vpcID := req.Params.Get("VpcId")
	if groupName == "" || desc == "" || vpcID == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
			fmt.Errorf("GroupName, GroupDescription, and VpcId required: %w", models.ErrConflict))
		return
	}
	specs, refused := refuseTagSpecifications(w, req.Params, "security-group")
	if refused {
		return
	}
	id := "sg-" + ec2RandID()
	sg := &repository.EC2SecurityGroup{
		ID: id, VPCID: vpcID, GroupName: groupName, Description: desc,
		Region:    region,
		ARN:       awsproto.BuildEC2SecurityGroupARN(region, id),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	err := app.repo.CreateSecurityGroup(account, sg)
	if err == nil {
		err = app.tagNew(account, region, onResource(specs["security-group"], id, "security-group"),
			func() error { return app.repo.DeleteSecurityGroup(account, region, id) })
	}
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "CreateSecurityGroup",
		&ec2CreateSecurityGroupResult{GroupId: sg.ID})
}

// ec2FindSecurityGroups looks up each GroupId.N or, with none, lists
// every group in the region. It writes the error itself and reports
// false.
func (app *Application) ec2FindSecurityGroups(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) ([]*repository.EC2SecurityGroup, bool) {
	ids := queryListValues(req.Params, "GroupId.")
	if len(ids) == 0 {
		sgs, err := app.repo.ListSecurityGroups(account, region)
		if err != nil {
			awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
			return nil, false
		}
		return sgs, true
	}
	var out []*repository.EC2SecurityGroup
	for _, id := range ids {
		sg, err := app.repo.GetSecurityGroup(account, region, id)
		// terraform-provider-aws's destroy wait-loop polls
		// DescribeSecurityGroups({sg-id}) after DeleteSecurityGroup
		// and treats EXACTLY the AWS code "InvalidGroup.NotFound"
		// as "deletion complete". A generic ResourceNotFoundException
		// (the default mapDomainError gives) is treated as an
		// unexpected hard error and the wait bails out, leaving
		// the SG marked as undeleted in state. Surface the
		// service-specific code on this read path so destroy
		// drains cleanly. Same pattern as the WriteServiceError
		// note for RDS's DBInstanceNotFound.
		if errors.Is(err, models.ErrNotFound) {
			awsproto.WriteServiceError(w, awsproto.ShapeEC2Query,
				http.StatusNotFound, "InvalidGroup.NotFound",
				fmt.Sprintf("The security group ID '%s' does not exist", id))
			return nil, false
		}
		if err != nil {
			awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
			return nil, false
		}
		out = append(out, sg)
	}
	return out, true
}

// ec2DescribeSecurityGroups answers the provider's GroupId.N lookup
// and, with none, the scope sweep's list of every group. Filter.N and
// GroupName.N are refused rather than ignored.
func (app *Application) ec2DescribeSecurityGroups(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	if refuseUnmodelled(w, req, "Filter.", "GroupName.") {
		return
	}
	sgs, ok := app.ec2FindSecurityGroups(w, account, region, req)
	if !ok {
		return
	}
	tags, ok := app.tagSets(w, account)
	if !ok {
		return
	}
	out := ec2DescribeSecurityGroupsResult{SecurityGroupSet: make([]ec2SecurityGroupXML, 0, len(sgs))}
	for _, sg := range sgs {
		ing, eg, err := app.repo.GetSecurityGroupRules(account, region, sg.ID)
		if err != nil {
			awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
			return
		}
		ingress, ingErr := decodeSGRules(ing)
		egress, egErr := decodeSGRules(eg)
		if err := errors.Join(ingErr, egErr); err != nil {
			awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
			return
		}
		out.SecurityGroupSet = append(out.SecurityGroupSet, ec2SecurityGroupXML{
			GroupId: sg.ID, GroupName: sg.GroupName, GroupDesc: sg.Description, VpcId: sg.VPCID,
			OwnerId:       awsproto.FakeAccountID,
			IpPermissions: ingress,
			IpPermsEgress: egress,
			TagSet:        tags[sg.ID],
		})
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DescribeSecurityGroups", &out)
}

func (app *Application) ec2DeleteSecurityGroup(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	id := req.Params.Get("GroupId")
	if id == "" {
		// AWS also accepts GroupName for non-VPC SGs; v1 supports GroupId only.
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
			fmt.Errorf("GroupId required: %w", models.ErrConflict))
		return
	}
	if err := app.repo.DeleteSecurityGroup(account, region, id); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DeleteSecurityGroup", nil)
}

// ec2AuthorizeSecurityGroupRules adds the parsed IpPermissions to the
// SG's existing direction column. Authorize is additive at the AWS
// contract; we union with the existing rules and dedupe by
// (proto, from, to, range-set).
func (app *Application) ec2AuthorizeSecurityGroupRules(w http.ResponseWriter, account, region, direction string, req awsproto.QueryRPCRequest) {
	sgID := req.Params.Get("GroupId")
	if sgID == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
			fmt.Errorf("GroupId required: %w", models.ErrConflict))
		return
	}
	add := parseIpPermissions(req)
	if len(add) == 0 {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
			fmt.Errorf("at least one IpPermissions.<n>.* required: %w", models.ErrConflict))
		return
	}
	if app.refuseIpPermissions(w, account, region, add) {
		return
	}
	existing, err := loadSGRules(app, account, region, sgID, direction)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	merged := mergeIpPermissions(existing, add)
	body, _ := json.Marshal(merged)
	if err := app.repo.UpdateSecurityGroupRules(account, region, sgID, direction, body); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	action := "AuthorizeSecurityGroupIngress"
	if direction == "egress" {
		action = "AuthorizeSecurityGroupEgress"
	}
	awsproto.WriteEC2QueryRPCResponse(w, action, nil)
}

func (app *Application) ec2RevokeSecurityGroupRules(w http.ResponseWriter, account, region, direction string, req awsproto.QueryRPCRequest) {
	sgID := req.Params.Get("GroupId")
	if sgID == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
			fmt.Errorf("GroupId required: %w", models.ErrConflict))
		return
	}
	rm := parseIpPermissions(req)
	existing, err := loadSGRules(app, account, region, sgID, direction)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	remaining := subtractIpPermissions(existing, rm)
	body, _ := json.Marshal(remaining)
	if err := app.repo.UpdateSecurityGroupRules(account, region, sgID, direction, body); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	action := "RevokeSecurityGroupIngress"
	if direction == "egress" {
		action = "RevokeSecurityGroupEgress"
	}
	awsproto.WriteEC2QueryRPCResponse(w, action, nil)
}

// refuseIpPermissions writes the error real EC2 answers for the first
// permission it would refuse, and reports whether it wrote one. The
// provider only checks CIDRs at plan time, so bad ports and protocols
// reach us. A group pair naming another account's UserId is admitted:
// the fake cannot see other accounts.
func (app *Application) refuseIpPermissions(w http.ResponseWriter, account, region string, perms []ec2IpPermission) bool {
	for _, p := range perms {
		if msg := ipPermissionProblem(p); msg != "" {
			awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest, "InvalidParameterValue", msg)
			return true
		}
		for _, g := range p.UserIdGroupPairs {
			if g.UserId != "" && g.UserId != account {
				continue
			}
			_, err := app.repo.GetSecurityGroup(account, region, g.GroupId)
			if errors.Is(err, models.ErrNotFound) {
				awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest,
					"InvalidGroup.NotFound", fmt.Sprintf("The security group '%s' does not exist", g.GroupId))
				return true
			}
			if err != nil {
				awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
				return true
			}
		}
	}
	return false
}

// ipPermissionProblem returns the InvalidParameterValue message EC2
// gives for p, or "" when EC2 accepts it. Sources for each message are
// cited in TestEC2_SecurityGroupRuleValidation.
func ipPermissionProblem(p ec2IpPermission) string {
	for _, r := range p.IpRanges {
		if pfx, err := netip.ParsePrefix(r.CidrIp); err != nil || !pfx.Addr().Is4() {
			return fmt.Sprintf("CIDR block %s is malformed", r.CidrIp)
		}
	}
	for _, r := range p.Ipv6Ranges {
		if pfx, err := netip.ParsePrefix(r.CidrIpv6); err != nil || !pfx.Addr().Is6() {
			return fmt.Sprintf("CIDR block %s is malformed", r.CidrIpv6)
		}
	}
	switch strings.ToLower(p.IpProtocol) {
	case "tcp", "udp", "6", "17":
		return tcpUDPPortProblem(p)
	case "icmp", "icmpv6", "1", "58":
		return icmpProblem(p)
	case "-1":
		// A literal "all" falls through and is refused, as EC2 does
		// (terraform-provider-aws#1793); the provider sends -1 for it.
		return ""
	}
	if n, err := strconv.Atoi(p.IpProtocol); err != nil || n < 0 || n > 255 {
		return fmt.Sprintf("Invalid value '%s' for IP protocol. Unknown protocol.", p.IpProtocol)
	}
	return ""
}

func tcpUDPPortProblem(p ec2IpPermission) string {
	const maxPort = 65535
	for _, end := range []struct {
		name string
		port int
	}{{"from", p.FromPort}, {"to", p.ToPort}} {
		if end.port < 0 || end.port > maxPort {
			return fmt.Sprintf("TCP/UDP (%s) port (%d) out of range", end.name, end.port)
		}
	}
	if p.FromPort > p.ToPort {
		return fmt.Sprintf("Invalid port range %d-%d for protocol '%s': the from port is greater than the to port",
			p.FromPort, p.ToPort, p.IpProtocol)
	}
	return ""
}

// icmpProblem checks FromPort as the ICMP type and ToPort as the code;
// -1 means all, and all types takes only all codes.
func icmpProblem(p ec2IpPermission) string {
	const maxICMP = 255
	if p.FromPort < -1 || p.FromPort > maxICMP {
		return fmt.Sprintf("ICMP type (%d) out of range", p.FromPort)
	}
	if p.ToPort < -1 || p.ToPort > maxICMP {
		return fmt.Sprintf("ICMP code (%d) out of range", p.ToPort)
	}
	if p.FromPort == -1 && p.ToPort != -1 {
		return fmt.Sprintf("ICMP code (%d) must be -1 when the ICMP type is -1 (all types)", p.ToPort)
	}
	return ""
}

func loadSGRules(app *Application, account, region, id, direction string) ([]ec2IpPermission, error) {
	ing, eg, err := app.repo.GetSecurityGroupRules(account, region, id)
	if err != nil {
		return nil, err
	}
	if direction == "egress" {
		return decodeSGRules(eg)
	}
	return decodeSGRules(ing)
}

// permPortKey identifies an AWS permission: every source authorized
// with the same protocol and port range lives on one IpPermission.
func permPortKey(p ec2IpPermission) string {
	return fmt.Sprintf("%s|%d|%d", p.IpProtocol, p.FromPort, p.ToPort)
}

// mergeIpPermissions adds each source to the permission with its
// protocol and ports. A source already present is kept as is, so
// Authorize is idempotent (AWS would answer InvalidPermission.Duplicate).
func mergeIpPermissions(existing, add []ec2IpPermission) []ec2IpPermission {
	out := slices.Clone(existing)
	for _, p := range add {
		i := slices.IndexFunc(out, func(e ec2IpPermission) bool { return permPortKey(e) == permPortKey(p) })
		if i < 0 {
			out = append(out, p)
			continue
		}
		out[i].IpRanges = unionSources(out[i].IpRanges, p.IpRanges)
		out[i].Ipv6Ranges = unionSources(out[i].Ipv6Ranges, p.Ipv6Ranges)
		out[i].UserIdGroupPairs = unionSources(out[i].UserIdGroupPairs, p.UserIdGroupPairs)
		out[i].PrefixListIds = unionSources(out[i].PrefixListIds, p.PrefixListIds)
	}
	return out
}

// subtractIpPermissions revokes only the named sources; a permission
// is dropped once a revoke leaves it with none.
func subtractIpPermissions(existing, rm []ec2IpPermission) []ec2IpPermission {
	out := make([]ec2IpPermission, 0, len(existing))
	for _, e := range existing {
		matched := false
		for _, r := range rm {
			if permPortKey(r) != permPortKey(e) {
				continue
			}
			matched = true
			e.IpRanges = removeSources(e.IpRanges, r.IpRanges)
			e.Ipv6Ranges = removeSources(e.Ipv6Ranges, r.Ipv6Ranges)
			e.UserIdGroupPairs = removeSources(e.UserIdGroupPairs, r.UserIdGroupPairs)
			e.PrefixListIds = removeSources(e.PrefixListIds, r.PrefixListIds)
		}
		if matched && len(e.IpRanges)+len(e.Ipv6Ranges)+len(e.UserIdGroupPairs)+len(e.PrefixListIds) == 0 {
			continue
		}
		out = append(out, e)
	}
	return out
}

func unionSources[T ec2RuleSource](have, add []T) []T {
	out := slices.Clone(have)
	for _, s := range add {
		if !slices.ContainsFunc(out, func(o T) bool { return o.key() == s.key() }) {
			out = append(out, s)
		}
	}
	return out
}

func removeSources[T ec2RuleSource](have, rm []T) []T {
	return slices.DeleteFunc(slices.Clone(have), func(s T) bool {
		return slices.ContainsFunc(rm, func(r T) bool { return r.key() == s.key() })
	})
}

// sgPermsState renders rules with the snake_case AWS keys /mock/state
// documents. Every key is always present and every list non-nil, so a
// state policy can walk them without existence checks.
func sgPermsState(perms []ec2IpPermission) []map[string]any {
	out := make([]map[string]any, 0, len(perms))
	for _, p := range perms {
		out = append(out, map[string]any{
			"ip_protocol":         p.IpProtocol,
			"from_port":           p.FromPort,
			"to_port":             p.ToPort,
			"ip_ranges":           sourcesState(p.IpRanges),
			"ipv6_ranges":         sourcesState(p.Ipv6Ranges),
			"user_id_group_pairs": sourcesState(p.UserIdGroupPairs),
			"prefix_list_ids":     sourcesState(p.PrefixListIds),
		})
	}
	return out
}

func sourcesState[T ec2RuleSource](srcs []T) []map[string]any {
	out := make([]map[string]any, 0, len(srcs))
	for _, s := range srcs {
		out = append(out, s.state())
	}
	return out
}

// ----- Instance handlers -----

// ec2InstanceXML's network fields all come from the primary ENI; a
// terminated instance has none.
//
// CRITICAL[ec2-instance-public-ip-from-primary-eni]: an instance
// launched with NetworkInterface.1.AssociatePublicIpAddress=true MUST
// describe with ipAddress equal to networkInterfaceSet[0].association
// .publicIp, and one launched without MUST have neither element.
// terraform-provider-aws sets associate_public_ip_address (ForceNew)
// to association != nil, so a missing or stray association replaces
// the instance on every plan. privateIpAddress lies in the subnet
// CIDR, and groupSet is the ENI's groups, so a
// ModifyNetworkInterfaceAttribute Groups change reads back.
type ec2InstanceXML struct {
	InstanceId          string                   `xml:"instanceId"`
	ImageId             string                   `xml:"imageId"`
	InstanceType        string                   `xml:"instanceType"`
	SubnetId            string                   `xml:"subnetId"`
	PrivateIpAddress    string                   `xml:"privateIpAddress,omitempty"`
	IpAddress           string                   `xml:"ipAddress,omitempty"`
	SourceDestCheck     *bool                    `xml:"sourceDestCheck,omitempty"`
	IamProfile          *ec2IamProfileXML        `xml:"iamInstanceProfile,omitempty"`
	InstanceState       ec2InstanceStateXML      `xml:"instanceState"`
	GroupSet            []ec2InstanceSGXML       `xml:"groupSet>item,omitempty"`
	NetworkInterfaceSet []ec2NetworkInterfaceXML `xml:"networkInterfaceSet>item,omitempty"`
	TagSet              []ec2ResourceTagXML      `xml:"tagSet>item,omitempty"`
}

// ec2NetworkInterfaceXML serves both an instance's networkInterfaceSet
// item and a DescribeNetworkInterfaces item; the SDK ignores the
// fields one shape has and the other lacks.
type ec2NetworkInterfaceXML struct {
	NetworkInterfaceId string                `xml:"networkInterfaceId"`
	SubnetId           string                `xml:"subnetId"`
	VpcId              string                `xml:"vpcId"`
	OwnerId            string                `xml:"ownerId"`
	Status             string                `xml:"status"`
	InterfaceType      string                `xml:"interfaceType"`
	PrivateIpAddress   string                `xml:"privateIpAddress"`
	SourceDestCheck    bool                  `xml:"sourceDestCheck"`
	GroupSet           []ec2InstanceSGXML    `xml:"groupSet>item"`
	Attachment         ec2ENIAttachmentXML   `xml:"attachment"`
	Association        *ec2ENIAssociationXML `xml:"association,omitempty"`
}

type ec2ENIAttachmentXML struct {
	AttachmentId        string `xml:"attachmentId"`
	InstanceId          string `xml:"instanceId"`
	InstanceOwnerId     string `xml:"instanceOwnerId"`
	DeviceIndex         int    `xml:"deviceIndex"`
	NetworkCardIndex    int    `xml:"networkCardIndex"`
	Status              string `xml:"status"`
	DeleteOnTermination bool   `xml:"deleteOnTermination"`
}

type ec2ENIAssociationXML struct {
	PublicIp  string `xml:"publicIp"`
	IpOwnerId string `xml:"ipOwnerId"`
}

type ec2DescribeNetworkInterfacesResult struct {
	NetworkInterfaceSet []ec2NetworkInterfaceXML `xml:"networkInterfaceSet>item"`
}

type ec2IamProfileXML struct {
	Arn string `xml:"arn"`
	Id  string `xml:"id"`
}

// ec2InstanceStateXML is rendered through three distinct field
// positions (instanceState, currentState, previousState) — so it
// intentionally has no XMLName: encoding/xml treats the field tag
// as the element name, which is what we need.
type ec2InstanceStateXML struct {
	Code int    `xml:"code"`
	Name string `xml:"name"`
}

type ec2InstanceSGXML struct {
	GroupId string `xml:"groupId"`
}

type ec2RunInstancesResult struct {
	Reservation  string           `xml:"reservationId"`
	OwnerId      string           `xml:"ownerId"`
	InstancesSet []ec2InstanceXML `xml:"instancesSet>item"`
}

type ec2DescribeInstancesResult struct {
	ReservationSet []ec2ReservationXML `xml:"reservationSet>item"`
}

type ec2ReservationXML struct {
	ReservationId string           `xml:"reservationId"`
	OwnerId       string           `xml:"ownerId"`
	InstancesSet  []ec2InstanceXML `xml:"instancesSet>item"`
}

type ec2TerminateInstancesResult struct {
	InstancesSet []ec2InstanceStateChangeXML `xml:"instancesSet>item"`
}

type ec2InstanceStateChangeXML struct {
	InstanceId    string              `xml:"instanceId"`
	CurrentState  ec2InstanceStateXML `xml:"currentState"`
	PreviousState ec2InstanceStateXML `xml:"previousState"`
}

var ec2InstanceStateCodes = map[string]int{
	"pending":       0,
	"running":       16,
	"shutting-down": 32,
	"terminated":    48,
	"stopping":      64,
	"stopped":       80,
}

func ec2InstanceStateForName(name string) ec2InstanceStateXML {
	return ec2InstanceStateXML{Code: ec2InstanceStateCodes[name], Name: name}
}

// ec2InstanceToXML renders inst; eni is its primary ENI, nil once
// terminated.
func ec2InstanceToXML(inst *repository.EC2Instance, eni *repository.EC2NetworkInterface) ec2InstanceXML {
	x := ec2InstanceXML{
		InstanceId:    inst.ID,
		ImageId:       inst.AMIID,
		InstanceType:  inst.InstanceType,
		SubnetId:      inst.SubnetID,
		InstanceState: ec2InstanceStateForName(inst.State),
	}
	if inst.IAMInstanceProfileName != "" {
		x.IamProfile = &ec2IamProfileXML{
			Arn: awsproto.BuildIAMInstanceProfileARN(inst.IAMInstanceProfileName),
			Id:  inst.IAMInstanceProfileName,
		}
	}
	if eni == nil {
		return x
	}
	eniXML := ec2ENIToXML(eni)
	x.PrivateIpAddress = eni.PrivateIP
	x.IpAddress = eni.PublicIP
	x.SourceDestCheck = &eniXML.SourceDestCheck
	x.GroupSet = eniXML.GroupSet
	x.NetworkInterfaceSet = []ec2NetworkInterfaceXML{eniXML}
	return x
}

func ec2ENIToXML(eni *repository.EC2NetworkInterface) ec2NetworkInterfaceXML {
	x := ec2NetworkInterfaceXML{
		NetworkInterfaceId: eni.ID,
		SubnetId:           eni.SubnetID,
		VpcId:              eni.VPCID,
		OwnerId:            awsproto.FakeAccountID,
		Status:             "in-use",
		InterfaceType:      "interface",
		PrivateIpAddress:   eni.PrivateIP,
		SourceDestCheck:    eni.SourceDestCheck,
		GroupSet:           []ec2InstanceSGXML{},
		Attachment: ec2ENIAttachmentXML{
			AttachmentId:        eni.AttachmentID,
			InstanceId:          eni.InstanceID,
			InstanceOwnerId:     awsproto.FakeAccountID,
			Status:              "attached",
			DeleteOnTermination: true,
		},
	}
	for _, sgID := range eni.SecurityGroupIDs {
		x.GroupSet = append(x.GroupSet, ec2InstanceSGXML{GroupId: sgID})
	}
	if eni.PublicIP != "" {
		x.Association = &ec2ENIAssociationXML{PublicIp: eni.PublicIP, IpOwnerId: "amazon"}
	}
	return x
}

// queryListValues returns a flattened scalar list (<prefix>1,
// <prefix>2, ...) in order, never nil. The SDK numbers lists from 1
// without gaps.
func queryListValues(p url.Values, prefix string) []string {
	out := []string{}
	for i := 1; p.Has(prefix + strconv.Itoa(i)); i++ {
		out = append(out, p.Get(prefix+strconv.Itoa(i)))
	}
	return out
}

// parseInstanceIDs reads InstanceId.<n> params.
func parseInstanceIDs(req awsproto.QueryRPCRequest) []string {
	var ids []string
	for k, vs := range req.Params {
		if strings.HasPrefix(k, "InstanceId.") && len(vs) > 0 {
			ids = append(ids, vs[0])
		}
	}
	return ids
}

// ec2InstanceNetwork is where RunInstances puts the primary ENI.
type ec2InstanceNetwork struct {
	subnetID          string
	sgIDs             []string
	privateIP         string // empty: the lowest free address
	associatePublicIP string // "true", "false", or "" for the subnet's default
}

// errNICWithInstanceLevelPlacement is AWS's InvalidParameterCombination.
var errNICWithInstanceLevelPlacement = errors.New("Network interfaces and an instance-level subnet ID, security groups or private IP may not be specified on the same request")

// parseInstanceNetwork reads either the top-level SubnetId +
// SecurityGroupId.N form or NetworkInterface.1.*, which the provider
// sends whenever associate_public_ip_address is set. Without an
// AssociatePublicIpAddress the subnet's MapPublicIpOnLaunch decides.
func parseInstanceNetwork(p url.Values) (ec2InstanceNetwork, error) {
	top := ec2InstanceNetwork{
		subnetID:  p.Get("SubnetId"),
		sgIDs:     queryListValues(p, "SecurityGroupId."),
		privateIP: p.Get("PrivateIpAddress"),
	}
	nics := queryListItems(p, "NetworkInterface.")
	if len(nics) == 0 {
		return top, nil
	}
	if top.subnetID != "" || len(top.sgIDs) > 0 || top.privateIP != "" {
		return ec2InstanceNetwork{}, errNICWithInstanceLevelPlacement
	}
	const nic = "NetworkInterface.1."
	if len(nics) > 1 || nics[0] != nic || p.Get(nic+"DeviceIndex") != "0" ||
		p.Get(nic+"NetworkInterfaceId") != "" || p.Get(nic+"DeleteOnTermination") == "false" {
		return ec2InstanceNetwork{}, fmt.Errorf("fakeaws launches only a new primary network interface (NetworkInterface.1, DeviceIndex 0, deleted on termination): %w", models.ErrConflict)
	}
	return ec2InstanceNetwork{
		subnetID:          p.Get(nic + "SubnetId"),
		sgIDs:             queryListValues(p, nic+"SecurityGroupId."),
		privateIP:         p.Get(nic + "PrivateIpAddress"),
		associatePublicIP: p.Get(nic + "AssociatePublicIpAddress"),
	}, nil
}

// checkSubnetGroups looks up the subnet and refuses a security group
// from another VPC (S44-T8 regression pattern; the load-bearing fakegcp
// pass-27 finding ported to AWS). Both RunInstances forms and
// ModifyNetworkInterfaceAttribute go through it, so they fail alike.
func (app *Application) checkSubnetGroups(account, region, subnetID string, sgIDs []string) (*repository.EC2Subnet, error) {
	subnet, err := app.repo.GetSubnet(account, region, subnetID)
	if err != nil {
		return nil, err
	}
	for _, sgID := range sgIDs {
		sg, err := app.repo.GetSecurityGroup(account, region, sgID)
		if err != nil {
			return nil, err
		}
		if sg.VPCID != subnet.VPCID {
			return nil, fmt.Errorf("security group %q lives in vpc %q but subnet %q is in vpc %q: %w",
				sgID, sg.VPCID, subnetID, subnet.VPCID, models.ErrNotFound)
		}
	}
	return subnet, nil
}

func (app *Application) ec2RunInstances(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	nw, err := parseInstanceNetwork(req.Params)
	if errors.Is(err, errNICWithInstanceLevelPlacement) {
		awsproto.WriteServiceError(w, awsproto.ShapeEC2Query,
			http.StatusBadRequest, "InvalidParameterCombination", err.Error())
		return
	}
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	imageID := req.Params.Get("ImageId")
	instanceType := req.Params.Get("InstanceType")
	if nw.subnetID == "" || imageID == "" || instanceType == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
			fmt.Errorf("SubnetId, ImageId, InstanceType required: %w", models.ErrConflict))
		return
	}
	// The provider adds a volume spec whenever default_tags is set;
	// fakeaws has no volumes, so those tags are accepted and dropped.
	specs, refused := refuseTagSpecifications(w, req.Params, "instance", "network-interface", "volume")
	if refused {
		return
	}
	// Lazy-seed canonical AMI fixtures for this region (Codex pass 9
	// BLOCKING #1) so RunInstances and DescribeImages stay consistent
	// regardless of which region the caller picked.
	app.ensureAMIFixturesForRegion(account, region)
	// Real EC2 refuses an ImageId it does not know, so a hallucinated
	// AMI (ami-0c55b159cbfafe1f0) fails here as it would on AWS.
	if _, err := app.repo.GetAMI(account, region, imageID); err != nil {
		if errors.Is(err, models.ErrNotFound) {
			awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest,
				"InvalidAMIID.NotFound", fmt.Sprintf("The image id '[%s]' does not exist", imageID))
			return
		}
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	subnet, err := app.checkSubnetGroups(account, region, nw.subnetID, nw.sgIDs)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	id := "i-" + ec2RandID()
	inst := &repository.EC2Instance{
		ID: id, SubnetID: nw.subnetID, AMIID: imageID, InstanceType: instanceType,
		IAMInstanceProfileName: req.Params.Get("IamInstanceProfile.Name"),
		UserData:               req.Params.Get("UserData"),
		State:                  "running",
		Region:                 region,
		ARN:                    awsproto.BuildEC2InstanceARN(region, id),
		CreatedAt:              time.Now().UTC().Format(time.RFC3339),
	}
	eni := &repository.EC2NetworkInterface{
		ID: "eni-" + ec2RandID(), AttachmentID: "eni-attach-" + ec2RandID(),
		SecurityGroupIDs: nw.sgIDs, PrivateIP: nw.privateIP, SourceDestCheck: true,
	}
	if nw.associatePublicIP == "true" || (nw.associatePublicIP == "" && subnet.MapPublicIPOnLaunch) {
		eni.PublicIP, eni.AutoPublicIP = ec2DerivePublicIP(eni.ID), true
	}
	err = app.repo.CreateInstance(account, inst, eni)
	if err == nil {
		tags := append(onResource(specs["instance"], id, "instance"),
			onResource(specs["network-interface"], eni.ID, "network-interface")...)
		err = app.tagNew(account, region, tags,
			func() error { return app.repo.DeleteInstance(account, region, id) })
	}
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "RunInstances", &ec2RunInstancesResult{
		Reservation:  "r-" + ec2RandID(),
		OwnerId:      awsproto.FakeAccountID,
		InstancesSet: []ec2InstanceXML{ec2InstanceToXML(inst, eni)},
	})
}

func (app *Application) ec2DescribeInstances(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	wanted := parseInstanceIDs(req)
	var instances []*repository.EC2Instance
	if len(wanted) > 0 {
		for _, id := range wanted {
			inst, err := app.repo.GetInstance(account, region, id)
			if err != nil {
				// Surface the EC2-specific NotFound code so
				// terraform-provider-aws's destroy wait-loop can treat
				// the response as "instance is gone, deletion complete"
				// instead of a generic hard error. Mirrors the SG /
				// RouteTable fix earlier in this session.
				writeInstanceError(w, id, err)
				return
			}
			instances = append(instances, inst)
		}
	} else {
		// Unfiltered describe: keep account-wide behavior to match the
		// existing wire contract — terraform-provider-aws's import path
		// doesn't expect region scoping at this endpoint.
		var err error
		instances, err = app.repo.ListInstances(account, "")
		if err != nil {
			awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
			return
		}
	}
	enis, err := app.instanceENIs(account)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	tags, ok := app.tagSets(w, account)
	if !ok {
		return
	}
	out := ec2DescribeInstancesResult{
		ReservationSet: make([]ec2ReservationXML, 0, len(instances)),
	}
	for _, inst := range instances {
		x := ec2InstanceToXML(inst, enis[inst.ID])
		x.TagSet = tags[inst.ID]
		out.ReservationSet = append(out.ReservationSet, ec2ReservationXML{
			ReservationId: "r-" + ec2RandID(),
			OwnerId:       awsproto.FakeAccountID,
			InstancesSet:  []ec2InstanceXML{x},
		})
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DescribeInstances", &out)
}

// instanceENIs maps instance id → primary ENI, account-wide.
func (app *Application) instanceENIs(account string) (map[string]*repository.EC2NetworkInterface, error) {
	enis, err := app.repo.ListNetworkInterfaces(account, "")
	if err != nil {
		return nil, err
	}
	out := make(map[string]*repository.EC2NetworkInterface, len(enis))
	for _, eni := range enis {
		out[eni.InstanceID] = eni
	}
	return out, nil
}

// ----- NetworkInterface handlers -----

// eniFilterValues maps each DescribeNetworkInterfaces filter fakeaws
// supports to the ENI's values for it. The provider's aws_subnet and
// aws_security_group deletes list lingering ENIs by subnet-id and
// group-id.
var eniFilterValues = map[string]func(*repository.EC2NetworkInterface) []string{
	"network-interface-id":   func(e *repository.EC2NetworkInterface) []string { return []string{e.ID} },
	"attachment.instance-id": func(e *repository.EC2NetworkInterface) []string { return []string{e.InstanceID} },
	"subnet-id":              func(e *repository.EC2NetworkInterface) []string { return []string{e.SubnetID} },
	"group-id":               func(e *repository.EC2NetworkInterface) []string { return e.SecurityGroupIDs },
}

// ec2Filters reads Filter.<n>.Name / Filter.<n>.Value.<m> as name → values.
func ec2Filters(p url.Values) map[string][]string {
	out := map[string][]string{}
	for _, f := range queryListItems(p, "Filter.") {
		name := p.Get(f + "Name")
		out[name] = append(out[name], queryListValues(p, f+"Value.")...)
	}
	return out
}

// writeInstanceError answers a failed instance lookup, with
// InvalidInstanceID.NotFound for a missing instance.
func writeInstanceError(w http.ResponseWriter, id string, err error) {
	if errors.Is(err, models.ErrNotFound) {
		awsproto.WriteServiceError(w, awsproto.ShapeEC2Query,
			http.StatusNotFound, "InvalidInstanceID.NotFound",
			fmt.Sprintf("The instance ID '%s' does not exist", id))
		return
	}
	awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
}

func writeENINotFound(w http.ResponseWriter, id string) {
	awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusNotFound,
		"InvalidNetworkInterfaceID.NotFound",
		fmt.Sprintf("The networkInterface ID '%s' does not exist", id))
}

// ec2DescribeNetworkInterfaces lists instance ENIs. An unknown
// NetworkInterfaceId.N is InvalidNetworkInterfaceID.NotFound, which
// the provider reads as "gone"; an unsupported filter is refused
// rather than ignored.
func (app *Application) ec2DescribeNetworkInterfaces(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	filters := ec2Filters(req.Params)
	for name := range filters {
		if eniFilterValues[name] == nil {
			awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
				fmt.Errorf("DescribeNetworkInterfaces filter %q not supported by fakeaws: %w", name, models.ErrConflict))
			return
		}
	}
	enis, err := app.repo.ListNetworkInterfaces(account, region)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	ids := queryListValues(req.Params, "NetworkInterfaceId.")
	for _, id := range ids {
		if !slices.ContainsFunc(enis, func(e *repository.EC2NetworkInterface) bool { return e.ID == id }) {
			writeENINotFound(w, id)
			return
		}
	}
	out := ec2DescribeNetworkInterfacesResult{NetworkInterfaceSet: []ec2NetworkInterfaceXML{}}
	for _, eni := range enis {
		if len(ids) > 0 && !slices.Contains(ids, eni.ID) {
			continue
		}
		if eniMatches(eni, filters) {
			out.NetworkInterfaceSet = append(out.NetworkInterfaceSet, ec2ENIToXML(eni))
		}
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DescribeNetworkInterfaces", &out)
}

// eniMatches reports whether eni has, for every filter, a value among
// that filter's values.
func eniMatches(eni *repository.EC2NetworkInterface, filters map[string][]string) bool {
	for name, want := range filters {
		if !slices.ContainsFunc(eniFilterValues[name](eni), func(v string) bool { return slices.Contains(want, v) }) {
			return false
		}
	}
	return true
}

// ec2ModifyNetworkInterfaceAttribute models the Groups attribute only:
// the provider sends vpc_security_group_ids changes here, to the
// instance's primary ENI, so they show up in the instance's groupSet.
func (app *Application) ec2ModifyNetworkInterfaceAttribute(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	id := req.Params.Get("NetworkInterfaceId")
	groups := queryListValues(req.Params, "SecurityGroupId.")
	if id == "" || len(groups) == 0 {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
			fmt.Errorf("NetworkInterfaceId and SecurityGroupId.N required (fakeaws models only the Groups attribute): %w", models.ErrConflict))
		return
	}
	eni, err := app.repo.GetNetworkInterface(account, region, id)
	if errors.Is(err, models.ErrNotFound) {
		writeENINotFound(w, id)
		return
	}
	if err == nil {
		_, err = app.checkSubnetGroups(account, region, eni.SubnetID, groups)
	}
	if err == nil {
		err = app.repo.UpdateNetworkInterface(account, region, id, func(e *repository.EC2NetworkInterface) {
			e.SecurityGroupIDs = groups
		})
	}
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "ModifyNetworkInterfaceAttribute", nil)
}

// ec2ModifyInstanceAttribute is intentionally minimal at v1: only
// SourceDestCheck round-trips, onto the primary ENI that
// DescribeInstances reads it from (the provider sends it after create
// for source_dest_check = false). Other attributes are accepted and
// not stored. State changes go through the dedicated state-machine
// handlers (Start / Stop / Terminate).
func (app *Application) ec2ModifyInstanceAttribute(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	id := req.Params.Get("InstanceId")
	if id == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
			fmt.Errorf("InstanceId required: %w", models.ErrConflict))
		return
	}
	_, err := app.repo.GetInstance(account, region, id)
	if v := req.Params.Get("SourceDestCheck.Value"); err == nil && v != "" {
		err = app.setSourceDestCheck(account, id, v == "true")
	}
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "ModifyInstanceAttribute", nil)
}

func (app *Application) setSourceDestCheck(account, instanceID string, on bool) error {
	enis, err := app.instanceENIs(account)
	if err != nil {
		return err
	}
	eni := enis[instanceID]
	if eni == nil {
		return fmt.Errorf("instance %s has no network interface (terminated): %w", instanceID, models.ErrConflict)
	}
	return app.repo.UpdateNetworkInterface(account, eni.Region, eni.ID, func(e *repository.EC2NetworkInterface) {
		e.SourceDestCheck = on
	})
}

func (app *Application) ec2TerminateInstances(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	ids := parseInstanceIDs(req)
	if len(ids) == 0 {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
			fmt.Errorf("InstanceId.<n> required: %w", models.ErrConflict))
		return
	}
	out := ec2TerminateInstancesResult{}
	for _, id := range ids {
		inst, err := app.repo.GetInstance(account, region, id)
		if err != nil {
			// Already gone — TerminateInstances is idempotent in real
			// AWS: a second call after the row has been GCd still
			// returns 200 with terminated/terminated. Match that by
			// synthesising the response when the row is no longer in
			// the repo. (The hard-delete-on-terminate below depends
			// on this branch to stay idempotent.)
			if errors.Is(err, models.ErrNotFound) {
				out.InstancesSet = append(out.InstancesSet, ec2InstanceStateChangeXML{
					InstanceId:    id,
					CurrentState:  ec2InstanceStateForName("terminated"),
					PreviousState: ec2InstanceStateForName("terminated"),
				})
				continue
			}
			awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
			return
		}
		previous := inst.State
		if previous == "terminated" {
			// Already terminated — AWS surfaces this as state-stays-terminated,
			// not as a 409. Concepts.md "Standing patterns" item 9 — terminal
			// state refuses transitions; the wire response just echoes
			// terminated/terminated.
			out.InstancesSet = append(out.InstancesSet, ec2InstanceStateChangeXML{
				InstanceId:    id,
				CurrentState:  ec2InstanceStateForName("terminated"),
				PreviousState: ec2InstanceStateForName("terminated"),
			})
			continue
		}
		if err := app.repo.SetInstanceState(account, region, id, "terminated"); err != nil {
			awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
			return
		}
		out.InstancesSet = append(out.InstancesSet, ec2InstanceStateChangeXML{
			InstanceId:    id,
			CurrentState:  ec2InstanceStateForName("terminated"),
			PreviousState: ec2InstanceStateForName(previous),
		})
		// NOTE: do NOT hard-delete the row here. The provider's
		// destroy wait-loop polls DescribeInstances expecting to
		// observe the state transition (running→stopping→terminated)
		// before accepting "gone." Hard-deleting collapses the wait
		// into a confusing "couldn't find resource (21 retries)"
		// error. Cleanup of terminated rows happens lazily inside
		// DeleteSubnet/DeleteVPC so the FK constraint doesn't block
		// dependent resource deletion.
	}
	awsproto.WriteEC2QueryRPCResponse(w, "TerminateInstances", &out)
}

// ----- KeyPair handlers -----

type ec2KeyPairXML struct {
	KeyPairId      string              `xml:"keyPairId,omitempty"`
	KeyName        string              `xml:"keyName"`
	KeyFingerprint string              `xml:"keyFingerprint"`
	TagSet         []ec2ResourceTagXML `xml:"tagSet>item,omitempty"`
}

type ec2ImportKeyPairResult = ec2KeyPairXML

func ec2KeyPairToXML(kp *repository.EC2KeyPair, tags map[string][]ec2ResourceTagXML) ec2KeyPairXML {
	return ec2KeyPairXML{KeyPairId: kp.ID, KeyName: kp.Name, KeyFingerprint: kp.Fingerprint, TagSet: tags[kp.ID]}
}

type ec2DescribeKeyPairsResult struct {
	KeySet []ec2KeyPairXML `xml:"keySet>item"`
}

func ec2KeyFingerprint(publicKey string) string {
	// AWS ImportKeyPair returns an MD5 fingerprint of the public key
	// per the docs; we don't import md5 here (reasonable cryptographic
	// hygiene at the wire-mock layer) — produce a deterministic
	// hex-from-content fingerprint instead. The provider treats it as
	// opaque, so the shape is what matters.
	sum := byte(0)
	for _, b := range []byte(publicKey) {
		sum = (sum*31 + b)
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
		sum, sum, sum, sum, sum, sum, sum, sum, sum, sum, sum, sum, sum, sum, sum, sum)
}

func (app *Application) ec2ImportKeyPair(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	name := req.Params.Get("KeyName")
	publicKey := req.Params.Get("PublicKeyMaterial")
	if name == "" || publicKey == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
			fmt.Errorf("KeyName and PublicKeyMaterial required: %w", models.ErrConflict))
		return
	}
	specs, refused := refuseTagSpecifications(w, req.Params, "key-pair")
	if refused {
		return
	}
	kp := &repository.EC2KeyPair{
		ID:   "key-" + ec2RandID(),
		Name: name, PublicKey: publicKey, Fingerprint: ec2KeyFingerprint(publicKey), Region: region,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	tags := onResource(specs["key-pair"], kp.ID, "key-pair")
	err := app.repo.CreateKeyPair(account, kp)
	if err == nil {
		err = app.tagNew(account, region, tags,
			func() error { return app.repo.DeleteKeyPair(account, region, name) })
	}
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	out := ec2KeyPairToXML(kp, nil)
	for _, t := range tags {
		out.TagSet = append(out.TagSet, ec2ResourceTagXML{Key: t.Key, Value: t.Value})
	}
	awsproto.WriteEC2QueryRPCResponse(w, "ImportKeyPair", &out)
}

func (app *Application) ec2DescribeKeyPairs(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	// KeyName.<n> filter — terraform-provider-aws's read path.
	var wanted []string
	for k, vs := range req.Params {
		if strings.HasPrefix(k, "KeyName.") && len(vs) > 0 {
			wanted = append(wanted, vs[0])
		}
	}
	tags, ok := app.tagSets(w, account)
	if !ok {
		return
	}
	out := ec2DescribeKeyPairsResult{KeySet: []ec2KeyPairXML{}}
	if len(wanted) == 0 {
		// no filter — list all in region
		kps, err := app.repo.ListKeyPairs(account, region)
		if err != nil {
			awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
			return
		}
		for _, kp := range kps {
			out.KeySet = append(out.KeySet, ec2KeyPairToXML(kp, tags))
		}
	} else {
		for _, name := range wanted {
			kp, err := app.repo.GetKeyPair(account, region, name)
			if err != nil {
				awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
				return
			}
			out.KeySet = append(out.KeySet, ec2KeyPairToXML(kp, tags))
		}
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DescribeKeyPairs", &out)
}

// ec2DeleteKeyPair deletes by KeyName or, as EC2 also accepts, by the
// KeyPairId DescribeKeyPairs lists.
func (app *Application) ec2DeleteKeyPair(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	name := req.Params.Get("KeyName")
	if id := req.Params.Get("KeyPairId"); id != "" {
		kp, err := app.repo.GetKeyPairByID(account, region, id)
		if err != nil {
			awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
			return
		}
		name = kp.Name
	}
	if err := app.repo.DeleteKeyPair(account, region, name); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DeleteKeyPair", nil)
}

// ----- AMI (read-only fixture) handlers -----

type ec2ImageXML struct {
	ImageId            string `xml:"imageId"`
	Name               string `xml:"name"`
	OwnerId            string `xml:"imageOwnerId"`
	VirtualizationType string `xml:"virtualizationType"`
	RootDeviceName     string `xml:"rootDeviceName"`
	State              string `xml:"imageState"`
}

type ec2DescribeImagesResult struct {
	ImagesSet []ec2ImageXML `xml:"imagesSet>item"`
}

func (app *Application) ec2DescribeImages(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	// Lazy-seed canonical AMI fixtures for this region (Codex pass 9
	// BLOCKING #1) so callers in any valid AWS region see the same
	// fixture set as the boot-time slice.
	app.ensureAMIFixturesForRegion(account, region)
	// ImageId.<n> filter — most common from terraform-provider-aws
	// where users pass a literal AMI id. data.aws_ami is NOT supported
	// per the S44-T0 pitfall.
	var wanted []string
	for k, vs := range req.Params {
		if strings.HasPrefix(k, "ImageId.") && len(vs) > 0 {
			wanted = append(wanted, vs[0])
		}
	}
	var amis []*repository.EC2AMI
	if len(wanted) == 0 {
		var err error
		if amis, err = app.repo.ListAMIs(account, region); err != nil {
			awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
			return
		}
	} else {
		for _, id := range wanted {
			a, err := app.repo.GetAMI(account, region, id)
			if err != nil {
				awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
				return
			}
			amis = append(amis, a)
		}
	}
	// Owner.N keeps images of those owners, "self" meaning the caller:
	// the scope sweep's Owner.1=self sees none of the fixtures. There
	// are no disabled images, so IncludeDisabled changes nothing.
	owners := queryListValues(req.Params, "Owner.")
	out := ec2DescribeImagesResult{ImagesSet: []ec2ImageXML{}}
	for _, a := range amis {
		if len(owners) == 0 || slices.Contains(owners, a.OwnerID) || a.OwnerID == account && slices.Contains(owners, "self") {
			out.ImagesSet = append(out.ImagesSet, ec2AMIToXML(a))
		}
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DescribeImages", &out)
}

// ec2NoneSets names the result set of each Describe for a resource
// fakeaws never creates.
var ec2NoneSets = map[string]string{
	"DescribeVolumes":         "volumeSet",
	"DescribeNatGateways":     "natGatewaySet",
	"DescribeSnapshots":       "snapshotSet",
	"DescribeLaunchTemplates": "launchTemplates",
}

type ec2EmptySet struct {
	XMLName xml.Name
}

type ec2DescribeNoneResult struct {
	Set ec2EmptySet
}

// ec2DescribeNone answers a Describe in ec2NoneSets with its real
// result, an empty set, and refuses Filter.N rather than ignoring it.
// ponytail: an id lookup (VolumeId.N, ...) answers empty, not the
// service's NotFound code; add the codes when a caller looks one up.
func ec2DescribeNone(w http.ResponseWriter, req awsproto.QueryRPCRequest) {
	if refuseUnmodelled(w, req, "Filter.") {
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, req.Action,
		&ec2DescribeNoneResult{Set: ec2EmptySet{XMLName: xml.Name{Local: ec2NoneSets[req.Action]}}})
}

// refuseUnmodelled answers 409 when req carries a param under one of
// prefixes, a filter fakeaws does not model, rather than ignoring it
// and describing everything. It reports whether it answered.
func refuseUnmodelled(w http.ResponseWriter, req awsproto.QueryRPCRequest, prefixes ...string) bool {
	for k := range req.Params {
		if slices.ContainsFunc(prefixes, func(p string) bool { return strings.HasPrefix(k, p) }) {
			awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
				fmt.Errorf("%s parameter %q not supported by fakeaws: %w", req.Action, k, models.ErrConflict))
			return true
		}
	}
	return false
}

func ec2AMIToXML(a *repository.EC2AMI) ec2ImageXML {
	return ec2ImageXML{
		ImageId: a.ID, Name: a.Name, OwnerId: a.OwnerID,
		VirtualizationType: a.VirtualizationType, RootDeviceName: a.RootDeviceName,
		State: "available",
	}
}

// AL2023AMIID is the Amazon Linux 2023 fixture, the image SSM's public
// al2023-ami-kernel-default-x86_64 parameter resolves to.
const AL2023AMIID = "ami-0al2023x8664"

// ec2AMIFixtures is the canonical fixture list seeded at startup. The
// AWS provider's documentation examples reference Amazon Linux and
// Ubuntu LTS images by canonical name; we cover both so scenarios can
// pass in either. Per concepts.md "Standing patterns" item 8 — fixture
// state, never derived from real AWS.
var ec2AMIFixtures = []repository.EC2AMI{
	{ID: "ami-0abcd1234", Name: "amzn2-ami-hvm-2.0", OwnerID: "amazon", VirtualizationType: "hvm", RootDeviceName: "/dev/xvda"},
	{ID: AL2023AMIID, Name: "al2023-ami-2023.6.20241010.0-kernel-6.1-x86_64", OwnerID: "amazon", VirtualizationType: "hvm", RootDeviceName: "/dev/xvda"},
	{ID: "ami-0ubuntu2004", Name: "ubuntu/images/hvm-ssd/ubuntu-focal-20.04", OwnerID: "099720109477", VirtualizationType: "hvm", RootDeviceName: "/dev/sda1"},
	{ID: "ami-0ubuntu2204", Name: "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04", OwnerID: "099720109477", VirtualizationType: "hvm", RootDeviceName: "/dev/sda1"},
}

// ec2InstanceTypeXML mirrors a single InstanceTypeInfo entry in a
// DescribeInstanceTypes response. The provider's `aws_instance` read
// path uses `InstanceType`, `MemoryInfo.SizeInMiB`, `VCpuInfo.DefaultVCpus`,
// and `Hypervisor`; missing values bubble up as nil-deref panics in
// the provider plugin, so we always populate those fields with
// plausible defaults.
type ec2InstanceTypeXML struct {
	InstanceType string                `xml:"instanceType"`
	VCpuInfo     ec2InstanceVCpuInfo   `xml:"vCpuInfo"`
	MemoryInfo   ec2InstanceMemoryInfo `xml:"memoryInfo"`
	Hypervisor   string                `xml:"hypervisor"`
}

type ec2InstanceVCpuInfo struct {
	DefaultVCpus int `xml:"defaultVCpus"`
}

type ec2InstanceMemoryInfo struct {
	SizeInMiB int64 `xml:"sizeInMiB"`
}

type ec2DescribeInstanceTypesResult struct {
	InstanceTypeSet []ec2InstanceTypeXML `xml:"instanceTypeSet>item"`
}

// ec2DescribeInstanceTypes serves the read-path call that
// terraform-provider-aws makes after RunInstances to populate
// `aws_instance` state fields (memory, vcpu, hypervisor). The set of
// real-world instance types is huge and grows constantly, so we
// synthesise a plausible fixture for whatever the caller asks for
// rather than enumerating: mocks optimize for fast feedback, not for
// rejecting unknown fixture data.
func (app *Application) ec2DescribeInstanceTypes(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	var wanted []string
	for k, vs := range req.Params {
		if strings.HasPrefix(k, "InstanceType.") && len(vs) > 0 {
			wanted = append(wanted, vs[0])
		}
	}
	if len(wanted) == 0 {
		// Unfiltered DescribeInstanceTypes returns a representative
		// slice. Common terraform-provider-aws docs examples are t3.* /
		// t2.* / m5.* — covering them avoids a noisy 404 when the
		// LLM lists types without filtering.
		wanted = []string{"t2.micro", "t3.micro", "t3.small", "t3.medium", "m5.large"}
	}
	out := ec2DescribeInstanceTypesResult{InstanceTypeSet: make([]ec2InstanceTypeXML, 0, len(wanted))}
	for _, name := range wanted {
		out.InstanceTypeSet = append(out.InstanceTypeSet, synthesizeInstanceType(name))
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DescribeInstanceTypes", &out)
}

// ec2DescribeInstanceAttributeResult is the response wrapper for one
// scalar attribute lookup. terraform-provider-aws issues one of these
// per attribute it wants to read; the response varies per attribute
// name. userData is the instance's stored RunInstances UserData; the
// rest are synthesised AWS defaults — none of our scenarios mutate
// them after create.
type ec2DescribeInstanceAttributeResult struct {
	InstanceId                        string                   `xml:"instanceId"`
	InstanceInitiatedShutdownBehavior *ec2AttributeStringValue `xml:"instanceInitiatedShutdownBehavior,omitempty"`
	DisableApiTermination             *ec2AttributeBoolValue   `xml:"disableApiTermination,omitempty"`
	DisableApiStop                    *ec2AttributeBoolValue   `xml:"disableApiStop,omitempty"`
	UserData                          *ec2AttributeStringValue `xml:"userData,omitempty"`
	EbsOptimized                      *ec2AttributeBoolValue   `xml:"ebsOptimized,omitempty"`
	SourceDestCheck                   *ec2AttributeBoolValue   `xml:"sourceDestCheck,omitempty"`
}

type ec2AttributeStringValue struct {
	Value string `xml:"value,omitempty"`
}

type ec2AttributeBoolValue struct {
	Value bool `xml:"value"`
}

// ec2DescribeInstanceAttribute synthesises AWS defaults for the
// commonly-read scalar attributes. The Attribute query param selects
// which one to populate.
func (app *Application) ec2DescribeInstanceAttribute(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	instanceID := req.Params.Get("InstanceId")
	attr := req.Params.Get("Attribute")
	out := ec2DescribeInstanceAttributeResult{InstanceId: instanceID}
	switch attr {
	case "instanceInitiatedShutdownBehavior":
		out.InstanceInitiatedShutdownBehavior = &ec2AttributeStringValue{Value: "stop"}
	case "disableApiTermination":
		out.DisableApiTermination = &ec2AttributeBoolValue{Value: false}
	case "disableApiStop":
		out.DisableApiStop = &ec2AttributeBoolValue{Value: false}
	case "userData":
		// An instance without user data answers an empty <userData/>:
		// a <value></value> reads back as user_data = sha1("") and
		// plans a diff.
		inst, err := app.repo.GetInstance(account, region, instanceID)
		if err != nil {
			writeInstanceError(w, instanceID, err)
			return
		}
		out.UserData = &ec2AttributeStringValue{Value: inst.UserData}
	case "ebsOptimized":
		out.EbsOptimized = &ec2AttributeBoolValue{Value: false}
	case "sourceDestCheck":
		out.SourceDestCheck = &ec2AttributeBoolValue{Value: true}
	default:
		// Unknown attribute — return the envelope with just the
		// instance id. The provider will see "attribute not present"
		// and treat it as default-valued.
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DescribeInstanceAttribute", &out)
}

// ----- Tags -----
//
// Tags are stored per resource id. The Create* calls persist their
// TagSpecification.N; CreateTags and DeleteTags change them later
// (terraform-provider-aws's updateTags sends DeleteTags for removed
// keys, with their old values, then CreateTags for added and changed
// ones); each Describe* returns them as tagSet; DescribeTags lists them.
//
// CRITICAL[ec2-tags-round-trip-in-tagset]: a tag given on create or by
// CreateTags MUST come back in its resource's Describe* tagSet, and one
// removed by DeleteTags MUST NOT. The provider sets tags and tags_all
// from tagSet, so a dropped or stale tag plans a diff every run.

type ec2ResourceTagXML struct {
	Key   string `xml:"key"`
	Value string `xml:"value"`
}

// ec2TaggedKind is a resource type CreateTags and DeleteTags accept,
// recognised by its id prefix.
type ec2TaggedKind struct {
	prefix, resourceType, notFound string
	get                            func(app *Application, account, region, id string) error
}

var ec2TaggedKinds = []ec2TaggedKind{
	{"vpc-", "vpc", "InvalidVpcID.NotFound", func(app *Application, account, region, id string) error {
		_, err := app.repo.GetVPC(account, region, id)
		return err
	}},
	{"subnet-", "subnet", "InvalidSubnetID.NotFound", func(app *Application, account, region, id string) error {
		_, err := app.repo.GetSubnet(account, region, id)
		return err
	}},
	{"igw-", "internet-gateway", "InvalidInternetGatewayID.NotFound", func(app *Application, account, region, id string) error {
		_, err := app.repo.GetInternetGateway(account, region, id)
		return err
	}},
	{"rtb-", "route-table", "InvalidRouteTableID.NotFound", func(app *Application, account, region, id string) error {
		_, err := app.repo.GetRouteTable(account, region, id)
		return err
	}},
	{"sg-", "security-group", "InvalidGroup.NotFound", func(app *Application, account, region, id string) error {
		_, err := app.repo.GetSecurityGroup(account, region, id)
		return err
	}},
	{"i-", "instance", "InvalidInstanceID.NotFound", func(app *Application, account, region, id string) error {
		_, err := app.repo.GetInstance(account, region, id)
		return err
	}},
	{"eni-", "network-interface", "InvalidNetworkInterfaceID.NotFound", func(app *Application, account, region, id string) error {
		_, err := app.repo.GetNetworkInterface(account, region, id)
		return err
	}},
	{"key-", "key-pair", "InvalidKeyPair.NotFound", func(app *Application, account, region, id string) error {
		_, err := app.repo.GetKeyPairByID(account, region, id)
		return err
	}},
	{"eipalloc-", "elastic-ip", "InvalidAllocationID.NotFound", func(app *Application, account, region, id string) error {
		_, err := app.repo.GetEIP(account, region, id)
		return err
	}},
}

// parseTags reads a flattened <prefix>N.Key / <prefix>N.Value list.
func parseTags(p url.Values, prefix string) []repository.EC2Tag {
	var out []repository.EC2Tag
	for _, it := range queryListItems(p, prefix) {
		out = append(out, repository.EC2Tag{Key: p.Get(it + "Key"), Value: p.Get(it + "Value")})
	}
	return out
}

// tagSpecifications reads TagSpecification.N as resource type → tags,
// or returns the InvalidParameterValue message for a type the
// operation cannot tag.
func tagSpecifications(p url.Values, allowed ...string) (map[string][]repository.EC2Tag, string) {
	out := map[string][]repository.EC2Tag{}
	for _, spec := range queryListItems(p, "TagSpecification.") {
		rt := p.Get(spec + "ResourceType")
		if !slices.Contains(allowed, rt) {
			return nil, fmt.Sprintf("'%s' is not a valid taggable resource type for this operation.", rt)
		}
		out[rt] = append(out[rt], parseTags(p, spec+"Tag.")...)
	}
	return out, ""
}

// refuseTagSpecifications parses TagSpecification.N and writes
// InvalidParameterValue when a type is not in allowed.
func refuseTagSpecifications(w http.ResponseWriter, p url.Values, allowed ...string) (map[string][]repository.EC2Tag, bool) {
	specs, msg := tagSpecifications(p, allowed...)
	if msg != "" {
		awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest, "InvalidParameterValue", msg)
		return nil, true
	}
	return specs, false
}

// onResource stamps tags with the id and type of the resource they go on.
func onResource(tags []repository.EC2Tag, id, resourceType string) []repository.EC2Tag {
	out := make([]repository.EC2Tag, len(tags))
	for i, t := range tags {
		t.ResourceID, t.ResourceType = id, resourceType
		out[i] = t
	}
	return out
}

// tagNew stores the tags of resources a Create* call just made. If
// that fails it deletes them with undo, so the create is all or nothing.
func (app *Application) tagNew(account, region string, tags []repository.EC2Tag, undo func() error) error {
	if err := app.repo.PutTags(account, region, tags); err != nil {
		return errors.Join(err, undo())
	}
	return nil
}

// tagSets returns each resource's tagSet by id, account-wide. It
// writes the error itself and reports false when the lookup fails.
func (app *Application) tagSets(w http.ResponseWriter, account string) (map[string][]ec2ResourceTagXML, bool) {
	tags, err := app.repo.ListTags(account, "")
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return nil, false
	}
	out := map[string][]ec2ResourceTagXML{}
	for _, t := range tags {
		out[t.ResourceID] = append(out[t.ResourceID], ec2ResourceTagXML{Key: t.Key, Value: t.Value})
	}
	return out, true
}

// taggableResources resolves each ResourceId.N to its EC2 resource
// type. It writes the typed NotFound code for a missing resource, and
// InvalidID for an id of a type fakeaws cannot tag, and then reports
// false.
func (app *Application) taggableResources(w http.ResponseWriter, account, region string, p url.Values) (map[string]string, bool) {
	ids := queryListValues(p, "ResourceId.")
	if len(ids) == 0 {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
			fmt.Errorf("ResourceId.N required: %w", models.ErrConflict))
		return nil, false
	}
	out := make(map[string]string, len(ids))
	for _, id := range ids {
		i := slices.IndexFunc(ec2TaggedKinds, func(k ec2TaggedKind) bool { return strings.HasPrefix(id, k.prefix) })
		if i < 0 {
			awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest,
				"InvalidID", fmt.Sprintf("The ID '%s' is not valid", id))
			return nil, false
		}
		kind := ec2TaggedKinds[i]
		err := kind.get(app, account, region, id)
		if errors.Is(err, models.ErrNotFound) {
			awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest,
				kind.notFound, fmt.Sprintf("The ID '%s' does not exist", id))
			return nil, false
		}
		if err != nil {
			awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
			return nil, false
		}
		out[id] = kind.resourceType
	}
	return out, true
}

func (app *Application) ec2CreateTags(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	resources, ok := app.taggableResources(w, account, region, req.Params)
	if !ok {
		return
	}
	add := parseTags(req.Params, "Tag.")
	if len(add) == 0 {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
			fmt.Errorf("Tag.N required: %w", models.ErrConflict))
		return
	}
	var tags []repository.EC2Tag
	for id, rt := range resources {
		tags = append(tags, onResource(add, id, rt)...)
	}
	if err := app.repo.PutTags(account, region, tags); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	app.ec2NoOpSuccess(w, "CreateTags")
}

// ec2DeleteTags removes each Tag.N by key, or by key and value when a
// Value is sent (an empty one included), and every tag when no Tag.N
// is sent, as EC2 does.
func (app *Application) ec2DeleteTags(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	resources, ok := app.taggableResources(w, account, region, req.Params)
	if !ok {
		return
	}
	var matches []repository.EC2TagMatch
	for _, it := range queryListItems(req.Params, "Tag.") {
		m := repository.EC2TagMatch{Key: req.Params.Get(it + "Key")}
		if req.Params.Has(it + "Value") {
			v := req.Params.Get(it + "Value")
			m.Value = &v
		}
		matches = append(matches, m)
	}
	if err := app.repo.DeleteTags(account, slices.Collect(maps.Keys(resources)), matches); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	app.ec2NoOpSuccess(w, "DeleteTags")
}

type ec2DescribeTagsResult struct {
	TagSet []ec2TagXML `xml:"tagSet>item"`
}

type ec2TagXML struct {
	ResourceId   string `xml:"resourceId"`
	ResourceType string `xml:"resourceType"`
	Key          string `xml:"key"`
	Value        string `xml:"value"`
}

// tagFilterValues maps each DescribeTags filter fakeaws supports to a
// tag's value for it. The provider filters by resource-id, and by key
// for single-tag lookups (the instance read's launch-template tags).
var tagFilterValues = map[string]func(repository.EC2Tag) string{
	"resource-id":   func(t repository.EC2Tag) string { return t.ResourceID },
	"resource-type": func(t repository.EC2Tag) string { return t.ResourceType },
	"key":           func(t repository.EC2Tag) string { return t.Key },
	"value":         func(t repository.EC2Tag) string { return t.Value },
}

// ec2DescribeTags lists the region's tags matching every filter; no
// match is a 200 with an empty tagSet. An unsupported filter is
// refused rather than ignored.
func (app *Application) ec2DescribeTags(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	filters := ec2Filters(req.Params)
	for name := range filters {
		if tagFilterValues[name] == nil {
			awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
				fmt.Errorf("DescribeTags filter %q not supported by fakeaws: %w", name, models.ErrConflict))
			return
		}
	}
	tags, err := app.repo.ListTags(account, region)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	out := ec2DescribeTagsResult{TagSet: []ec2TagXML{}}
	for _, t := range tags {
		if tagMatches(t, filters) {
			out.TagSet = append(out.TagSet, ec2TagXML{ResourceId: t.ResourceID, ResourceType: t.ResourceType, Key: t.Key, Value: t.Value})
		}
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DescribeTags", &out)
}

func tagMatches(t repository.EC2Tag, filters map[string][]string) bool {
	for name, want := range filters {
		if !slices.Contains(want, tagFilterValues[name](t)) {
			return false
		}
	}
	return true
}

// synthesizeInstanceType returns a plausible InstanceTypeInfo for any
// type name. Real values are looked up where well-known; otherwise a
// safe default keeps the schema fields non-nil.
func synthesizeInstanceType(name string) ec2InstanceTypeXML {
	type spec struct {
		vcpu int
		miB  int64
	}
	knownTypes := map[string]spec{
		"t2.micro":  {1, 1024},
		"t2.small":  {1, 2048},
		"t2.medium": {2, 4096},
		"t3.micro":  {2, 1024},
		"t3.small":  {2, 2048},
		"t3.medium": {2, 4096},
		"t3.large":  {2, 8192},
		"m5.large":  {2, 8192},
		"m5.xlarge": {4, 16384},
		"c5.large":  {2, 4096},
	}
	s, ok := knownTypes[name]
	if !ok {
		s = spec{vcpu: 2, miB: 4096}
	}
	return ec2InstanceTypeXML{
		InstanceType: name,
		VCpuInfo:     ec2InstanceVCpuInfo{DefaultVCpus: s.vcpu},
		MemoryInfo:   ec2InstanceMemoryInfo{SizeInMiB: s.miB},
		Hypervisor:   "nitro",
	}
}

// gatherEC2StateReal emits the EC2 block of /mock/state. Per
// concepts.md "Required surface" item 4 — topology_derive_aws keys
// off this shape; lists are non-nil so countOrphans assertions
// distinguish "no resources" from "service not yet shipped".
//
// Codex pass 3 BLOCKING #2 fix: every modeled collection emits
// its actual contents (was previously declaring keys but only
// filling vpcs/subnets/instances).
func (app *Application) gatherEC2StateReal() map[string]any {
	const account = awsproto.FakeAccountID
	out := map[string]any{
		"vpcs":                     []any{},
		"subnets":                  []any{},
		"security_groups":          []any{},
		"instances":                []any{},
		"key_pairs":                []any{},
		"internet_gateways":        []any{},
		"route_tables":             []any{},
		"routes":                   []any{},
		"route_table_associations": []any{},
		"eips":                     []any{},
		"network_interfaces":       []any{},
	}

	vpcs, _ := app.repo.ListVPCs(account, "")
	vOut := make([]map[string]any, 0, len(vpcs))
	for _, v := range vpcs {
		vOut = append(vOut, map[string]any{
			"id": v.ID, "cidr_block": v.CidrBlock, "region": v.Region, "arn": v.ARN,
		})
	}
	out["vpcs"] = vOut

	subnets, _ := app.repo.ListSubnets(account, "", "")
	sOut := make([]map[string]any, 0, len(subnets))
	for _, s := range subnets {
		sOut = append(sOut, map[string]any{
			"id": s.ID, "vpc_id": s.VPCID, "cidr_block": s.CidrBlock,
			"availability_zone": s.AvailabilityZone, "region": s.Region, "arn": s.ARN,
			"map_public_ip_on_launch": s.MapPublicIPOnLaunch,
		})
	}
	out["subnets"] = sOut

	// Instance network fields come from the primary ENI; a terminated
	// instance has none, so its IPs are "" and its groups [].
	instances, _ := app.repo.ListInstances(account, "")
	enis, _ := app.instanceENIs(account)
	iOut := make([]map[string]any, 0, len(instances))
	for _, inst := range instances {
		eni := enis[inst.ID]
		if eni == nil {
			eni = &repository.EC2NetworkInterface{SecurityGroupIDs: []string{}}
		}
		// Codex pass 15 BLOCKING #2: include iam_instance_profile_name
		// and vpc_security_group_ids — both are FK-bearing modeled
		// fields. Previously /mock/state stripped them so an instance
		// re-bound to a different IAM profile or SG set was invisible.
		iOut = append(iOut, map[string]any{
			"id": inst.ID, "subnet_id": inst.SubnetID, "ami_id": inst.AMIID,
			"instance_type":             inst.InstanceType,
			"iam_instance_profile_name": inst.IAMInstanceProfileName,
			"vpc_security_group_ids":    eni.SecurityGroupIDs,
			"public_ip":                 eni.PublicIP,
			"private_ip":                eni.PrivateIP,
			"state":                     inst.State,
			"region":                    inst.Region, "arn": inst.ARN,
		})
	}
	out["instances"] = iOut

	allENIs, _ := app.repo.ListNetworkInterfaces(account, "")
	eniOut := make([]map[string]any, 0, len(allENIs))
	for _, eni := range allENIs {
		eniOut = append(eniOut, map[string]any{
			"id": eni.ID, "instance_id": eni.InstanceID,
			"subnet_id": eni.SubnetID, "vpc_id": eni.VPCID,
			"private_ip": eni.PrivateIP, "public_ip": eni.PublicIP,
			"security_group_ids": eni.SecurityGroupIDs,
			"source_dest_check":  eni.SourceDestCheck,
			"region":             eni.Region,
		})
	}
	out["network_interfaces"] = eniOut

	// Security groups — every SG, exactly once. Codex pass 4 BLOCKING
	// #1 fix: previous version inferred from instance.VPCSecurityGroupIDs
	// which missed standalone SGs and duplicated shared ones. Rules are
	// exported in both directions for state policies (open ingress).
	sgs, _ := app.repo.ListSecurityGroups(account, "")
	sgOut := make([]map[string]any, 0, len(sgs))
	for _, sg := range sgs {
		ing, eg, _ := app.repo.GetSecurityGroupRules(account, sg.Region, sg.ID)
		ingress, _ := decodeSGRules(ing)
		egress, _ := decodeSGRules(eg)
		sgOut = append(sgOut, map[string]any{
			"id": sg.ID, "vpc_id": sg.VPCID, "group_name": sg.GroupName,
			"description": sg.Description, "region": sg.Region, "arn": sg.ARN,
			"ip_permissions":        sgPermsState(ingress),
			"ip_permissions_egress": sgPermsState(egress),
		})
	}
	out["security_groups"] = sgOut

	// Key pairs — account-wide list (Codex pass 8 BLOCKING #2 fix:
	// previously walked a hard-coded region slice, so KPs created in
	// any other region disappeared from /mock/state).
	kpOut := []map[string]any{}
	kps, _ := app.repo.ListKeyPairs(account, "")
	for _, kp := range kps {
		kpOut = append(kpOut, map[string]any{
			"name": kp.Name, "fingerprint": kp.Fingerprint, "region": kp.Region,
		})
	}
	out["key_pairs"] = kpOut

	// Internet gateways — account-wide list. Used by topology
	// derivation to detect public subnets.
	igws, _ := app.repo.ListInternetGateways(account, "")
	igwOut := make([]map[string]any, 0, len(igws))
	for _, igw := range igws {
		igwOut = append(igwOut, map[string]any{
			"id": igw.ID, "vpc_id": igw.VPCID,
			"region": igw.Region, "arn": igw.ARN,
		})
	}
	out["internet_gateways"] = igwOut

	// Route tables, routes, associations, and EIPs — Codex pass 10
	// BLOCKING #2 fix: previously absent from /mock/state, so
	// topology_derive_aws couldn't see public-subnet wiring or
	// allocated EIPs.
	rts, _ := app.repo.ListRouteTables(account, "")
	rtOut := make([]map[string]any, 0, len(rts))
	for _, rt := range rts {
		rtOut = append(rtOut, map[string]any{
			"id": rt.ID, "vpc_id": rt.VPCID,
			"region": rt.Region, "arn": rt.ARN,
		})
	}
	out["route_tables"] = rtOut

	routes, _ := app.repo.ListRoutes(account)
	routeOut := make([]map[string]any, 0, len(routes))
	for _, rr := range routes {
		routeOut = append(routeOut, map[string]any{
			"route_table_id":         rr.RouteTableID,
			"destination_cidr_block": rr.DestinationCidrBlock,
			"gateway_id":             rr.GatewayID,
			"nat_gateway_id":         rr.NatGatewayID,
			"instance_id":            rr.InstanceID,
			"network_interface_id":   rr.NetworkInterfaceID,
		})
	}
	out["routes"] = routeOut

	assocs, _ := app.repo.ListRouteTableAssociations(account)
	assocOut := make([]map[string]any, 0, len(assocs))
	for _, a := range assocs {
		assocOut = append(assocOut, map[string]any{
			"id":             a.ID,
			"route_table_id": a.RouteTableID,
			"subnet_id":      a.SubnetID,
		})
	}
	out["route_table_associations"] = assocOut

	eips, _ := app.repo.ListEIPs(account, "")
	eipOut := make([]map[string]any, 0, len(eips))
	for _, eip := range eips {
		eipOut = append(eipOut, map[string]any{
			"allocation_id":        eip.AllocationID,
			"public_ip":            eip.PublicIP,
			"domain":               eip.Domain,
			"network_interface_id": eip.NetworkInterfaceID,
			"instance_id":          eip.InstanceID,
			"association_id":       eip.AssociationID,
			"region":               eip.Region,
			"arn":                  awsproto.BuildEC2EIPARN(eip.Region, eip.AllocationID),
		})
	}
	out["eips"] = eipOut

	return out
}

// ensureAMIFixturesForRegion lazy-seeds the canonical AMI set into a
// region the first time we observe a request scoped to it. Codex
// pass 9 BLOCKING #1: previously fixtures were only seeded for an
// 8-region slice at boot, so RunInstances/DescribeImages in any
// other region got bogus 404s on the canonical AMIs. Now any region
// the user touches becomes consistent on first contact. SeedAMI is
// idempotent so re-entry is harmless.
func (app *Application) ensureAMIFixturesForRegion(account, region string) {
	for _, a := range ec2AMIFixtures {
		cp := a
		cp.Region = region
		_ = app.repo.SeedAMI(account, &cp)
	}
}

// SeedEC2AMIFixtures writes the canonical AMI set into every region
// referenced by /mock/state. It's idempotent (INSERT OR IGNORE in the
// repo) so calling it on every boot is safe.
//
// Called from NewApplication after the repo is open; tests that hit
// DescribeImages get a populated fixture set without any explicit
// admin call.
func (app *Application) SeedEC2AMIFixtures(account string, regions []string) error {
	for _, region := range regions {
		for _, a := range ec2AMIFixtures {
			cp := a
			cp.Region = region
			if err := app.repo.SeedAMI(account, &cp); err != nil {
				return err
			}
		}
	}
	return nil
}
