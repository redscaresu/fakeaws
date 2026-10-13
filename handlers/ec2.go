package handlers

import (
	"cmp"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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

// handleEC2 dispatches an EC2 Query-RPC request on its Action.
//
// MUST[ec2-describe-filter-never-ignored]: every Describe arm but
// DescribeVpcAttribute, DescribeInstanceAttribute and
// DescribeAddressesAttribute (no Filter in the AWS API) reads through
// an ec2FilterTable's read, naming the params it reads; every other
// param but MaxResults and NextToken, and every Filter.N the table does
// not honour, goes to ec2Refuse: 501 NotImplemented naming it, classed
// filter-refused. A Describe never ignores a param.
func (app *Application) handleEC2(w http.ResponseWriter, r *http.Request) {
	region := chi.URLParam(r, "region")
	req, err := awsproto.ParseQueryRPC(r)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
			fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}
	account, err := app.AccountID()
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, fmt.Errorf("read account id: %w", err))
		return
	}

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

	// ----- NetworkInterface (instance primary ENIs, loaded ENIs) -----
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

	// ----- AvailabilityZone (read-only) -----
	case "DescribeAvailabilityZones":
		app.ec2DescribeAvailabilityZones(w, account, region, req)

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

	// ----- InstanceAttribute -----
	// terraform-provider-aws calls DescribeInstanceAttribute for each
	// scalar attribute on the read path (disableApiTermination,
	// disableApiStop, userData, instanceInitiatedShutdownBehavior).
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
	case "DescribeSecurityGroupRules":
		app.ec2DescribeSecurityGroupRules(w, account, region, req)
	case "ModifySecurityGroupRules":
		ec2Refuse(w, req.Action, "SecurityGroupRule.N")

	// Any other Action hits the default arm and surfaces as 404 with
	// a log line — per concepts.md "Anti-patterns explicitly forbidden",
	// no silent 200.
	default:
		markClass(w, classNotModelled404)
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
			fmt.Errorf("EC2 action %q not yet implemented in fakeaws v1: %w", req.Action, models.ErrNotFound))
	}
}

// ----- VPC handlers -----

// ec2VpcXML mirrors the real EC2 CreateVpc/DescribeVpcs response
// shape. terraform-provider-aws's resourceVPCCreate (vpc_.go:235)
// iterates CidrBlockAssociationSet and reads OwnerId during Read;
// nil/missing values panic the provider plugin. Every field is the
// stored VPC's (ec2VpcToXML): newEC2VPC fills each for a created VPC.
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
	State         string `xml:"state"`
	StatusMessage string `xml:"statusMessage,omitempty"`
}

type ec2VpcIpv6BlockAssociationXML struct {
	AssociationId        string                          `xml:"associationId"`
	Ipv6CidrBlock        string                          `xml:"ipv6CidrBlock"`
	CidrBlockState       ec2VpcCidrBlockAssociationState `xml:"ipv6CidrBlockState"`
	Ipv6Pool             string                          `xml:"ipv6Pool,omitempty"`
	NetworkBorderGroup   string                          `xml:"networkBorderGroup,omitempty"`
	IpSource             string                          `xml:"ipSource,omitempty"`
	Ipv6AddressAttribute string                          `xml:"ipv6AddressAttribute,omitempty"`
}

type ec2DescribeVpcsResult struct {
	VpcSet []ec2VpcXML `xml:"vpcSet>item"`
}

type ec2CreateVpcResult struct {
	Vpc ec2VpcXML `xml:"vpc"`
}

// ec2CreateVpc stores the VPC and its default security group.
//
// CRITICAL[ec2-vpc-default-security-group]: CreateVpc stores the VPC
// and its security group named default, description "default VPC
// security group", in one transaction, so DescribeSecurityGroups
// group-name=default with vpc-id answers exactly that group, as
// terraform-provider-aws's default_security_group_id and
// aws_default_security_group read it. CreateSecurityGroup refuses the
// name with 400 InvalidGroup.Reserved and DeleteSecurityGroup refuses
// the group with 400 CannotDelete, so the VPC keeps it until DeleteVpc.
// A database that is not loaded gets one for each VPC stored without
// it (repository.BackfillDefaultGroups) at boot and in /mock/restore's
// copy of the snapshot before it goes live; a loaded database answers
// its rows. The group has no rules: AWS's allows all traffic from itself and all
// egress, but fakeaws gives a created group no default egress either.
//
// UNVERIFIED(aws-code): InvalidGroup.Reserved and CannotDelete from https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html; no recording
func (app *Application) ec2CreateVpc(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	cidr := req.Params.Get("CidrBlock")
	if cidr == "" {
		ec2Refuse(w, req.Action, "no CidrBlock") // AWS also takes Ipv4IpamPoolId
		return
	}
	specs, refused := refuseTagSpecifications(w, req.Params, "vpc")
	if refused {
		return
	}
	id := "vpc-" + ec2RandID()
	v := newEC2VPC(account, region, id, cidr)
	err := app.repo.CreateVPCWithDefaultGroup(account, v, newDefaultGroup(account, region, id))
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

// ec2NoFilters honours no filter: a Describe reading through it
// refuses every Filter.N, by name.
var ec2NoFilters ec2FilterTable[any]

// vpcIsDefault is the VPC's isDefault: false for a created VPC, as
// fakeaws makes no default VPC, and the recorded value for a loaded one.
func vpcIsDefault(v ec2VpcXML) []string { return []string{strconv.FormatBool(v.IsDefault)} }

// vpcFilters are the DescribeVpcs filters fakeaws models: the AWS
// names whose value a VPC answers, isDefault (data.aws_vpc's spelling
// of is-default) and the tag filters.
var vpcFilters = ec2FilterTable[ec2VpcXML]{
	values: map[string]func(ec2VpcXML) []string{
		"vpc-id":   func(v ec2VpcXML) []string { return []string{v.VpcId} },
		"cidr":     func(v ec2VpcXML) []string { return []string{v.CidrBlock} },
		"state":    func(v ec2VpcXML) []string { return []string{v.State} },
		"owner-id": func(v ec2VpcXML) []string { return []string{v.OwnerId} },
		"cidr-block-association.cidr-block": func(v ec2VpcXML) []string {
			var out []string
			for _, a := range v.CidrBlockAssociationSet {
				out = append(out, a.CidrBlock)
			}
			return out
		},
		"is-default": vpcIsDefault,
		"isDefault":  vpcIsDefault,
	},
	tagID: func(v ec2VpcXML) string { return v.VpcId },
}

// ec2DescribeVpcs answers VpcId.N with exactly those VPCs: the
// provider's lookup by id wants one result, so listing every VPC in
// the region breaks it as soon as a second VPC exists.
func (app *Application) ec2DescribeVpcs(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	filters, ok := vpcFilters.read(w, req, "VpcId.N")
	if !ok {
		return
	}
	var vpcs []*repository.EC2VPC
	ids := queryIDs(req.Params, "VpcId.")
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
		if vpcFilters.matches(x, filters, tags) {
			out.VpcSet = append(out.VpcSet, x)
		}
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DescribeVpcs", &out)
}

// ec2DescribeVpcAttribute models the real EC2 API: caller specifies
// one attribute (enableDnsHostnames / enableDnsSupport / etc.) via
// the `Attribute` parameter, response returns just that attribute's
// boolean value. terraform-provider-aws calls this twice as part of
// the aws_vpc Read flow (once per attribute) after CreateVpc.
func (app *Application) ec2DescribeVpcAttribute(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	v, err := app.repo.GetVPC(account, region, req.Params.Get("VpcId"))
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	out := ec2VpcAttribute(v, req.Params.Get("Attribute"))
	awsproto.WriteEC2QueryRPCResponse(w, "DescribeVpcAttribute", &out)
}

// ec2VpcAttribute is v's attribute: the stored enableDnsSupport or
// enableDnsHostnames, or enableNetworkAddressUsageMetrics, which is
// always false.
func ec2VpcAttribute(v *repository.EC2VPC, attr string) ec2DescribeVpcAttributeResult {
	out := ec2DescribeVpcAttributeResult{VpcId: v.ID}
	switch attr {
	case "enableDnsSupport":
		out.EnableDnsSupport = &ec2BoolValue{Value: *vpcDNS(v, attr)}
	case "enableDnsHostnames":
		out.EnableDnsHostnames = &ec2BoolValue{Value: *vpcDNS(v, attr)}
	case "enableNetworkAddressUsageMetrics":
		out.EnableNetworkAddressUsageMetrics = &ec2BoolValue{Value: false}
	}
	return out
}

// ec2VpcDNSAttributes are the VPC attributes fakeaws stores, as
// DescribeVpcAttribute names them.
var ec2VpcDNSAttributes = []string{"enableDnsSupport", "enableDnsHostnames"}

// vpcDNS is v's field holding attr, one of ec2VpcDNSAttributes.
func vpcDNS(v *repository.EC2VPC, attr string) *bool {
	if attr == "enableDnsSupport" {
		return &v.EnableDNSSupport
	}
	return &v.EnableDNSHostnames
}

// vpcDNSParam is the ModifyVpcAttribute param that sets attr:
// EnableDnsSupport.Value for enableDnsSupport.
func vpcDNSParam(attr string) string { return strings.ToUpper(attr[:1]) + attr[1:] + ".Value" }

// ec2ModifyVpcAttribute stores each of ec2VpcDNSAttributes its param
// (vpcDNSParam) sets, true or false (400 InvalidParameterValue
// otherwise), for DescribeVpcAttribute to answer. Any other attribute
// is accepted and not stored.
func (app *Application) ec2ModifyVpcAttribute(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	p := req.Params
	values := map[string][]string{}
	for _, attr := range ec2VpcDNSAttributes {
		values[vpcDNSParam(attr)] = ec2Bool
	}
	if refuseInvalidValues(w, p, values) {
		return
	}
	err := app.repo.UpdateVPC(account, region, p.Get("VpcId"), func(v *repository.EC2VPC) {
		for _, attr := range ec2VpcDNSAttributes {
			if p.Has(vpcDNSParam(attr)) {
				*vpcDNS(v, attr) = p.Get(vpcDNSParam(attr)) == "true"
			}
		}
	})
	if err != nil {
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
	MapCustomerOwnedIpOnLaunch    *bool                           `xml:"mapCustomerOwnedIpOnLaunch,omitempty"`
	AssignIpv6AddressOnCreation   bool                            `xml:"assignIpv6AddressOnCreation"`
	EnableDns64                   *bool                           `xml:"enableDns64,omitempty"`
	Ipv6Native                    *bool                           `xml:"ipv6Native,omitempty"`
	EnableLniAtDeviceIndex        *int                            `xml:"enableLniAtDeviceIndex,omitempty"`
	CustomerOwnedIpv4Pool         string                          `xml:"customerOwnedIpv4Pool,omitempty"`
	OutpostArn                    string                          `xml:"outpostArn,omitempty"`
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

// CRITICAL[ec2-subnet-overlap-refused]: a CidrBlock overlapping a subnet
// of the same VPC is refused 400 InvalidSubnet.Conflict naming it, and
// nothing is stored; the overlap check and the INSERT share one tx
// (repository.CreateSubnet), so concurrent creates cannot both pass.
//
// UNVERIFIED(aws-code): InvalidSubnet.Conflict from https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html; no recording
func (app *Application) ec2CreateSubnet(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	vpcID := req.Params.Get("VpcId")
	cidr := req.Params.Get("CidrBlock")
	if vpcID == "" || cidr == "" {
		ec2Refuse(w, req.Action, "no VpcId or CidrBlock") // AWS also takes Ipv6Native or Ipv4IpamPoolId
		return
	}
	vpc, err := app.repo.GetVPC(account, region, vpcID)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	if !subnetCIDRInRange(vpc.CidrBlock, cidr) {
		awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest, "InvalidSubnet.Range",
			fmt.Sprintf("The CIDR '%s' is invalid.", cidr))
		return
	}
	zones, zoneID, err := app.ec2Zones(account, region)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	az, ok := subnetZone(req.Params, region, zones, zoneID)
	if !ok {
		ec2Refuse(w, req.Action, "AvailabilityZoneId")
		return
	}
	specs, refused := refuseTagSpecifications(w, req.Params, "subnet")
	if refused {
		return
	}
	id := "subnet-" + ec2RandID()
	s := newEC2Subnet(account, region, id, vpcID, cidr, az)
	err = app.repo.CreateSubnet(account, s)
	if errors.Is(err, repository.ErrSubnetConflict) {
		awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest, "InvalidSubnet.Conflict",
			fmt.Sprintf("The CIDR '%s' conflicts with another subnet", cidr))
		return
	}
	if err == nil {
		err = app.tagNew(account, region, onResource(specs["subnet"], id, "subnet"),
			func() error { return app.repo.DeleteSubnet(account, region, id) })
	}
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	out := ec2CreateSubnetResult{Subnet: ec2SubnetToXML(s, zoneID)}
	awsproto.WriteEC2QueryRPCResponse(w, "CreateSubnet", &out)
}

// subnetZone is the zone CreateSubnet places a subnet in:
// AvailabilityZone, else the zone of zones (ec2Zones) whose id is
// AvailabilityZoneId, else <region>a. It reports false for an
// AvailabilityZoneId that is no zone's id, or another zone's than
// AvailabilityZone names: fakeaws cannot tell an id it lacks from one
// AWS lacks, so the caller refuses it rather than ignore it.
func subnetZone(p url.Values, region string, zones []repository.AvailabilityZone, zoneID func(string) string) (string, bool) {
	az := p.Get("AvailabilityZone")
	if p.Has("AvailabilityZoneId") {
		id := p.Get("AvailabilityZoneId")
		i := slices.IndexFunc(zones, func(z repository.AvailabilityZone) bool { return zoneID(z.ZoneName) == id })
		if i < 0 || az != "" && az != zones[i].ZoneName {
			return "", false
		}
		az = zones[i].ZoneName
	}
	return cmp.Or(az, region+"a"), true
}

// subnetCIDRInRange reports whether EC2 accepts cidr as a subnet of a
// VPC whose block is vpcCIDR: inside it, and between /16 and /28.
// Overlap with sibling subnets is refused by repository.CreateSubnet.
func subnetCIDRInRange(vpcCIDR, cidr string) bool {
	vpc, err := netip.ParsePrefix(vpcCIDR)
	if err != nil {
		return false
	}
	sub, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}
	return sub.Bits() >= 16 && sub.Bits() <= 28 && sub.Bits() >= vpc.Bits() && vpc.Contains(sub.Addr())
}

func subnetCidrBlock(s ec2SubnetXML) []string    { return []string{s.CidrBlock} }
func subnetAZ(s ec2SubnetXML) []string           { return []string{s.AvailabilityZone} }
func subnetAZID(s ec2SubnetXML) []string         { return []string{s.AvailabilityZoneId} }
func subnetDefaultForAz(s ec2SubnetXML) []string { return []string{strconv.FormatBool(s.DefaultForAz)} }

// subnetFilters are the DescribeSubnets filters fakeaws models: the AWS
// names whose value a subnet answers, each camelCase alias AWS
// documents and data.aws_subnet sends, and the tag filters.
var subnetFilters = ec2FilterTable[ec2SubnetXML]{
	values: map[string]func(ec2SubnetXML) []string{
		"subnet-id":            func(s ec2SubnetXML) []string { return []string{s.SubnetId} },
		"vpc-id":               func(s ec2SubnetXML) []string { return []string{s.VpcId} },
		"state":                func(s ec2SubnetXML) []string { return []string{s.State} },
		"owner-id":             func(s ec2SubnetXML) []string { return []string{s.OwnerId} },
		"cidr-block":           subnetCidrBlock,
		"cidr":                 subnetCidrBlock,
		"cidrBlock":            subnetCidrBlock,
		"availability-zone":    subnetAZ,
		"availabilityZone":     subnetAZ,
		"availability-zone-id": subnetAZID,
		"availabilityZoneId":   subnetAZID,
		"default-for-az":       subnetDefaultForAz,
		"defaultForAz":         subnetDefaultForAz,
		"map-public-ip-on-launch": func(s ec2SubnetXML) []string {
			return []string{strconv.FormatBool(s.MapPublicIpOnLaunch)}
		},
	},
	tagID: func(s ec2SubnetXML) string { return s.SubnetId },
}

// ec2SubnetNotFound is EC2's code for a subnet id it does not have.
const ec2SubnetNotFound = "InvalidSubnetID.NotFound"

// ec2DescribeSubnets answers SubnetId.N, the direct-by-id lookup the
// provider's Read sends to find exactly the subnet it created (a wrong
// match count loops its wait until "couldn't find resource"), and
// subnetFilters. An unknown SubnetId.N is 400 InvalidSubnetID.NotFound
// naming it, which the provider's delete wait reads as gone.
func (app *Application) ec2DescribeSubnets(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	filters, ok := subnetFilters.read(w, req, "SubnetId.N")
	if !ok {
		return
	}
	ids := queryListValues(req.Params, "SubnetId.")
	subnets, err := app.repo.ListSubnets(account, region)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	for _, id := range ids {
		if !slices.ContainsFunc(subnets, func(s *repository.EC2Subnet) bool { return s.ID == id }) {
			awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest,
				ec2SubnetNotFound, fmt.Sprintf("The subnet ID '%s' does not exist", id))
			return
		}
	}
	_, zoneID, err := app.ec2Zones(account, region)
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
		x := ec2SubnetToXML(s, zoneID)
		x.TagSet = tags[s.ID]
		if len(ids) > 0 && !slices.Contains(ids, s.ID) || !subnetFilters.matches(x, filters, tags) {
			continue
		}
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

// newEC2VPC is a created VPC: not the default VPC, under placeholder
// DHCP options, with its one CIDR block associated and both DNS
// attributes true. AWS defaults enableDnsHostnames to false.
func newEC2VPC(account, region, id, cidr string) *repository.EC2VPC {
	return &repository.EC2VPC{
		ID: id, CidrBlock: cidr, Region: region,
		ARN:             awsproto.BuildEC2VPCARN(region, account, id),
		State:           "available",
		CreatedAt:       time.Now().UTC().Format(time.RFC3339),
		OwnerID:         account,
		DhcpOptionsID:   "dopt-fakeaws-default",
		InstanceTenancy: "default",
		CidrBlockAssociations: []repository.EC2CidrBlockAssociation{
			{AssociationID: "vpc-cidr-assoc-" + id, CidrBlock: cidr, State: "associated"},
		},
		EnableDNSSupport:   true,
		EnableDNSHostnames: true,
	}
}

// newEC2Subnet is a created subnet: IPv4 only, not the default for its
// zone, its instances named by IP.
func newEC2Subnet(account, region, id, vpcID, cidr, az string) *repository.EC2Subnet {
	return &repository.EC2Subnet{
		ID: id, VPCID: vpcID, CidrBlock: cidr, AvailabilityZone: az,
		Region: region,
		ARN:    awsproto.BuildEC2SubnetARN(region, account, id),
		State:  "available", CreatedAt: time.Now().UTC().Format(time.RFC3339),
		OwnerID:                       account,
		AvailableIPAddressCount:       subnetAvailableIPs(cidr),
		MapCustomerOwnedIPOnLaunch:    new(false),
		EnableDNS64:                   new(false),
		Ipv6Native:                    new(false),
		PrivateDNSNameOptionsOnLaunch: &repository.EC2PrivateDNSNameOptions{HostnameType: "ip-name"},
	}
}

// subnetAvailableIPs is a new subnet's available IPv4 count: its
// block's size less the 5 addresses AWS reserves (.0 to .3 and the
// broadcast), 251 for a /24, and 251 for a block it cannot parse.
func subnetAvailableIPs(cidr string) int {
	p, err := netip.ParsePrefix(cidr)
	if err != nil || p.Bits() < 16 || p.Bits() > 28 {
		return 251
	}
	return 1<<(32-p.Bits()) - 5
}

func newEC2SecurityGroup(account, region, vpcID, name, desc string) *repository.EC2SecurityGroup {
	id := "sg-" + ec2RandID()
	return &repository.EC2SecurityGroup{
		ID: id, VPCID: vpcID, GroupName: name, Description: desc,
		Region: region, OwnerID: account,
		ARN:       awsproto.BuildEC2SecurityGroupARN(region, account, id),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

// newDefaultGroup is vpcID's security group named default.
func newDefaultGroup(account, region, vpcID string) *repository.EC2SecurityGroup {
	return newEC2SecurityGroup(account, region, vpcID, repository.DefaultGroupName, "default VPC security group")
}

func ec2VpcToXML(v *repository.EC2VPC) ec2VpcXML {
	x := ec2VpcXML{
		VpcId:           v.ID,
		State:           v.State,
		CidrBlock:       v.CidrBlock,
		DhcpOptionsId:   v.DhcpOptionsID,
		InstanceTenancy: v.InstanceTenancy,
		OwnerId:         v.OwnerID,
		IsDefault:       v.IsDefault,
	}
	for _, a := range v.CidrBlockAssociations {
		x.CidrBlockAssociationSet = append(x.CidrBlockAssociationSet, ec2VpcCidrBlockAssociationXML{
			AssociationId: a.AssociationID, CidrBlock: a.CidrBlock, CidrBlockState: ec2CidrBlockState(a),
		})
	}
	for _, a := range v.Ipv6CidrBlockAssociations {
		x.Ipv6CidrBlockAssociationSet = append(x.Ipv6CidrBlockAssociationSet, ec2VpcIpv6BlockAssociationXML{
			AssociationId: a.AssociationID, Ipv6CidrBlock: a.CidrBlock, CidrBlockState: ec2CidrBlockState(a),
			Ipv6Pool: a.Ipv6Pool, NetworkBorderGroup: a.NetworkBorderGroup, IpSource: a.IPSource, Ipv6AddressAttribute: a.Ipv6AddressAttribute,
		})
	}
	return x
}

// ec2CidrBlockState is a's cidrBlockState or ipv6CidrBlockState.
func ec2CidrBlockState(a repository.EC2CidrBlockAssociation) ec2VpcCidrBlockAssociationState {
	return ec2VpcCidrBlockAssociationState{State: a.State, StatusMessage: a.StatusMessage}
}

// ec2SubnetToXML answers s, its availabilityZoneId from zoneID (ec2Zones).
func ec2SubnetToXML(s *repository.EC2Subnet, zoneID func(zone string) string) ec2SubnetXML {
	x := ec2SubnetXML{
		SubnetId:                    s.ID,
		VpcId:                       s.VPCID,
		State:                       s.State,
		CidrBlock:                   s.CidrBlock,
		AvailabilityZone:            s.AvailabilityZone,
		AvailabilityZoneId:          zoneID(s.AvailabilityZone),
		AvailableIpAddressCount:     s.AvailableIPAddressCount,
		OwnerId:                     s.OwnerID,
		SubnetArn:                   s.ARN,
		DefaultForAz:                s.DefaultForAz,
		MapPublicIpOnLaunch:         s.MapPublicIPOnLaunch,
		MapCustomerOwnedIpOnLaunch:  s.MapCustomerOwnedIPOnLaunch,
		AssignIpv6AddressOnCreation: s.AssignIpv6AddressOnCreation,
		EnableDns64:                 s.EnableDNS64,
		Ipv6Native:                  s.Ipv6Native,
		EnableLniAtDeviceIndex:      s.EnableLniAtDeviceIndex,
		CustomerOwnedIpv4Pool:       s.CustomerOwnedIpv4Pool,
		OutpostArn:                  s.OutpostARN,
	}
	for _, a := range s.Ipv6CidrBlockAssociations {
		x.Ipv6CidrBlockAssociationSet = append(x.Ipv6CidrBlockAssociationSet, ec2SubnetIpv6BlockAssociation{
			AssociationId: a.AssociationID, Ipv6CidrBlock: a.CidrBlock, CidrBlockState: ec2CidrBlockState(a),
		})
	}
	if o := s.PrivateDNSNameOptionsOnLaunch; o != nil {
		x.PrivateDnsNameOptionsOnLaunch = &ec2SubnetPrivateDnsOptionsXML{
			HostnameType: o.HostnameType, EnableResourceNameDnsARecord: o.EnableResourceNameDNSARecord,
			EnableResourceNameDnsAAAARecord: o.EnableResourceNameDNSAAAARecord,
		}
	}
	return x
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
	out := ec2IgwXML{InternetGatewayId: igw.ID, OwnerId: igw.OwnerID}
	if igw.VPCID != "" {
		out.Attachments = []ec2IgwAttachmentXML{{VpcId: igw.VPCID, State: igw.AttachmentState}}
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
		ARN:       awsproto.BuildEC2InternetGatewayARN(region, account, id),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		OwnerID:   account,
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

// igwFilters are the DescribeInternetGateways filters fakeaws models:
// the AWS names whose value a gateway answers and the tag filters. A
// detached gateway has no attachment.vpc-id or attachment.state.
var igwFilters = ec2FilterTable[ec2IgwXML]{
	values: map[string]func(ec2IgwXML) []string{
		"internet-gateway-id": func(g ec2IgwXML) []string { return []string{g.InternetGatewayId} },
		"owner-id":            func(g ec2IgwXML) []string { return []string{g.OwnerId} },
		"attachment.vpc-id": func(g ec2IgwXML) []string {
			var out []string
			for _, a := range g.Attachments {
				out = append(out, a.VpcId)
			}
			return out
		},
		"attachment.state": func(g ec2IgwXML) []string {
			var out []string
			for _, a := range g.Attachments {
				out = append(out, a.State)
			}
			return out
		},
	},
	tagID: func(g ec2IgwXML) string { return g.InternetGatewayId },
}

// ec2DescribeInternetGateways answers InternetGatewayId.N with exactly
// those gateways, as ec2DescribeVpcs does VpcId.N.
func (app *Application) ec2DescribeInternetGateways(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	filters, ok := igwFilters.read(w, req, "InternetGatewayId.N")
	if !ok {
		return
	}
	var igws []*repository.EC2InternetGateway
	ids := queryIDs(req.Params, "InternetGatewayId.")
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
		if igwFilters.matches(x, filters, tags) {
			out.InternetGatewaySet = append(out.InternetGatewaySet, x)
		}
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

// ec2RouteTableAssociationXML is an associationSet item: a subnet's
// association, a gateway's (an edge association) or a main one, which
// has neither subnetId nor gatewayId.
type ec2RouteTableAssociationXML struct {
	AssociationId string `xml:"routeTableAssociationId"`
	RouteTableId  string `xml:"routeTableId"`
	SubnetId      string `xml:"subnetId,omitempty"`
	GatewayId     string `xml:"gatewayId,omitempty"`
	Main          bool   `xml:"main"`
	// AssociationState is the structured indicator the provider uses
	// to decide whether the association is ready. AssociateRouteTable
	// stores "associated", the terminal state; a loaded association
	// answers its recorded state, or none when the recording held none.
	AssociationState *ec2AssociationStateXML `xml:"associationState"`
}

type ec2AssociationStateXML struct {
	State string `xml:"state"`
}

func ec2AssociationToXML(a *repository.EC2RouteTableAssociation) ec2RouteTableAssociationXML {
	x := ec2RouteTableAssociationXML{AssociationId: a.ID, RouteTableId: a.RouteTableID, SubnetId: a.SubnetID, GatewayId: a.GatewayID, Main: a.Main}
	if a.State != "" {
		x.AssociationState = &ec2AssociationStateXML{State: a.State}
	}
	return x
}

type ec2CreateRouteTableResult struct {
	RouteTable ec2RouteTableXML `xml:"routeTable"`
}

// ec2RouteXML mirrors the per-route entry under <routeSet><item>. The
// provider's CreateRoute wait-loop polls DescribeRouteTables and looks
// for its destination CIDR in this set; without it, the wait times
// out after 5 minutes per iteration. CreateRoute stores State "active"
// (there's no async install step in the mock) and Origin
// "CreateRoute"; a loaded route answers its recorded ones, a table's
// local route origin CreateRouteTable.
type ec2RouteXML struct {
	DestinationCidrBlock string `xml:"destinationCidrBlock"`
	GatewayId            string `xml:"gatewayId,omitempty"`
	NatGatewayId         string `xml:"natGatewayId,omitempty"`
	InstanceId           string `xml:"instanceId,omitempty"`
	NetworkInterfaceId   string `xml:"networkInterfaceId,omitempty"`
	State                string `xml:"state"`
	Origin               string `xml:"origin"`
}

func ec2RouteToXML(r *repository.EC2Route) ec2RouteXML {
	return ec2RouteXML{
		DestinationCidrBlock: r.DestinationCidrBlock, GatewayId: r.GatewayID, NatGatewayId: r.NatGatewayID,
		InstanceId: r.InstanceID, NetworkInterfaceId: r.NetworkInterfaceID, State: r.State, Origin: r.Origin,
	}
}

// ec2RouteTableToXML is rt as DescribeRouteTables answers it, with its
// routes, associations and tags: the handler's encoder and the loader's
// render.
func ec2RouteTableToXML(rt *repository.EC2RouteTable, routes []*repository.EC2Route,
	assocs []*repository.EC2RouteTableAssociation, tags []ec2ResourceTagXML) ec2RouteTableXML {
	x := ec2RouteTableXML{RouteTableId: rt.ID, VpcId: rt.VPCID, OwnerId: rt.OwnerID, TagSet: tags}
	for _, r := range routes {
		x.Routes = append(x.Routes, ec2RouteToXML(r))
	}
	for _, a := range assocs {
		x.Associations = append(x.Associations, ec2AssociationToXML(a))
	}
	return x
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
		ID: id, VPCID: vpcID, Region: region, OwnerID: account,
		ARN:       awsproto.BuildEC2RouteTableARN(region, account, id),
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
		&ec2CreateRouteTableResult{RouteTable: ec2RouteTableXML{RouteTableId: rt.ID, VpcId: rt.VPCID, OwnerId: account}})
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
// the ones the provider's lookups by VPC, by association id and
// data.aws_route_table send. CreateVpc makes no main route table, so
// only a loaded one answers association.main=true.
var rtFilterValues = map[string]func(rt ec2RouteTableXML) []string{
	"route-table-id": func(rt ec2RouteTableXML) []string { return []string{rt.RouteTableId} },
	"vpc-id":         func(rt ec2RouteTableXML) []string { return []string{rt.VpcId} },
	"association.subnet-id": func(rt ec2RouteTableXML) []string {
		var ids []string
		for _, a := range rt.Associations {
			ids = append(ids, a.SubnetId)
		}
		return ids
	},
	"association.route-table-association-id": func(rt ec2RouteTableXML) []string {
		var ids []string
		for _, a := range rt.Associations {
			ids = append(ids, a.AssociationId)
		}
		return ids
	},
	"association.main": func(rt ec2RouteTableXML) []string {
		var mains []string
		for _, a := range rt.Associations {
			mains = append(mains, strconv.FormatBool(a.Main))
		}
		return mains
	},
}

var rtFilters = ec2FilterTable[ec2RouteTableXML]{
	values: rtFilterValues,
	tagID:  func(rt ec2RouteTableXML) string { return rt.RouteTableId },
}

func (app *Application) ec2DescribeRouteTables(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	filters, ok := rtFilters.read(w, req, "RouteTableId.N")
	if !ok {
		return
	}
	wanted := queryIDs(req.Params, "RouteTableId.")
	// Pre-load all routes once and key by route_table_id so the
	// per-RT lookup below is O(1). ListRoutes returns the union for
	// the account; we filter by RT id at populate time.
	allRoutes, err := app.repo.ListRoutes(account)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	routesByRT := make(map[string][]*repository.EC2Route, len(allRoutes))
	for _, rt := range allRoutes {
		routesByRT[rt.RouteTableID] = append(routesByRT[rt.RouteTableID], rt)
	}
	// Same trick for associations — populate <associationSet> so the
	// CreateAssociation wait-loop terminates.
	allAssocs, err := app.repo.ListRouteTableAssociations(account)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	assocsByRT := make(map[string][]*repository.EC2RouteTableAssociation, len(allAssocs))
	for _, a := range allAssocs {
		assocsByRT[a.RouteTableID] = append(assocsByRT[a.RouteTableID], a)
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
			out.RouteTableSet = append(out.RouteTableSet, ec2RouteTableToXML(rt, routesByRT[rt.ID], assocsByRT[rt.ID], tags[rt.ID]))
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
			out.RouteTableSet = append(out.RouteTableSet, ec2RouteTableToXML(rt, routesByRT[rt.ID], assocsByRT[rt.ID], tags[rt.ID]))
		}
	}
	out.RouteTableSet = slices.DeleteFunc(out.RouteTableSet, func(rt ec2RouteTableXML) bool {
		return !rtFilters.matches(rt, filters, tags)
	})
	awsproto.WriteEC2QueryRPCResponse(w, "DescribeRouteTables", &out)
}

// ec2DeleteRouteTable refuses a VPC's main route table with 400
// DependencyViolation, and the table and its main association stay.
//
// UNVERIFIED(aws-code): DependencyViolation from https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html; no recording
func (app *Application) ec2DeleteRouteTable(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	id := req.Params.Get("RouteTableId")
	err := app.repo.DeleteRouteTable(account, region, id)
	if errors.Is(err, repository.ErrMainRouteTable) {
		awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest, "DependencyViolation",
			fmt.Sprintf("The routeTable '%s' has dependencies and cannot be deleted.", id))
		return
	}
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DeleteRouteTable", nil)
}

func (app *Application) ec2AssociateRouteTable(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	rtID := req.Params.Get("RouteTableId")
	subnetID := req.Params.Get("SubnetId")
	if rtID == "" || subnetID == "" {
		ec2Refuse(w, req.Action, "no RouteTableId or SubnetId") // AWS also takes GatewayId
		return
	}
	assoc := &repository.EC2RouteTableAssociation{
		ID: "rtbassoc-" + ec2RandID(), RouteTableID: rtID, SubnetID: subnetID, State: "associated",
	}
	if err := app.repo.AssociateRouteTable(account, region, assoc); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "AssociateRouteTable",
		&ec2AssociateRouteTableResult{AssociationId: assoc.ID})
}

// ec2DisassociateRouteTable refuses a main association with 400
// InvalidParameterValue and keeps it: AWS moves a VPC's main
// association (ReplaceRouteTableAssociation), never drops it.
//
// UNVERIFIED(aws-code): InvalidParameterValue from https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html; no recording
func (app *Application) ec2DisassociateRouteTable(w http.ResponseWriter, account string, req awsproto.QueryRPCRequest) {
	id := req.Params.Get("AssociationId")
	err := app.repo.DisassociateRouteTable(account, id)
	if errors.Is(err, repository.ErrMainAssociation) {
		awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest, "InvalidParameterValue",
			fmt.Sprintf("cannot disassociate the main route table association %s", id))
		return
	}
	if err != nil {
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
		Origin:               "CreateRoute",
		State:                "active",
	}
	if rt.RouteTableID == "" || rt.DestinationCidrBlock == "" {
		ec2Refuse(w, req.Action, "no RouteTableId or DestinationCidrBlock") // AWS also takes DestinationIpv6CidrBlock or DestinationPrefixListId
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
	AllocationId            string              `xml:"allocationId"`
	PublicIp                string              `xml:"publicIp"`
	Domain                  string              `xml:"domain"`
	AssociationId           string              `xml:"associationId,omitempty"`
	InstanceId              string              `xml:"instanceId,omitempty"`
	NetworkInterfaceId      string              `xml:"networkInterfaceId,omitempty"`
	NetworkInterfaceOwnerId string              `xml:"networkInterfaceOwnerId,omitempty"`
	PrivateIpAddress        string              `xml:"privateIpAddress,omitempty"`
	PublicIpv4Pool          string              `xml:"publicIpv4Pool,omitempty"`
	NetworkBorderGroup      string              `xml:"networkBorderGroup,omitempty"`
	TagSet                  []ec2ResourceTagXML `xml:"tagSet>item,omitempty"`
}

// ec2AddressToXML renders eip with its tags. The network interface it
// is associated with is account's: fakeaws holds no other account's.
func ec2AddressToXML(account string, eip *repository.EC2EIP, tags []ec2ResourceTagXML) ec2AddressXML {
	x := ec2AddressXML{
		AllocationId: eip.AllocationID, PublicIp: eip.PublicIP, Domain: eip.Domain,
		AssociationId: eip.AssociationID, InstanceId: eip.InstanceID,
		NetworkInterfaceId: eip.NetworkInterfaceID, PrivateIpAddress: eip.PrivateIP,
		PublicIpv4Pool: eip.PublicIPv4Pool, NetworkBorderGroup: eip.NetworkBorderGroup,
		TagSet: tags,
	}
	if eip.NetworkInterfaceID != "" {
		x.NetworkInterfaceOwnerId = account
	}
	return x
}

type ec2AllocateAddressResult struct {
	AllocationId string `xml:"allocationId"`
	PublicIp     string `xml:"publicIp"`
	Domain       string `xml:"domain"`
}

type ec2DescribeAddressesResult struct {
	AddressSet []ec2AddressXML `xml:"addressesSet>item"`
}

// ec2EIPNet and ec2AutoIPNet are the /24s Elastic IPs and the public
// IPs a launch auto-assigns are drawn from: RFC 5737 test nets
// (TEST-NET-3 and TEST-NET-1), per concepts.md "Standing patterns" item
// 8, never a real routable IP. They are apart, so an auto-assigned IP
// is never an address's.
const (
	ec2EIPNet    = "203.0.113."
	ec2AutoIPNet = "192.0.2."
)

// ec2DerivePublicIP synthesises a deterministic-looking public IP in
// net from id (an allocation id or an ENI id). Two ids can derive one
// IP; repository.CreateEIP and claimPublicIP step past an IP already
// held in the region.
func ec2DerivePublicIP(net, id string) string {
	sum := 0
	for _, b := range []byte(id) {
		sum = (sum*31 + int(b)) & 0xff
	}
	return net + strconv.Itoa(sum)
}

func (app *Application) ec2AllocateAddress(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	domain := req.Params.Get("Domain")
	if domain == "" {
		domain = "vpc"
	}
	if domain != "vpc" {
		// classic EIPs are out of scope at v1 per PLAN.md S44.
		ec2Refuse(w, req.Action, "Domain="+domain)
		return
	}
	specs, refused := refuseTagSpecifications(w, req.Params, "elastic-ip")
	if refused {
		return
	}
	allocID := "eipalloc-" + ec2RandID()
	eip := &repository.EC2EIP{
		AllocationID: allocID, Domain: domain,
		PublicIP:  ec2DerivePublicIP(ec2EIPNet, allocID),
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
	ids := queryIDs(req.Params, "AllocationId.")
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

// addressFilters are the DescribeAddresses filters fakeaws models.
var addressFilters = ec2FilterTable[*repository.EC2EIP]{
	values: map[string]func(*repository.EC2EIP) []string{
		"association-id":       func(e *repository.EC2EIP) []string { return []string{e.AssociationID} },
		"allocation-id":        func(e *repository.EC2EIP) []string { return []string{e.AllocationID} },
		"domain":               func(e *repository.EC2EIP) []string { return []string{e.Domain} },
		"public-ip":            func(e *repository.EC2EIP) []string { return []string{e.PublicIP} },
		"instance-id":          func(e *repository.EC2EIP) []string { return []string{e.InstanceID} },
		"network-interface-id": func(e *repository.EC2EIP) []string { return []string{e.NetworkInterfaceID} },
		"private-ip-address":   func(e *repository.EC2EIP) []string { return []string{e.PrivateIP} },
	},
	tagID: func(e *repository.EC2EIP) string { return e.AllocationID },
}

// ec2DescribeAddresses answers the AllocationId.N lookup the provider
// makes, PublicIp.N, its association-id filter after AssociateAddress
// and, with none of them, the scope sweep's list of every address.
func (app *Application) ec2DescribeAddresses(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	filters, ok := addressFilters.read(w, req, "AllocationId.N", "PublicIp.N")
	if !ok {
		return
	}
	eips, ok := app.ec2FindAddresses(w, account, region, req)
	if !ok {
		return
	}
	ips := queryListValues(req.Params, "PublicIp.")
	for _, ip := range ips {
		if !slices.ContainsFunc(eips, func(e *repository.EC2EIP) bool { return e.PublicIP == ip }) {
			// UNVERIFIED(aws-code): InvalidAddress.NotFound from https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html; no recording
			awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest,
				"InvalidAddress.NotFound", fmt.Sprintf("Address '%s' not found.", ip))
			return
		}
	}
	if len(ips) > 0 {
		eips = slices.DeleteFunc(eips, func(e *repository.EC2EIP) bool { return !slices.Contains(ips, e.PublicIP) })
	}
	tags, ok := app.tagSets(w, account)
	if !ok {
		return
	}
	out := ec2DescribeAddressesResult{AddressSet: []ec2AddressXML{}}
	for _, eip := range eips {
		if !addressFilters.matches(eip, filters, tags) {
			continue
		}
		out.AddressSet = append(out.AddressSet, ec2AddressToXML(account, eip, tags[eip.AllocationID]))
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
		ec2Refuse(w, req.Action, "AllowReassociation")
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
	if _, err := app.repo.GetInstance(account, region, instanceID); err != nil {
		writeInstanceError(w, instanceID, err)
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
// and an ENI whose launch auto-assigned a public IP gets one again,
// derived as at launch and held by no other ENI in the region. An
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
		eni.PublicIP = ec2DerivePublicIP(ec2AutoIPNet, eni.ID)
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
// and every source may carry a .Description. Each source is stored as
// one ec2_security_group_rules row, AWS's security group rule, with its
// permission's protocol and ports; the xml tags are the
// DescribeSecurityGroups element names.
//
// CRITICAL[ec2-sg-rule-source-descriptions-round-trip]: every source
// (IpRanges, Ipv6Ranges, Groups, PrefixListIds) MUST come back from
// DescribeSecurityGroups on its own item with its own Description.
// terraform-provider-aws's securityGroupIPPermGather groups remote
// sources into rules keyed by (protocol, ports, description); a
// dropped source or description reads back as a different rule and
// `plan` shows a diff that never converges.

type ec2IpRange struct {
	CidrIp      string `xml:"cidrIp"`
	Description string `xml:"description,omitempty"`
}

type ec2Ipv6Range struct {
	CidrIpv6    string `xml:"cidrIpv6"`
	Description string `xml:"description,omitempty"`
}

type ec2UserIdGroupPair struct {
	GroupId     string `xml:"groupId"`
	UserId      string `xml:"userId,omitempty"`
	Description string `xml:"description,omitempty"`
}

type ec2PrefixListId struct {
	PrefixListId string `xml:"prefixListId"`
	Description  string `xml:"description,omitempty"`
}

type ec2IpPermission struct {
	IpProtocol string `xml:"ipProtocol"`
	FromPort   int    `xml:"fromPort"`
	ToPort     int    `xml:"toPort"`
	ec2PermissionSources
}

// MarshalXML answers an all-traffic permission (ip protocol -1) with no
// fromPort or toPort, as AWS does (testdata/ec2/DescribeSecurityGroups.xml),
// whatever ports it was stored with. terraform-provider-aws reads an
// absent port as 0, the port its aws_security_group sends for -1.
func (p ec2IpPermission) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	type plain ec2IpPermission // without this method
	if p.IpProtocol != ec2AllProtocols {
		return e.EncodeElement(plain(p), start)
	}
	return e.EncodeElement(struct {
		IpProtocol string `xml:"ipProtocol"`
		ec2PermissionSources
	}{p.IpProtocol, p.ec2PermissionSources}, start)
}

// ec2PermissionSources are a permission's sources, each kind's list.
type ec2PermissionSources struct {
	IpRanges         []ec2IpRange         `xml:"ipRanges>item,omitempty"`
	Ipv6Ranges       []ec2Ipv6Range       `xml:"ipv6Ranges>item,omitempty"`
	UserIdGroupPairs []ec2UserIdGroupPair `xml:"groups>item,omitempty"`
	PrefixListIds    []ec2PrefixListId    `xml:"prefixListIds>item,omitempty"`
}

// ec2RuleSource is one source inside a permission. onRule is rule
// with this source; state is the snake_case /mock/state rendering.
type ec2RuleSource interface {
	onRule(rule repository.EC2SecurityGroupRule) repository.EC2SecurityGroupRule
	state() map[string]any
}

func (r ec2IpRange) onRule(rule repository.EC2SecurityGroupRule) repository.EC2SecurityGroupRule {
	rule.CidrIPv4, rule.Description = r.CidrIp, r.Description
	return rule
}
func (r ec2IpRange) state() map[string]any {
	return map[string]any{"cidr_ip": r.CidrIp, "description": r.Description}
}

func (r ec2Ipv6Range) onRule(rule repository.EC2SecurityGroupRule) repository.EC2SecurityGroupRule {
	rule.CidrIPv6, rule.Description = r.CidrIpv6, r.Description
	return rule
}
func (r ec2Ipv6Range) state() map[string]any {
	return map[string]any{"cidr_ipv6": r.CidrIpv6, "description": r.Description}
}

func (g ec2UserIdGroupPair) onRule(rule repository.EC2SecurityGroupRule) repository.EC2SecurityGroupRule {
	rule.ReferencedGroupID, rule.ReferencedUserID, rule.Description = g.GroupId, g.UserId, g.Description
	return rule
}
func (g ec2UserIdGroupPair) state() map[string]any {
	return map[string]any{"group_id": g.GroupId, "user_id": g.UserId, "description": g.Description}
}

func (p ec2PrefixListId) onRule(rule repository.EC2SecurityGroupRule) repository.EC2SecurityGroupRule {
	rule.PrefixListID, rule.Description = p.PrefixListId, p.Description
	return rule
}
func (p ec2PrefixListId) state() map[string]any {
	return map[string]any{"prefix_list_id": p.PrefixListId, "description": p.Description}
}

// sgRules is perms as rules of one direction, a rule per source, each
// permission's sources in DescribeSecurityGroups' order.
func sgRules(perms []ec2IpPermission, egress bool) []repository.EC2SecurityGroupRule {
	var out []repository.EC2SecurityGroupRule
	for _, p := range perms {
		base := repository.EC2SecurityGroupRule{IsEgress: egress, IPProtocol: p.IpProtocol, FromPort: p.FromPort, ToPort: p.ToPort}
		out = appendRules(out, base, p.IpRanges)
		out = appendRules(out, base, p.Ipv6Ranges)
		out = appendRules(out, base, p.UserIdGroupPairs)
		out = appendRules(out, base, p.PrefixListIds)
	}
	return out
}

func appendRules[T ec2RuleSource](out []repository.EC2SecurityGroupRule, base repository.EC2SecurityGroupRule, srcs []T) []repository.EC2SecurityGroupRule {
	for _, s := range srcs {
		out = append(out, s.onRule(base))
	}
	return out
}

// sgPermissions gathers rules, in ListSecurityGroupRules' order, into
// each direction's permissions: one per perm_ord, each source on its
// kind's list in src_ord order.
func sgPermissions(rules []repository.EC2SecurityGroupRule) (ingress, egress []ec2IpPermission) {
	for i, r := range rules {
		perms := &ingress
		if r.IsEgress {
			perms = &egress
		}
		if i == 0 || rules[i-1].IsEgress != r.IsEgress || rules[i-1].PermOrd != r.PermOrd {
			*perms = append(*perms, ec2IpPermission{IpProtocol: r.IPProtocol, FromPort: r.FromPort, ToPort: r.ToPort})
		}
		p := &(*perms)[len(*perms)-1]
		switch {
		case r.CidrIPv4 != "":
			p.IpRanges = append(p.IpRanges, ec2IpRange{CidrIp: r.CidrIPv4, Description: r.Description})
		case r.CidrIPv6 != "":
			p.Ipv6Ranges = append(p.Ipv6Ranges, ec2Ipv6Range{CidrIpv6: r.CidrIPv6, Description: r.Description})
		case r.PrefixListID != "":
			p.PrefixListIds = append(p.PrefixListIds, ec2PrefixListId{PrefixListId: r.PrefixListID, Description: r.Description})
		default:
			p.UserIdGroupPairs = append(p.UserIdGroupPairs, ec2UserIdGroupPair{GroupId: r.ReferencedGroupID, UserId: r.ReferencedUserID, Description: r.Description})
		}
	}
	return ingress, egress
}

// ec2SecurityGroupToXML is sg as a securityGroupInfo item with tags;
// its caller adds its permissions (sgPermissions). It answers
// securityGroupArn when sg has one: a created group's, or a loaded
// group's recorded one.
func ec2SecurityGroupToXML(sg *repository.EC2SecurityGroup, tags []ec2ResourceTagXML) ec2SecurityGroupXML {
	return ec2SecurityGroupXML{
		GroupId: sg.ID, GroupName: sg.GroupName, GroupDesc: sg.Description, VpcId: sg.VPCID,
		OwnerId: sg.OwnerID, SecurityGroupArn: sg.ARN, TagSet: tags,
	}
}

type ec2SecurityGroupXML struct {
	GroupId          string              `xml:"groupId"`
	GroupName        string              `xml:"groupName"`
	GroupDesc        string              `xml:"groupDescription"`
	VpcId            string              `xml:"vpcId"`
	OwnerId          string              `xml:"ownerId"`
	SecurityGroupArn string              `xml:"securityGroupArn,omitempty"`
	IpPermissions    []ec2IpPermission   `xml:"ipPermissions>item,omitempty"`
	IpPermsEgress    []ec2IpPermission   `xml:"ipPermissionsEgress>item,omitempty"`
	TagSet           []ec2ResourceTagXML `xml:"tagSet>item,omitempty"`
}

type ec2CreateSecurityGroupResult struct {
	GroupId string `xml:"groupId"`
}

type ec2DescribeSecurityGroupsResult struct {
	SecurityGroupSet []ec2SecurityGroupXML `xml:"securityGroupInfo>item"`
}

// ec2AuthorizeSecurityGroupRulesResult is an Authorize* answer that
// added rules, in testdata/ec2/AuthorizeSecurityGroupIngress.xml's shape.
type ec2AuthorizeSecurityGroupRulesResult struct {
	Return bool                      `xml:"return"`
	Rules  []ec2SecurityGroupRuleXML `xml:"securityGroupRuleSet>item"`
}

// ec2SecurityGroupRuleXML is a SecurityGroupRule.
type ec2SecurityGroupRuleXML struct {
	SecurityGroupRuleId string                  `xml:"securityGroupRuleId"`
	GroupId             string                  `xml:"groupId"`
	GroupOwnerId        string                  `xml:"groupOwnerId"`
	IsEgress            bool                    `xml:"isEgress"`
	IpProtocol          string                  `xml:"ipProtocol"`
	FromPort            int                     `xml:"fromPort"`
	ToPort              int                     `xml:"toPort"`
	CidrIpv4            string                  `xml:"cidrIpv4,omitempty"`
	CidrIpv6            string                  `xml:"cidrIpv6,omitempty"`
	PrefixListId        string                  `xml:"prefixListId,omitempty"`
	ReferencedGroupInfo *ec2UserIdGroupPairInfo `xml:"referencedGroupInfo,omitempty"`
	Description         string                  `xml:"description,omitempty"`
	TagSet              []ec2ResourceTagXML     `xml:"tagSet>item,omitempty"`
}

// ec2AllProtocols is the ip protocol of an all-traffic rule.
const ec2AllProtocols = "-1"

// ec2PortProtocols are the protocols, by name and number, whose rules
// carry ports, each with the check of its ports; every other protocol
// takes all ports.
var ec2PortProtocols = map[string]func(ec2IpPermission) string{
	"tcp": tcpUDPPortProblem, "udp": tcpUDPPortProblem, "6": tcpUDPPortProblem, "17": tcpUDPPortProblem,
	"icmp": icmpProblem, "icmpv6": icmpProblem, "1": icmpProblem, "58": icmpProblem,
}

// ec2UserIdGroupPairInfo is a rule's referencedGroupInfo.
type ec2UserIdGroupPairInfo struct {
	GroupId string `xml:"groupId"`
	UserId  string `xml:"userId,omitempty"`
}

// ec2SecurityGroupRuleToXML is r as a SecurityGroupRule item. An
// all-traffic rule (ip protocol -1) answers fromPort and toPort -1 as
// AWS does (testdata/ec2/DescribeSecurityGroupRules.xml), whatever ports
// it was stored with: the provider's aws_vpc_security_group_*_rule read
// keeps a null port only when it reads -1. Every other rule answers its
// stored ports: the legacy aws_security_group_rule sends ports for any
// protocol but -1 (protocol 50 with 0/0) and matches its rule on them.
// DescribeSecurityGroups' ipPermissions answer the stored ports, but
// none for -1 (ec2IpPermission.MarshalXML).
func ec2SecurityGroupRuleToXML(r repository.EC2SecurityGroupRule) ec2SecurityGroupRuleXML {
	if r.IPProtocol == ec2AllProtocols {
		r.FromPort, r.ToPort = -1, -1
	}
	x := ec2SecurityGroupRuleXML{
		SecurityGroupRuleId: r.ID, GroupId: r.GroupID, GroupOwnerId: r.GroupOwnerID, IsEgress: r.IsEgress,
		IpProtocol: r.IPProtocol, FromPort: r.FromPort, ToPort: r.ToPort,
		CidrIpv4: r.CidrIPv4, CidrIpv6: r.CidrIPv6, PrefixListId: r.PrefixListID, Description: r.Description,
	}
	if r.ReferencedGroupID != "" {
		x.ReferencedGroupInfo = &ec2UserIdGroupPairInfo{GroupId: r.ReferencedGroupID, UserId: r.ReferencedUserID}
	}
	return x
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
	slices.SortFunc(ns, ec2IndexOrder)
	items := make([]string, len(ns))
	for i, n := range ns {
		items[i] = prefix + n + "."
	}
	return items
}

// readIpPermissions parses req's IpPermissions.N and, when they name no
// source, refuses through ec2Refuse and reports false: none sent (AWS
// also takes the legacy top-level IpProtocol, CidrIp, ...), a source
// item without its key (e.g. a Groups.N GroupName, which AWS resolves in
// the default VPC), or a permission with none, which AWS refuses.
func readIpPermissions(w http.ResponseWriter, req awsproto.QueryRPCRequest) ([]ec2IpPermission, bool) {
	perms, keyless := parseIpPermissions(req)
	switch {
	case len(perms) == 0:
		ec2Refuse(w, req.Action, "no IpPermissions.N")
	case len(keyless) > 0:
		ec2Refuse(w, req.Action, keyless...)
	case slices.ContainsFunc(perms, func(p ec2IpPermission) bool {
		return len(p.IpRanges)+len(p.Ipv6Ranges)+len(p.UserIdGroupPairs)+len(p.PrefixListIds) == 0
	}):
		ec2Refuse(w, req.Action, "IpPermissions.N with no source")
	default:
		return perms, true
	}
	return nil, false
}

// hasParamUnder reports whether p holds a param named under prefix.
func hasParamUnder(p url.Values, prefix string) bool {
	for k := range p {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

// parseIpPermissions reads the flattened IpPermissions.<n>.* params
// out of the Query-RPC body. keyless names each field of a source item
// that lacks its key, which is no source (parseIpPermission).
func parseIpPermissions(req awsproto.QueryRPCRequest) (perms []ec2IpPermission, keyless []string) {
	for _, base := range queryListItems(req.Params, "IpPermissions.") {
		perm, k := parseIpPermission(req.Params, base)
		perms, keyless = append(perms, perm), append(keyless, k...)
	}
	return perms, keyless
}

// parseIpPermission reads the permission at base. A source item without
// its key (a Groups.N with a GroupName or UserId but no GroupId) is no
// source; its fields come back in keyless.
func parseIpPermission(p url.Values, base string) (perm ec2IpPermission, keyless []string) {
	perm = ec2IpPermission{IpProtocol: p.Get(base + "IpProtocol")}
	perm.FromPort, _ = strconv.Atoi(p.Get(base + "FromPort"))
	perm.ToPort, _ = strconv.Atoi(p.Get(base + "ToPort"))
	for _, it := range keyedItems(p, base+"IpRanges.", "CidrIp", &keyless) {
		perm.IpRanges = append(perm.IpRanges, ec2IpRange{CidrIp: p.Get(it + "CidrIp"), Description: p.Get(it + "Description")})
	}
	for _, it := range keyedItems(p, base+"Ipv6Ranges.", "CidrIpv6", &keyless) {
		perm.Ipv6Ranges = append(perm.Ipv6Ranges, ec2Ipv6Range{CidrIpv6: p.Get(it + "CidrIpv6"), Description: p.Get(it + "Description")})
	}
	for _, it := range keyedItems(p, base+"Groups.", "GroupId", &keyless) {
		perm.UserIdGroupPairs = append(perm.UserIdGroupPairs, ec2UserIdGroupPair{
			GroupId: p.Get(it + "GroupId"), UserId: p.Get(it + "UserId"), Description: p.Get(it + "Description"),
		})
	}
	for _, it := range keyedItems(p, base+"PrefixListIds.", "PrefixListId", &keyless) {
		perm.PrefixListIds = append(perm.PrefixListIds, ec2PrefixListId{PrefixListId: p.Get(it + "PrefixListId"), Description: p.Get(it + "Description")})
	}
	return perm, keyless
}

// keyedItems returns the items of list that hold key, and adds to
// keyless each param of an item that does not, by its ec2ParamName
// (IpPermissions.N.Groups.N.GroupName).
func keyedItems(p url.Values, list, key string, keyless *[]string) []string {
	var out []string
	for _, it := range queryListItems(p, list) {
		if p.Get(it+key) != "" {
			out = append(out, it)
			continue
		}
		for k := range p {
			if strings.HasPrefix(k, it) {
				*keyless = append(*keyless, ec2ParamName(k))
			}
		}
	}
	return out
}

func (app *Application) ec2CreateSecurityGroup(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	groupName := req.Params.Get("GroupName")
	desc := req.Params.Get("GroupDescription")
	vpcID := req.Params.Get("VpcId")
	if groupName == "" || desc == "" || vpcID == "" {
		ec2Refuse(w, req.Action, "no GroupName, GroupDescription or VpcId") // AWS puts a group without VpcId in the default VPC
		return
	}
	if groupName == repository.DefaultGroupName {
		awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest, "InvalidGroup.Reserved",
			fmt.Sprintf("The name '%s' is reserved, and cannot be used to create a new security group.", repository.DefaultGroupName))
		return
	}
	specs, refused := refuseTagSpecifications(w, req.Params, "security-group")
	if refused {
		return
	}
	sg := newEC2SecurityGroup(account, region, vpcID, groupName, desc)
	err := app.repo.CreateSecurityGroup(account, sg)
	if err == nil {
		err = app.tagNew(account, region, onResource(specs["security-group"], sg.ID, "security-group"),
			func() error { return app.repo.DeleteSecurityGroup(account, region, sg.ID) })
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
	ids := queryIDs(req.Params, "GroupId.")
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

// sgFilters are the DescribeSecurityGroups filters fakeaws models: the
// AWS names whose value a group answers and the tag filters. The
// ip-permission.* and egress.ip-permission.* names stay refused.
var sgFilters = ec2FilterTable[ec2SecurityGroupXML]{
	values: map[string]func(ec2SecurityGroupXML) []string{
		"group-id":    func(g ec2SecurityGroupXML) []string { return []string{g.GroupId} },
		"group-name":  func(g ec2SecurityGroupXML) []string { return []string{g.GroupName} },
		"vpc-id":      func(g ec2SecurityGroupXML) []string { return []string{g.VpcId} },
		"description": func(g ec2SecurityGroupXML) []string { return []string{g.GroupDesc} },
		"owner-id":    func(g ec2SecurityGroupXML) []string { return []string{g.OwnerId} },
	},
	tagID: func(g ec2SecurityGroupXML) string { return g.GroupId },
}

// ec2DescribeSecurityGroups answers the provider's GroupId.N lookup
// and, with none, the scope sweep's list of every group, each through
// sgFilters.
//
// MUST[ec2-sg-group-name-default-vpc-only]: AWS resolves GroupName.N
// only in the default VPC. fakeaws never creates one (CreateSecurityGroup
// requires VpcId), so on an unloaded database the rows prove there is
// none and every GroupName.N answers 400 VPCIdNotSpecified, never a
// group. A loaded database's account usually has a default VPC its
// rows cannot show, so there GroupName.N is refused through ec2Refuse.
// The loaded flag is read only for a request with GroupName.N; an
// unreadable flag answers 500, neither.
// UNVERIFIED(aws-code): VPCIdNotSpecified from https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html; no recording
func (app *Application) ec2DescribeSecurityGroups(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	reads := []string{"GroupId.N"}
	groupNames := len(queryListValues(req.Params, "GroupName.")) > 0
	if groupNames {
		loaded, err := app.repo.Loaded()
		if err != nil {
			awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
			return
		}
		if !loaded {
			reads = append(reads, "GroupName.N")
		}
	}
	filters, ok := sgFilters.read(w, req, reads...)
	if !ok {
		return
	}
	if groupNames {
		awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest, "VPCIdNotSpecified",
			"You have no default VPC in which to carry out the request. Specify a VPC ID or create a default VPC.")
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
		if sg.OwnerID == "" {
			sg.OwnerID = account // a row stored before groups kept their owner
		}
		x := ec2SecurityGroupToXML(sg, tags[sg.ID])
		if !sgFilters.matches(x, filters, tags) {
			continue
		}
		rules, err := app.repo.ListSecurityGroupRules(account, region, sg.ID)
		if err != nil {
			awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
			return
		}
		x.IpPermissions, x.IpPermsEgress = sgPermissions(rules)
		out.SecurityGroupSet = append(out.SecurityGroupSet, x)
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DescribeSecurityGroups", &out)
}

func (app *Application) ec2DeleteSecurityGroup(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	id := req.Params.Get("GroupId")
	if id == "" {
		// AWS also accepts GroupName for non-VPC SGs; v1 supports GroupId only.
		ec2Refuse(w, req.Action, "no GroupId")
		return
	}
	sg, err := app.repo.GetSecurityGroup(account, region, id)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	if sg.GroupName == repository.DefaultGroupName {
		awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest, "CannotDelete",
			fmt.Sprintf("the specified group: %q name: %q cannot be deleted by a user", id, repository.DefaultGroupName))
		return
	}
	err = app.repo.DeleteSecurityGroup(account, region, id)
	if errors.Is(err, repository.ErrGroupHeld) {
		// EC2's code, which aws_security_group's delete retries until its
		// timeout; it fails at once on any other.
		// UNVERIFIED(aws-code): DependencyViolation from https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html; no recording
		awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest, "DependencyViolation",
			fmt.Sprintf("resource %s has a dependent object", id))
		return
	}
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DeleteSecurityGroup", nil)
}

// ec2AuthorizeSecurityGroupRules adds a rule per source of the parsed
// IpPermissions that the group lacks (AuthorizeSecurityGroupRules) and
// answers them in securityGroupRuleSet. A source the group holds adds
// none, where AWS answers InvalidPermission.Duplicate, so a request that
// adds nothing answers as it did before rules had ids: requestId alone.
func (app *Application) ec2AuthorizeSecurityGroupRules(w http.ResponseWriter, account, region, direction string, req awsproto.QueryRPCRequest) {
	sgID := req.Params.Get("GroupId")
	if sgID == "" {
		ec2Refuse(w, req.Action, "no GroupId") // AWS also takes GroupName for ingress
		return
	}
	// AWS tags the new rules; fakeaws tags no rule on create.
	if hasParamUnder(req.Params, "TagSpecification.") {
		ec2Refuse(w, req.Action, "TagSpecification.N")
		return
	}
	add, ok := readIpPermissions(w, req)
	if !ok || app.refuseIpPermissions(w, account, region, add) {
		return
	}
	rules := sgRules(add, direction == "egress")
	for i := range rules {
		rules[i].ID, rules[i].GroupOwnerID = "sgr-"+ec2RandID(), account
	}
	added, err := app.repo.AuthorizeSecurityGroupRules(account, region, sgID, rules)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	if len(added) == 0 {
		awsproto.WriteEC2QueryRPCResponse(w, req.Action, nil)
		return
	}
	out := ec2AuthorizeSecurityGroupRulesResult{Return: true}
	for _, r := range added {
		out.Rules = append(out.Rules, ec2SecurityGroupRuleToXML(r))
	}
	awsproto.WriteEC2QueryRPCResponse(w, req.Action, &out)
}

// ec2RevokeSecurityGroupRules deletes the rule of each
// SecurityGroupRuleId.N (what the provider's
// aws_vpc_security_group_*_rule delete sends) and of each parsed source
// (RevokeSecurityGroupRules), all or none; a permission left with no
// source is gone. A rule id the group lacks in this direction, an
// empty one included, is 400 InvalidSecurityGroupRuleId.NotFound. A
// request with no rule id that names no source through
// readIpPermissions, or with rule ids and a param outside GroupId,
// SecurityGroupRuleId.N and IpPermissions.N, is refused rather than
// deleting nothing.
func (app *Application) ec2RevokeSecurityGroupRules(w http.ResponseWriter, account, region, direction string, req awsproto.QueryRPCRequest) {
	sgID := req.Params.Get("GroupId")
	if sgID == "" {
		ec2Refuse(w, req.Action, "no GroupId") // AWS also takes GroupName for ingress
		return
	}
	// Any SecurityGroupRuleId. key, one queryIDs does not read
	// (SecurityGroupRuleId.N itself) included, makes this a revoke by id.
	if hasParamUnder(req.Params, "SecurityGroupRuleId.") && refuseUnreadBesidePermissions(w, req) {
		return
	}
	ruleIDs := queryIDs(req.Params, "SecurityGroupRuleId.")
	// An empty id would revoke by source, matching nothing.
	if slices.Contains(ruleIDs, "") {
		writeRuleNotFound(w, repository.RuleNotFoundError{})
		return
	}
	egress := direction == "egress"
	var rm []repository.EC2SecurityGroupRule
	for _, id := range ruleIDs {
		rm = append(rm, repository.EC2SecurityGroupRule{ID: id, IsEgress: egress})
	}
	if len(ruleIDs) == 0 || hasParamUnder(req.Params, "IpPermissions.") {
		perms, ok := readIpPermissions(w, req)
		if !ok {
			return
		}
		rm = append(rm, sgRules(perms, egress)...)
	}
	err := app.repo.RevokeSecurityGroupRules(account, region, sgID, rm)
	if writeRuleNotFound(w, err) {
		return
	}
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, req.Action, nil)
}

// refuseUnreadBesidePermissions refuses req through ec2Refuse naming
// each param a revoke by rule id does not read: any but GroupId,
// SecurityGroupRuleId.N and those under IpPermissions., which
// readIpPermissions reads. It reports whether it refused.
func refuseUnreadBesidePermissions(w http.ResponseWriter, req awsproto.QueryRPCRequest) bool {
	var names []string
	for _, k := range unread(req.Params, []string{"GroupId", "SecurityGroupRuleId.N"}) {
		if !strings.HasPrefix(k, "IpPermissions.") {
			names = append(names, ec2ParamName(k))
		}
	}
	if len(names) == 0 {
		return false
	}
	ec2Refuse(w, req.Action, names...)
	return true
}

// writeRuleNotFound writes 400 InvalidSecurityGroupRuleId.NotFound when
// err is a repository.RuleNotFoundError, which the provider's
// findSecurityGroupRules reads as the rule gone, and reports whether it
// wrote.
// UNVERIFIED(aws-code): InvalidSecurityGroupRuleId.NotFound from https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html; no recording
func writeRuleNotFound(w http.ResponseWriter, err error) bool {
	var nf repository.RuleNotFoundError
	if !errors.As(err, &nf) {
		return false
	}
	awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest, "InvalidSecurityGroupRuleId.NotFound",
		fmt.Sprintf("The security group rule ID '%s' does not exist", nf.ID))
	return true
}

// ec2DescribeSecurityGroupRulesResult is a DescribeSecurityGroupRules
// answer, in testdata/ec2/DescribeSecurityGroupRules.xml's shape.
type ec2DescribeSecurityGroupRulesResult struct {
	Rules []ec2SecurityGroupRuleXML `xml:"securityGroupRuleSet>item"`
}

// sgRuleFilters are the DescribeSecurityGroupRules filters: every name
// the EC2 API reference lists, and tag-key and tag-value.
var sgRuleFilters = ec2FilterTable[ec2SecurityGroupRuleXML]{
	values: map[string]func(ec2SecurityGroupRuleXML) []string{
		"group-id":               func(r ec2SecurityGroupRuleXML) []string { return []string{r.GroupId} },
		"security-group-rule-id": func(r ec2SecurityGroupRuleXML) []string { return []string{r.SecurityGroupRuleId} },
	},
	tagID: func(r ec2SecurityGroupRuleXML) string { return r.SecurityGroupRuleId },
}

// ec2DescribeSecurityGroupRules answers each SecurityGroupRuleId.N or,
// with none, every rule in the region, each through sgRuleFilters, from
// the rule rows. An unknown id is 400 InvalidSecurityGroupRuleId.NotFound.
func (app *Application) ec2DescribeSecurityGroupRules(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	filters, ok := sgRuleFilters.read(w, req, "SecurityGroupRuleId.N")
	if !ok {
		return
	}
	rules, err := app.findSecurityGroupRules(account, region, queryIDs(req.Params, "SecurityGroupRuleId."))
	if writeRuleNotFound(w, err) {
		return
	}
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	tags, ok := app.tagSets(w, account)
	if !ok {
		return
	}
	var out ec2DescribeSecurityGroupRulesResult
	for _, r := range rules {
		x := ec2SecurityGroupRuleToXML(r)
		x.TagSet = tags[r.ID]
		if sgRuleFilters.matches(x, filters, tags) {
			out.Rules = append(out.Rules, x)
		}
	}
	awsproto.WriteEC2QueryRPCResponse(w, req.Action, &out)
}

// findSecurityGroupRules returns the rule of each of ids or, with none,
// every rule in the region.
func (app *Application) findSecurityGroupRules(account, region string, ids []string) ([]repository.EC2SecurityGroupRule, error) {
	if len(ids) == 0 {
		return app.repo.ListRegionSecurityGroupRules(account, region)
	}
	var out []repository.EC2SecurityGroupRule
	for _, id := range ids {
		r, err := app.repo.GetSecurityGroupRule(account, region, id)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
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
	if check := ec2PortProtocols[strings.ToLower(p.IpProtocol)]; check != nil {
		return check(p)
	}
	if p.IpProtocol == ec2AllProtocols {
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
	KeyName             string                   `xml:"keyName,omitempty"`
	LaunchTime          string                   `xml:"launchTime,omitempty"`
	SubnetId            string                   `xml:"subnetId,omitempty"`
	VpcId               string                   `xml:"vpcId,omitempty"`
	PrivateIpAddress    string                   `xml:"privateIpAddress,omitempty"`
	PrivateDnsName      string                   `xml:"privateDnsName,omitempty"`
	IpAddress           string                   `xml:"ipAddress,omitempty"`
	SourceDestCheck     *bool                    `xml:"sourceDestCheck,omitempty"`
	EbsOptimized        bool                     `xml:"ebsOptimized"`
	IamProfile          *ec2IamProfileXML        `xml:"iamInstanceProfile,omitempty"`
	InstanceState       ec2InstanceStateXML      `xml:"instanceState"`
	GroupSet            []ec2InstanceSGXML       `xml:"groupSet>item,omitempty"`
	NetworkInterfaceSet []ec2NetworkInterfaceXML `xml:"networkInterfaceSet>item,omitempty"`
	TagSet              []ec2ResourceTagXML      `xml:"tagSet>item,omitempty"`
	ec2InstanceRecordedXML
}

// ec2InstanceRecordedXML are the fields of a loaded instance that
// fakeaws holds as DescribeInstances recorded them
// (repository.EC2Instance.Recorded) and answers back; a launched
// instance has none. A scalar is its recorded text, so it reads back
// byte-exact and an absent one stays absent.
type ec2InstanceRecordedXML struct {
	DnsName                          string                      `xml:"dnsName,omitempty"`
	Placement                        *ec2InstancePlacementXML    `xml:"placement,omitempty"`
	Monitoring                       *ec2InstanceMonitoringXML   `xml:"monitoring,omitempty"`
	Architecture                     string                      `xml:"architecture,omitempty"`
	RootDeviceType                   string                      `xml:"rootDeviceType,omitempty"`
	RootDeviceName                   string                      `xml:"rootDeviceName,omitempty"`
	BlockDeviceMapping               []ec2InstanceBlockDeviceXML `xml:"blockDeviceMapping>item,omitempty"`
	VirtualizationType               string                      `xml:"virtualizationType,omitempty"`
	ClientToken                      string                      `xml:"clientToken,omitempty"`
	Hypervisor                       string                      `xml:"hypervisor,omitempty"`
	CpuOptions                       *ec2InstanceCPUOptionsXML   `xml:"cpuOptions,omitempty"`
	CapacityReservationSpecification *ec2InstanceCapacityXML     `xml:"capacityReservationSpecification,omitempty"`
	HibernationOptions               *ec2InstanceHibernationXML  `xml:"hibernationOptions,omitempty"`
	EnclaveOptions                   *ec2InstanceEnclaveXML      `xml:"enclaveOptions,omitempty"`
	MetadataOptions                  *ec2InstanceMetadataXML     `xml:"metadataOptions,omitempty"`
	MaintenanceOptions               *ec2InstanceMaintenanceXML  `xml:"maintenanceOptions,omitempty"`
	PrivateDnsNameOptions            *ec2InstancePrivateDNSXML   `xml:"privateDnsNameOptions,omitempty"`
	PlatformDetails                  string                      `xml:"platformDetails,omitempty"`
	UsageOperation                   string                      `xml:"usageOperation,omitempty"`
	BootMode                         string                      `xml:"bootMode,omitempty"`
}

type ec2InstancePlacementXML struct {
	AvailabilityZone     string `xml:"availabilityZone,omitempty"`
	GroupName            string `xml:"groupName,omitempty"`
	Tenancy              string `xml:"tenancy,omitempty"`
	HostId               string `xml:"hostId,omitempty"`
	HostResourceGroupArn string `xml:"hostResourceGroupArn,omitempty"`
	PartitionNumber      string `xml:"partitionNumber,omitempty"`
}

type ec2InstanceMonitoringXML struct {
	State string `xml:"state,omitempty"`
}

type ec2InstanceBlockDeviceXML struct {
	DeviceName string `xml:"deviceName,omitempty"`
	Ebs        *struct {
		VolumeId            string `xml:"volumeId,omitempty"`
		Status              string `xml:"status,omitempty"`
		AttachTime          string `xml:"attachTime,omitempty"`
		DeleteOnTermination string `xml:"deleteOnTermination,omitempty"`
	} `xml:"ebs,omitempty"`
}

type ec2InstanceCPUOptionsXML struct {
	CoreCount      string `xml:"coreCount,omitempty"`
	ThreadsPerCore string `xml:"threadsPerCore,omitempty"`
	AmdSevSnp      string `xml:"amdSevSnp,omitempty"`
}

type ec2InstanceCapacityXML struct {
	CapacityReservationPreference string `xml:"capacityReservationPreference,omitempty"`
	CapacityReservationTarget     *struct {
		CapacityReservationId               string `xml:"capacityReservationId,omitempty"`
		CapacityReservationResourceGroupArn string `xml:"capacityReservationResourceGroupArn,omitempty"`
	} `xml:"capacityReservationTarget,omitempty"`
}

type ec2InstanceHibernationXML struct {
	Configured string `xml:"configured,omitempty"`
}

type ec2InstanceEnclaveXML struct {
	Enabled string `xml:"enabled,omitempty"`
}

type ec2InstanceMetadataXML struct {
	State                   string `xml:"state,omitempty"`
	HttpTokens              string `xml:"httpTokens,omitempty"`
	HttpPutResponseHopLimit string `xml:"httpPutResponseHopLimit,omitempty"`
	HttpEndpoint            string `xml:"httpEndpoint,omitempty"`
	HttpProtocolIpv6        string `xml:"httpProtocolIpv6,omitempty"`
	InstanceMetadataTags    string `xml:"instanceMetadataTags,omitempty"`
}

type ec2InstanceMaintenanceXML struct {
	AutoRecovery string `xml:"autoRecovery,omitempty"`
}

type ec2InstancePrivateDNSXML struct {
	HostnameType                    string `xml:"hostnameType,omitempty"`
	EnableResourceNameDnsARecord    string `xml:"enableResourceNameDnsARecord,omitempty"`
	EnableResourceNameDnsAAAARecord string `xml:"enableResourceNameDnsAAAARecord,omitempty"`
}

// ec2NetworkInterfaceXML serves both a DescribeNetworkInterfaces item
// and an instance's networkInterfaceSet item, which
// ec2InstanceENIToXML clears of the fields that shape lacks.
type ec2NetworkInterfaceXML struct {
	NetworkInterfaceId    string                `xml:"networkInterfaceId"`
	SubnetId              string                `xml:"subnetId"`
	VpcId                 string                `xml:"vpcId"`
	AvailabilityZone      string                `xml:"availabilityZone,omitempty"`
	Description           string                `xml:"description,omitempty"`
	OwnerId               string                `xml:"ownerId"`
	RequesterManaged      *bool                 `xml:"requesterManaged,omitempty"`
	Status                string                `xml:"status"`
	InterfaceType         string                `xml:"interfaceType"`
	MacAddress            string                `xml:"macAddress,omitempty"`
	PrivateIpAddress      string                `xml:"privateIpAddress"`
	PrivateDnsName        string                `xml:"privateDnsName,omitempty"`
	SourceDestCheck       bool                  `xml:"sourceDestCheck"`
	GroupSet              []ec2InstanceSGXML    `xml:"groupSet>item"`
	Attachment            *ec2ENIAttachmentXML  `xml:"attachment,omitempty"`
	Association           *ec2ENIAssociationXML `xml:"association,omitempty"`
	PrivateIpAddressesSet []ec2ENIPrivateIPXML  `xml:"privateIpAddressesSet>item,omitempty"`
	TagSet                []ec2ResourceTagXML   `xml:"tagSet>item,omitempty"`
}

type ec2ENIPrivateIPXML struct {
	PrivateIpAddress string `xml:"privateIpAddress"`
	PrivateDnsName   string `xml:"privateDnsName,omitempty"`
	Primary          bool   `xml:"primary"`
}

type ec2ENIAttachmentXML struct {
	AttachmentId        string `xml:"attachmentId"`
	InstanceId          string `xml:"instanceId,omitempty"`
	InstanceOwnerId     string `xml:"instanceOwnerId,omitempty"`
	DeviceIndex         int    `xml:"deviceIndex"`
	NetworkCardIndex    int    `xml:"networkCardIndex"`
	Status              string `xml:"status"`
	DeleteOnTermination bool   `xml:"deleteOnTermination"`
}

type ec2ENIAssociationXML struct {
	PublicIp      string `xml:"publicIp"`
	IpOwnerId     string `xml:"ipOwnerId"`
	AllocationId  string `xml:"allocationId,omitempty"`
	AssociationId string `xml:"associationId,omitempty"`
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
	GroupId   string `xml:"groupId"`
	GroupName string `xml:"groupName,omitempty"` // an instance's own groupSet's only
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

// ec2InstanceNet is what an instance's answer reads besides its row:
// its primary ENI, nil once terminated; the Elastic IP associated with
// it, nil for none; and the names of its groups, nil for an answer that
// names none (RunInstances').
type ec2InstanceNet struct {
	eni        *repository.EC2NetworkInterface
	eip        *repository.EC2EIP
	groupNames map[string]string
}

// ec2InstanceToXML renders inst on net. An instance launched before its
// profile's ARN was stored answers one built from the name.
func ec2InstanceToXML(account string, inst *repository.EC2Instance, net ec2InstanceNet) (ec2InstanceXML, error) {
	x := ec2InstanceXML{
		InstanceId:    inst.ID,
		ImageId:       inst.AMIID,
		InstanceType:  inst.InstanceType,
		KeyName:       inst.KeyName,
		LaunchTime:    inst.CreatedAt,
		EbsOptimized:  inst.EBSOptimized,
		InstanceState: ec2InstanceStateForName(inst.State),
	}
	if len(inst.Recorded) > 0 {
		if err := json.Unmarshal(inst.Recorded, &x.ec2InstanceRecordedXML); err != nil {
			return x, err
		}
	}
	if inst.IAMInstanceProfileName != "" {
		x.IamProfile = &ec2IamProfileXML{
			Arn: cmp.Or(inst.IAMInstanceProfileARN, awsproto.BuildIAMInstanceProfileARN(account, inst.IAMInstanceProfileName)),
			Id:  cmp.Or(inst.IAMInstanceProfileID, inst.IAMInstanceProfileName),
		}
	}
	eni := net.eni
	if eni == nil {
		return x, nil
	}
	eniXML := ec2InstanceENIToXML(account, eni, net.eip)
	x.SubnetId = eni.SubnetID
	x.VpcId = eni.VPCID
	x.PrivateIpAddress = eni.PrivateIP
	x.PrivateDnsName = eni.PrivateDNSName
	x.IpAddress = eni.PublicIP
	x.SourceDestCheck = &eniXML.SourceDestCheck
	for _, g := range eniXML.GroupSet {
		x.GroupSet = append(x.GroupSet, ec2InstanceSGXML{GroupId: g.GroupId, GroupName: net.groupNames[g.GroupId]})
	}
	x.NetworkInterfaceSet = []ec2NetworkInterfaceXML{eniXML}
	return x, nil
}

// ec2InstanceENIToXML renders eni, with eip the Elastic IP associated
// with it (nil for none), as an instance's networkInterfaceSet item:
// without the zone, requesterManaged, tags, attachment owner or
// association ids a DescribeNetworkInterfaces item has and EC2's
// InstanceNetworkInterface lacks.
func ec2InstanceENIToXML(account string, eni *repository.EC2NetworkInterface, eip *repository.EC2EIP) ec2NetworkInterfaceXML {
	x := ec2ENIToXML(account, eni, eip)
	x.AvailabilityZone, x.RequesterManaged = "", nil
	if x.Attachment != nil {
		x.Attachment.InstanceId, x.Attachment.InstanceOwnerId = "", ""
	}
	if x.Association != nil {
		x.Association.AllocationId, x.Association.AssociationId = "", ""
	}
	return x
}

// ec2ENIToXML renders eni; eip is the address associated with it, nil
// for none. An ENI with no instance has no attachment. A
// launched ENI, which stores no owner, status or type, answers account,
// in-use and interface, and is deleted on termination.
func ec2ENIToXML(account string, eni *repository.EC2NetworkInterface, eip *repository.EC2EIP) ec2NetworkInterfaceXML {
	x := ec2NetworkInterfaceXML{
		NetworkInterfaceId: eni.ID,
		SubnetId:           eni.SubnetID,
		VpcId:              eni.VPCID,
		AvailabilityZone:   eni.AvailabilityZone,
		Description:        eni.Description,
		OwnerId:            cmp.Or(eni.OwnerID, account),
		RequesterManaged:   &eni.RequesterManaged,
		Status:             cmp.Or(eni.Status, "in-use"),
		InterfaceType:      cmp.Or(eni.InterfaceType, "interface"),
		MacAddress:         eni.MacAddress,
		PrivateIpAddress:   eni.PrivateIP,
		PrivateDnsName:     eni.PrivateDNSName,
		SourceDestCheck:    eni.SourceDestCheck,
		GroupSet:           []ec2InstanceSGXML{},
	}
	if eni.InstanceID != "" {
		x.Attachment = &ec2ENIAttachmentXML{
			AttachmentId:        eni.AttachmentID,
			InstanceId:          eni.InstanceID,
			InstanceOwnerId:     account,
			Status:              "attached",
			DeleteOnTermination: !eni.KeepOnTermination,
		}
	}
	for _, sgID := range eni.SecurityGroupIDs {
		x.GroupSet = append(x.GroupSet, ec2InstanceSGXML{GroupId: sgID})
	}
	switch {
	case eip != nil:
		x.Association = &ec2ENIAssociationXML{PublicIp: eip.PublicIP, IpOwnerId: account,
			AllocationId: eip.AllocationID, AssociationId: eip.AssociationID}
	case eni.PublicIP != "":
		x.Association = &ec2ENIAssociationXML{PublicIp: eni.PublicIP, IpOwnerId: "amazon"}
	}
	for _, ip := range eni.PrivateIPAddresses {
		x.PrivateIpAddressesSet = append(x.PrivateIpAddressesSet,
			ec2ENIPrivateIPXML{PrivateIpAddress: ip.Address, PrivateDnsName: ip.PrivateDNSName, Primary: ip.Primary})
	}
	return x
}

// queryListValues returns a flattened scalar list (<prefix><n>) in
// numeric <n> order, never nil. Every index is read, a gap or a
// repeated key included, so a Describe that declares it reads Name.N
// drops no item.
func queryListValues(p url.Values, prefix string) []string {
	var ns []string
	for k := range p {
		if n, ok := strings.CutPrefix(k, prefix); ok && ec2IsIndex(n) {
			ns = append(ns, n)
		}
	}
	slices.SortFunc(ns, ec2IndexOrder)
	out := []string{}
	for _, n := range ns {
		out = append(out, p[prefix+n]...)
	}
	return out
}

// queryIDs is queryListValues with each value once, in first-seen
// order: a Describe answers an id named twice once, as AWS does.
func queryIDs(p url.Values, prefix string) []string {
	var out []string
	for _, v := range queryListValues(p, prefix) {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// parseInstanceIDs reads InstanceId.<n> params.
func parseInstanceIDs(req awsproto.QueryRPCRequest) []string {
	return queryListValues(req.Params, "InstanceId.")
}

// ec2InstanceNetwork is where RunInstances puts the primary ENI.
type ec2InstanceNetwork struct {
	subnetID          string
	sgIDs             []string
	privateIP         string // empty: the lowest free address
	associatePublicIP string // "true", "false", or "" for the subnet's default
}

// errNICNotModelled refuses a network interface fakeaws does not launch.
var errNICNotModelled = errors.New("a network interface other than a new primary one (NetworkInterface.1, DeviceIndex 0, deleted on termination)")

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
		return ec2InstanceNetwork{}, errNICNotModelled
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
	if errors.Is(err, errNICNotModelled) {
		ec2Refuse(w, req.Action, err.Error())
		return
	}
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	imageID := req.Params.Get("ImageId")
	instanceType := req.Params.Get("InstanceType")
	if nw.subnetID == "" || imageID == "" || instanceType == "" {
		ec2Refuse(w, req.Action, "no SubnetId, ImageId or InstanceType") // AWS defaults the subnet (default VPC) and InstanceType
		return
	}
	if refuseInvalidValues(w, req.Params, ec2AttributeValues("")) {
		return
	}
	// The provider adds a volume spec whenever default_tags is set;
	// fakeaws has no volumes, so those tags are accepted and dropped.
	specs, refusedType := tagSpecifications(req.Params, "instance", "network-interface", "volume")
	if specs == nil {
		// AWS also tags spot-instances-request, elastic-gpu, ...
		ec2Refuse(w, req.Action, "TagSpecification.N.ResourceType="+refusedType)
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
	keyName := req.Params.Get("KeyName")
	if keyName != "" {
		_, err := app.repo.GetKeyPair(account, region, keyName)
		if errors.Is(err, models.ErrNotFound) {
			writeKeyPairNotFound(w, "The key pair '%s' does not exist", keyName)
			return
		}
		if err != nil {
			awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
			return
		}
	}
	id := "i-" + ec2RandID()
	inst := &repository.EC2Instance{
		ID: id, SubnetID: nw.subnetID, AMIID: imageID, InstanceType: instanceType, KeyName: keyName,
		UserData:      req.Params.Get("UserData"),
		State:         "running",
		Region:        region,
		ARN:           awsproto.BuildEC2InstanceARN(region, account, id),
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
		ReservationID: "r-" + ec2RandID(),
	}
	// The instance answers the profile's stored ARN and id: a loaded
	// profile's ARN carries its path, which the name alone does not.
	if name := req.Params.Get("IamInstanceProfile.Name"); name != "" {
		profile, err := app.repo.GetInstanceProfile(account, name)
		if err != nil {
			awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
			return
		}
		inst.IAMInstanceProfileName, inst.IAMInstanceProfileARN, inst.IAMInstanceProfileID = name, profile.ARN, profile.ID
	}
	setInstanceAttributes(&inst.EC2InstanceAttributes, req.Params, "")
	eni := &repository.EC2NetworkInterface{
		ID: "eni-" + ec2RandID(), AttachmentID: "eni-attach-" + ec2RandID(),
		SecurityGroupIDs: nw.sgIDs, PrivateIP: nw.privateIP, SourceDestCheck: true,
	}
	if nw.associatePublicIP == "true" || (nw.associatePublicIP == "" && subnet.MapPublicIPOnLaunch) {
		eni.PublicIP, eni.AutoPublicIP = ec2DerivePublicIP(ec2AutoIPNet, eni.ID), true
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
	x, err := ec2InstanceToXML(account, inst, ec2InstanceNet{eni: eni})
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "RunInstances", &ec2RunInstancesResult{
		Reservation:  inst.ReservationID,
		OwnerId:      account,
		InstancesSet: []ec2InstanceXML{x},
	})
}

// ec2InstanceRow is what DescribeInstances filters: the instance as
// answered, plus what the answer does not show, the launch subnet's
// zone and the owning account.
type ec2InstanceRow struct {
	x             ec2InstanceXML
	zone, ownerID string
}

// instanceFilters are the DescribeInstances filters fakeaws models;
// subnet-id, vpc-id, private-ip-address and ip-address come from the
// primary ENI, so a terminated instance, which has none, matches none
// of them, as in AWS. availability-zone is the launch subnet's.
var instanceFilters = ec2FilterTable[ec2InstanceRow]{
	values: map[string]func(ec2InstanceRow) []string{
		"instance-id":         func(r ec2InstanceRow) []string { return []string{r.x.InstanceId} },
		"instance-state-name": func(r ec2InstanceRow) []string { return []string{r.x.InstanceState.Name} },
		"instance-type":       func(r ec2InstanceRow) []string { return []string{r.x.InstanceType} },
		"image-id":            func(r ec2InstanceRow) []string { return []string{r.x.ImageId} },
		"subnet-id":           func(r ec2InstanceRow) []string { return []string{r.x.SubnetId} },
		"vpc-id":              func(r ec2InstanceRow) []string { return []string{r.x.VpcId} },
		"private-ip-address":  func(r ec2InstanceRow) []string { return []string{r.x.PrivateIpAddress} },
		"ip-address":          func(r ec2InstanceRow) []string { return []string{r.x.IpAddress} },
		"availability-zone":   func(r ec2InstanceRow) []string { return []string{r.zone} },
		"owner-id":            func(r ec2InstanceRow) []string { return []string{r.ownerID} },
	},
	tagID: func(r ec2InstanceRow) string { return r.x.InstanceId },
}

// ec2DescribeInstances answers InstanceId.N or, with none, the
// region's instances, either way narrowed by instanceFilters, each in
// its reservation with the others launched in it.
func (app *Application) ec2DescribeInstances(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	filters, ok := instanceFilters.read(w, req, "InstanceId.N")
	if !ok {
		return
	}
	instances, ok := app.ec2FindInstances(w, account, region, queryIDs(req.Params, "InstanceId."))
	if !ok {
		return
	}
	enis, err := app.instanceENIs(account)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	subnets, err := app.repo.ListSubnets(account, region)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	groupNames, err := app.groupNames(account, region)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	eips, err := app.repo.ListEIPs(account, region)
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
		net := ec2InstanceNet{eni: enis[inst.ID], groupNames: groupNames}
		if i := slices.IndexFunc(eips, func(e *repository.EC2EIP) bool { return net.eni != nil && e.NetworkInterfaceID == net.eni.ID }); i >= 0 {
			net.eip = eips[i]
		}
		x, err := ec2InstanceToXML(account, inst, net)
		if err != nil {
			awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
			return
		}
		row := ec2InstanceRow{x: x, ownerID: account}
		row.x.TagSet = tags[inst.ID]
		if i := slices.IndexFunc(subnets, func(s *repository.EC2Subnet) bool { return s.ID == inst.SubnetID }); i >= 0 {
			row.zone = subnets[i].AvailabilityZone
		}
		if instanceFilters.matches(row, filters, tags) {
			out.ReservationSet = ec2Reserve(out.ReservationSet, account, inst.ReservationID, row.x)
		}
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DescribeInstances", &out)
}

// ec2Reserve adds x to reservation id of set, which it opens when set
// has none. An instance stored before its reservation was gets one of
// its own.
func ec2Reserve(set []ec2ReservationXML, account, id string, x ec2InstanceXML) []ec2ReservationXML {
	if i := slices.IndexFunc(set, func(r ec2ReservationXML) bool { return r.ReservationId == id }); id != "" && i >= 0 {
		set[i].InstancesSet = append(set[i].InstancesSet, x)
		return set
	}
	return append(set, ec2ReservationXML{ReservationId: cmp.Or(id, "r-"+ec2RandID()), OwnerId: account, InstancesSet: []ec2InstanceXML{x}})
}

// groupNames maps each security group id of region to its name.
func (app *Application) groupNames(account, region string) (map[string]string, error) {
	groups, err := app.repo.ListSecurityGroups(account, region)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(groups))
	for _, g := range groups {
		out[g.ID] = g.GroupName
	}
	return out, nil
}

// ec2FindInstances looks up each id or, with none, lists the region's
// instances. It writes the error itself, InvalidInstanceID.NotFound
// for a missing one, which the provider's destroy wait reads as gone,
// and reports false.
func (app *Application) ec2FindInstances(w http.ResponseWriter, account, region string, ids []string) ([]*repository.EC2Instance, bool) {
	if len(ids) == 0 {
		instances, err := app.repo.ListInstances(account, region)
		if err != nil {
			awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
			return nil, false
		}
		return instances, true
	}
	var out []*repository.EC2Instance
	for _, id := range ids {
		inst, err := app.repo.GetInstance(account, region, id)
		if err != nil {
			writeInstanceError(w, id, err)
			return nil, false
		}
		out = append(out, inst)
	}
	return out, true
}

// instanceENIs maps instance id → primary ENI, account-wide.
func (app *Application) instanceENIs(account string) (map[string]*repository.EC2NetworkInterface, error) {
	enis, err := app.repo.ListNetworkInterfaces(account, "")
	if err != nil {
		return nil, err
	}
	return enisByInstance(enis), nil
}

// enisByInstance maps instance id → ENI. ENIs with no instance share
// the entry "", which no instance's id looks up.
func enisByInstance(enis []*repository.EC2NetworkInterface) map[string]*repository.EC2NetworkInterface {
	out := make(map[string]*repository.EC2NetworkInterface, len(enis))
	for _, eni := range enis {
		out[eni.InstanceID] = eni
	}
	return out
}

// ----- NetworkInterface handlers -----

// eniFilterValues maps each DescribeNetworkInterfaces filter fakeaws
// supports to the ENI's values for it, read off the answer. The
// provider's aws_subnet and aws_security_group deletes list lingering
// ENIs by subnet-id and group-id.
var eniFilterValues = map[string]func(ec2NetworkInterfaceXML) []string{
	"network-interface-id": func(e ec2NetworkInterfaceXML) []string { return []string{e.NetworkInterfaceId} },
	"attachment.instance-id": func(e ec2NetworkInterfaceXML) []string {
		return eniAttachment(e, func(a *ec2ENIAttachmentXML) string { return a.InstanceId })
	},
	"attachment.attachment-id": func(e ec2NetworkInterfaceXML) []string {
		return eniAttachment(e, func(a *ec2ENIAttachmentXML) string { return a.AttachmentId })
	},
	"subnet-id":          func(e ec2NetworkInterfaceXML) []string { return []string{e.SubnetId} },
	"vpc-id":             func(e ec2NetworkInterfaceXML) []string { return []string{e.VpcId} },
	"private-ip-address": func(e ec2NetworkInterfaceXML) []string { return []string{e.PrivateIpAddress} },
	"owner-id":           func(e ec2NetworkInterfaceXML) []string { return []string{e.OwnerId} },
	"group-id": func(e ec2NetworkInterfaceXML) []string {
		var out []string
		for _, g := range e.GroupSet {
			out = append(out, g.GroupId)
		}
		return out
	},
}

// eniAttachment is field of e's attachment, none when e has none: an
// attachment filter matches no standalone ENI.
func eniAttachment(e ec2NetworkInterfaceXML, field func(*ec2ENIAttachmentXML) string) []string {
	if e.Attachment == nil {
		return nil
	}
	return []string{field(e.Attachment)}
}

var eniFilters = ec2FilterTable[ec2NetworkInterfaceXML]{
	values: eniFilterValues,
	tagID:  func(e ec2NetworkInterfaceXML) string { return e.NetworkInterfaceId },
}

// writeInstanceError answers a failed instance lookup, with EC2's 400
// InvalidInstanceID.NotFound for a missing instance.
func writeInstanceError(w http.ResponseWriter, id string, err error) {
	if errors.Is(err, models.ErrNotFound) {
		awsproto.WriteServiceError(w, awsproto.ShapeEC2Query,
			http.StatusBadRequest, "InvalidInstanceID.NotFound",
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

// ec2DescribeNetworkInterfaces lists ENIs, each with its tags and the
// association of the address associated with it. An unknown
// NetworkInterfaceId.N is InvalidNetworkInterfaceID.NotFound, which
// the provider reads as "gone"; an unsupported filter is refused
// rather than ignored.
func (app *Application) ec2DescribeNetworkInterfaces(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	filters, ok := eniFilters.read(w, req, "NetworkInterfaceId.N")
	if !ok {
		return
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
	eips, err := app.repo.ListEIPs(account, region)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	tags, ok := app.tagSets(w, account)
	if !ok {
		return
	}
	out := ec2DescribeNetworkInterfacesResult{NetworkInterfaceSet: []ec2NetworkInterfaceXML{}}
	for _, eni := range enis {
		if len(ids) > 0 && !slices.Contains(ids, eni.ID) {
			continue
		}
		var eip *repository.EC2EIP
		if i := slices.IndexFunc(eips, func(e *repository.EC2EIP) bool { return e.NetworkInterfaceID == eni.ID }); i >= 0 {
			eip = eips[i]
		}
		x := ec2ENIToXML(account, eni, eip)
		x.TagSet = tags[eni.ID]
		if eniFilters.matches(x, filters, tags) {
			out.NetworkInterfaceSet = append(out.NetworkInterfaceSet, x)
		}
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DescribeNetworkInterfaces", &out)
}

// ec2ModifyNetworkInterfaceAttribute models the Groups and Description
// attributes: the provider sends vpc_security_group_ids changes here,
// to the instance's primary ENI, so they show up in the instance's
// groupSet, and aws_network_interface's description as Description.Value.
// One call modifies one attribute, as on EC2: both at once is refused,
// and so is any other param (SourceDestCheck.Value, Attachment.*, ...).
func (app *Application) ec2ModifyNetworkInterfaceAttribute(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	if ec2RefuseUnread(w, req, "NetworkInterfaceId", "SecurityGroupId.N", "Description.Value") {
		return
	}
	id := req.Params.Get("NetworkInterfaceId")
	groups := queryListValues(req.Params, "SecurityGroupId.")
	description, hasDescription := req.Params.Get("Description.Value"), req.Params.Has("Description.Value")
	if id == "" || (len(groups) == 0 && !hasDescription) {
		ec2Refuse(w, req.Action, "no NetworkInterfaceId, or neither SecurityGroupId.N nor Description.Value (only the Groups and Description attributes are modelled)")
		return
	}
	if len(groups) > 0 && hasDescription {
		// EC2 modifies one attribute per call; the API reference names no
		// error code for two, so fakeaws refuses rather than guess one.
		ec2Refuse(w, req.Action, "SecurityGroupId.N", "Description.Value")
		return
	}
	eni, err := app.repo.GetNetworkInterface(account, region, id)
	if errors.Is(err, models.ErrNotFound) {
		writeENINotFound(w, id)
		return
	}
	if err == nil && len(groups) > 0 {
		_, err = app.checkSubnetGroups(account, region, eni.SubnetID, groups)
	}
	if err == nil {
		err = app.repo.UpdateNetworkInterface(account, region, id, func(e *repository.EC2NetworkInterface) {
			if hasDescription {
				e.Description = description
			} else {
				e.SecurityGroupIDs = groups
			}
		})
	}
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "ModifyNetworkInterfaceAttribute", nil)
}

// ec2ModifyInstanceAttribute stores SourceDestCheck on the primary
// ENI that DescribeInstances reads it from (the provider sends it
// after create for source_dest_check = false), and the
// ec2InstanceAttributes on the instance, in one transaction. Any other
// param (UserData.Value, InstanceType.Value, GroupId.N, the legacy
// Attribute and Value, ...) is refused, and so are a value AWS does
// not accept, a request with no attribute and a terminated instance,
// before anything is written.
func (app *Application) ec2ModifyInstanceAttribute(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	id := req.Params.Get("InstanceId")
	if id == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
			fmt.Errorf("InstanceId required: %w", models.ErrConflict))
		return
	}
	values := ec2AttributeValues(".Value")
	values["SourceDestCheck.Value"] = ec2Bool
	attrs := slices.Collect(maps.Keys(values))
	if ec2RefuseUnread(w, req, append(attrs, "InstanceId")...) || refuseInvalidValues(w, req.Params, values) {
		return
	}
	if !slices.ContainsFunc(attrs, req.Params.Has) {
		// UNVERIFIED(aws-code): MissingParameter from https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html; no recording
		awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest, "MissingParameter",
			"The request must contain an attribute to modify.")
		return
	}
	change := repository.EC2InstanceAttributeChange{Set: func(a *repository.EC2InstanceAttributes) {
		setInstanceAttributes(a, req.Params, ".Value")
	}}
	if v := req.Params.Get("SourceDestCheck.Value"); v != "" {
		on := v == "true"
		change.SourceDestCheck = &on
	}
	err := app.repo.UpdateInstanceAttributes(account, region, id, change)
	if errors.Is(err, models.ErrTerminalState) {
		// UNVERIFIED(aws-code): IncorrectInstanceState from https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html; no recording
		awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest, "IncorrectInstanceState",
			fmt.Sprintf("The instance '%s' is not in a state from which it can be modified.", id))
		return
	}
	if err != nil {
		writeInstanceError(w, id, err)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "ModifyInstanceAttribute", nil)
}

// ec2Bool is what AWS accepts for a boolean attribute value.
var ec2Bool = []string{"true", "false"}

// ec2InstanceAttribute is one attribute stored on the instance row:
// the values AWS accepts for it and how one sets it.
type ec2InstanceAttribute struct {
	values []string
	set    func(*repository.EC2InstanceAttributes, string)
}

// ec2InstanceAttributes are the attributes stored on the instance row.
// RunInstances sends one as <Name>, ModifyInstanceAttribute as
// <Name>.Value.
var ec2InstanceAttributes = map[string]ec2InstanceAttribute{
	"DisableApiTermination": {ec2Bool, func(a *repository.EC2InstanceAttributes, v string) { a.DisableAPITermination = v == "true" }},
	"DisableApiStop":        {ec2Bool, func(a *repository.EC2InstanceAttributes, v string) { a.DisableAPIStop = v == "true" }},
	"EbsOptimized":          {ec2Bool, func(a *repository.EC2InstanceAttributes, v string) { a.EBSOptimized = v == "true" }},
	"InstanceInitiatedShutdownBehavior": {[]string{"stop", "terminate"},
		func(a *repository.EC2InstanceAttributes, v string) { a.ShutdownBehavior = v }},
}

// ec2AttributeValues maps each ec2InstanceAttributes param, named
// <Name><suffix>, to the values AWS accepts for it.
func ec2AttributeValues(suffix string) map[string][]string {
	out := map[string][]string{}
	for name, attr := range ec2InstanceAttributes {
		out[name+suffix] = attr.values
	}
	return out
}

// setInstanceAttributes sets on a each attribute p carries as
// <Name><suffix>.
func setInstanceAttributes(a *repository.EC2InstanceAttributes, p url.Values, suffix string) {
	for name, attr := range ec2InstanceAttributes {
		if v := p.Get(name + suffix); v != "" {
			attr.set(a, v)
		}
	}
}

// refuseInvalidValues answers InvalidParameterValue, and reports true,
// when p carries a param of values with a value not listed for it, an
// empty one included. Params are checked in name order, so the same
// request always names the same param.
func refuseInvalidValues(w http.ResponseWriter, p url.Values, values map[string][]string) bool {
	for _, param := range slices.Sorted(maps.Keys(values)) {
		if v := p.Get(param); p.Has(param) && !slices.Contains(values[param], v) {
			// UNVERIFIED(aws-code): InvalidParameterValue from https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html; no recording
			awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest, "InvalidParameterValue",
				fmt.Sprintf("Value (%s) for parameter %s is invalid. Expected: '%s'.", v, param, strings.Join(values[param], "', '")))
			return true
		}
	}
	return false
}

// ec2TerminateInstances terminates every id in one transaction, where
// each one's previous state is read: as in AWS, an instance that
// cannot be terminated (unknown, or with disableApiTermination set)
// leaves all of them as they were, and one already terminated answers
// terminated/terminated.
//
// NOTE: do NOT hard-delete the rows. The provider's destroy wait-loop
// polls DescribeInstances expecting to observe the state transition
// (running→stopping→terminated) before accepting "gone."
// Hard-deleting collapses the wait into a confusing "couldn't find
// resource (21 retries)" error. Cleanup of terminated rows happens
// lazily inside DeleteSubnet/DeleteVPC so the FK constraint doesn't
// block dependent resource deletion.
func (app *Application) ec2TerminateInstances(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	ids := parseInstanceIDs(req)
	if len(ids) == 0 {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
			fmt.Errorf("InstanceId.<n> required: %w", models.ErrConflict))
		return
	}
	previous, err := app.repo.SetInstanceState(account, region, "terminated", ids...)
	var refused *repository.InstanceError
	if errors.As(err, &refused) && errors.Is(err, repository.ErrTerminationProtected) {
		// UNVERIFIED(aws-code): OperationNotPermitted from https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html; no recording
		awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest, "OperationNotPermitted",
			fmt.Sprintf("The instance '%s' may not be terminated. Modify its 'disableApiTermination' instance attribute and try again.", refused.InstanceID))
		return
	}
	if refused != nil {
		writeInstanceError(w, refused.InstanceID, err)
		return
	}
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	out := ec2TerminateInstancesResult{}
	for i, id := range ids {
		out.InstancesSet = append(out.InstancesSet, ec2InstanceStateChangeXML{
			InstanceId:    id,
			CurrentState:  ec2InstanceStateForName("terminated"),
			PreviousState: ec2InstanceStateForName(previous[i]),
		})
	}
	awsproto.WriteEC2QueryRPCResponse(w, "TerminateInstances", &out)
}

// ----- KeyPair handlers -----

type ec2KeyPairXML struct {
	KeyPairId      string              `xml:"keyPairId,omitempty"`
	KeyName        string              `xml:"keyName"`
	KeyType        string              `xml:"keyType,omitempty"`
	KeyFingerprint string              `xml:"keyFingerprint"`
	PublicKey      string              `xml:"publicKey,omitempty"`
	CreateTime     string              `xml:"createTime,omitempty"`
	TagSet         []ec2ResourceTagXML `xml:"tagSet>item,omitempty"`
}

type ec2ImportKeyPairResult = ec2KeyPairXML

// ec2KeyPairToXML renders kp: its createTime is its created_at, a
// loaded key's as recorded.
func ec2KeyPairToXML(kp *repository.EC2KeyPair, tags map[string][]ec2ResourceTagXML) ec2KeyPairXML {
	return ec2KeyPairXML{KeyPairId: kp.ID, KeyName: kp.Name, KeyType: kp.KeyType, KeyFingerprint: kp.Fingerprint,
		CreateTime: kp.CreatedAt, TagSet: tags[kp.ID]}
}

type ec2DescribeKeyPairsResult struct {
	KeySet []ec2KeyPairXML `xml:"keySet>item"`
}

// ec2KeyFingerprint is the first 16 bytes of the public key's SHA-256,
// colon-separated hex: AWS's MD5 fingerprint shape, distinct per key so
// the fingerprint filter selects one. The provider treats it as opaque.
func ec2KeyFingerprint(publicKey string) string {
	sum := sha256.Sum256([]byte(publicKey))
	parts := make([]string, 16)
	for i, b := range sum[:16] {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}

// ec2ImportKeyPair stores the key text: PublicKeyMaterial is a blob,
// which the SDK sends base64-encoded on the Query wire, so the row holds
// what aws_key_pair's public_key said and DescribeKeyPairs'
// IncludePublicKey answers it as is. Material that is not base64 is
// 400 InvalidKeyPair.Format.
//
// UNVERIFIED(aws-code): InvalidKeyPair.Format from https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html; no recording
func (app *Application) ec2ImportKeyPair(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	name := req.Params.Get("KeyName")
	material := req.Params.Get("PublicKeyMaterial")
	if name == "" || material == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
			fmt.Errorf("KeyName and PublicKeyMaterial required: %w", models.ErrConflict))
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(material)
	if err != nil {
		awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest, "InvalidKeyPair.Format",
			"Key is not in valid OpenSSH public key format: PublicKeyMaterial is not base64-encoded")
		return
	}
	publicKey := string(decoded)
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
	err = app.repo.CreateKeyPair(account, kp)
	if err == nil {
		err = app.tagNew(account, region, tags,
			func() error { return app.repo.DeleteKeyPair(account, region, name) })
	}
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	out := ec2KeyPairToXML(kp, nil)
	out.CreateTime = "" // ImportKeyPair answers none
	for _, t := range tags {
		out.TagSet = append(out.TagSet, ec2ResourceTagXML{Key: t.Key, Value: t.Value})
	}
	awsproto.WriteEC2QueryRPCResponse(w, "ImportKeyPair", &out)
}

// keyPairFilters are the DescribeKeyPairs filters fakeaws models.
var keyPairFilters = ec2FilterTable[ec2KeyPairXML]{
	values: map[string]func(ec2KeyPairXML) []string{
		"key-name":    func(k ec2KeyPairXML) []string { return []string{k.KeyName} },
		"key-pair-id": func(k ec2KeyPairXML) []string { return []string{k.KeyPairId} },
		"fingerprint": func(k ec2KeyPairXML) []string { return []string{k.KeyFingerprint} },
	},
	tagID: func(k ec2KeyPairXML) string { return k.KeyPairId },
}

// ec2DescribeKeyPairs answers the region's key pairs narrowed by
// KeyName.N, terraform-provider-aws's read path, KeyPairId.N and
// keyPairFilters, each with its publicKey when IncludePublicKey=true,
// as data.aws_key_pair's include_public_key asks. An unknown KeyName.N
// or KeyPairId.N fails the call with writeKeyPairNotFound.
func (app *Application) ec2DescribeKeyPairs(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	filters, ok := keyPairFilters.read(w, req, "KeyName.N", "KeyPairId.N", "IncludePublicKey")
	if !ok || refuseInvalidValues(w, req.Params, map[string][]string{"IncludePublicKey": ec2Bool}) {
		return
	}
	kps, err := app.repo.ListKeyPairs(account, region)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	names := queryListValues(req.Params, "KeyName.")
	for _, name := range names {
		if !slices.ContainsFunc(kps, func(kp *repository.EC2KeyPair) bool { return kp.Name == name }) {
			writeKeyPairNotFound(w, "The key pair '%s' does not exist", name)
			return
		}
	}
	ids := queryListValues(req.Params, "KeyPairId.")
	for _, id := range ids {
		if !slices.ContainsFunc(kps, func(kp *repository.EC2KeyPair) bool { return kp.ID == id }) {
			writeKeyPairNotFound(w, "The key pair ID '%s' does not exist", id)
			return
		}
	}
	tags, ok := app.tagSets(w, account)
	if !ok {
		return
	}
	out := ec2DescribeKeyPairsResult{KeySet: []ec2KeyPairXML{}}
	for _, kp := range kps {
		x := ec2KeyPairToXML(kp, tags)
		if req.Params.Get("IncludePublicKey") == "true" {
			x.PublicKey = kp.PublicKey
		}
		if (len(names) == 0 || slices.Contains(names, kp.Name)) && (len(ids) == 0 || slices.Contains(ids, kp.ID)) &&
			keyPairFilters.matches(x, filters, tags) {
			out.KeySet = append(out.KeySet, x)
		}
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DescribeKeyPairs", &out)
}

// writeKeyPairNotFound answers an unknown KeyName.N or KeyPairId.N
// with 400 InvalidKeyPair.NotFound, which the provider's aws_key_pair
// read takes as gone; format names the key.
// UNVERIFIED(aws-code): InvalidKeyPair.NotFound from https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html; no recording
func writeKeyPairNotFound(w http.ResponseWriter, format, key string) {
	awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest,
		"InvalidKeyPair.NotFound", fmt.Sprintf(format, key))
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
	ImageType          string `xml:"imageType"`
	ImageOwnerAlias    string `xml:"imageOwnerAlias,omitempty"`
}

type ec2DescribeImagesResult struct {
	ImagesSet []ec2ImageXML `xml:"imagesSet>item"`
}

// imageFilters are the DescribeImages filters fakeaws models: the
// fields an AMI row stores (repository.EC2AMI), what ec2AMIToXML
// derives from them, and the tag filters. The row has no field for
// architecture, platform, block-device-mapping.* and the rest, so
// those stay refused, by name.
var imageFilters = ec2FilterTable[ec2ImageXML]{
	values: map[string]func(ec2ImageXML) []string{
		"name":                func(x ec2ImageXML) []string { return []string{x.Name} },
		"image-id":            func(x ec2ImageXML) []string { return []string{x.ImageId} },
		"owner-id":            func(x ec2ImageXML) []string { return []string{x.OwnerId} },
		"owner-alias":         func(x ec2ImageXML) []string { return []string{x.ImageOwnerAlias} },
		"virtualization-type": func(x ec2ImageXML) []string { return []string{x.VirtualizationType} },
		"root-device-name":    func(x ec2ImageXML) []string { return []string{x.RootDeviceName} },
		"state":               func(x ec2ImageXML) []string { return []string{x.State} },
		"image-type":          func(x ec2ImageXML) []string { return []string{x.ImageType} },
	},
	tagID: func(x ec2ImageXML) string { return x.ImageId },
}

// ec2DescribeImages answers ImageId.N, most common from
// terraform-provider-aws where users pass a literal AMI id, Owner.N
// and imageFilters (data.aws_ami's owners and filter blocks). Owner.N
// keeps account ids, self (the caller) and amazon, which matches the
// fixtures' literal ec2AmazonOwner; a loaded database has no fixtures
// and its Amazon images a numeric owner, so amazon matches none there. ExecutableBy.N is refused, by name. IncludeDisabled and
// IncludeDeprecated (which data.aws_ami always sends) are read:
// fakeaws has no disabled or deprecated image, so neither can change
// the answer.
func (app *Application) ec2DescribeImages(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	filters, ok := imageFilters.read(w, req, "ImageId.N", "Owner.N", "IncludeDisabled", "IncludeDeprecated")
	if !ok {
		return
	}
	// Lazy-seed canonical AMI fixtures for this region (Codex pass 9
	// BLOCKING #1) so callers in any valid AWS region see the same
	// fixture set as the boot-time slice.
	app.ensureAMIFixturesForRegion(account, region)
	wanted := queryIDs(req.Params, "ImageId.")
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
	tags, ok := app.tagSets(w, account)
	if !ok {
		return
	}
	// Owner.N keeps images of those owners, "self" meaning the caller:
	// the scope sweep's Owner.1=self sees none of the fixtures.
	owners := queryListValues(req.Params, "Owner.")
	out := ec2DescribeImagesResult{ImagesSet: []ec2ImageXML{}}
	for _, a := range amis {
		x := ec2AMIToXML(a)
		if (len(owners) == 0 || slices.Contains(owners, a.OwnerID) || a.OwnerID == account && slices.Contains(owners, "self")) &&
			imageFilters.matches(x, filters, tags) {
			out.ImagesSet = append(out.ImagesSet, x)
		}
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DescribeImages", &out)
}

// ----- AvailabilityZone -----

type ec2AvailabilityZoneXML struct {
	ZoneName           string `xml:"zoneName"`
	ZoneId             string `xml:"zoneId"`
	ZoneState          string `xml:"zoneState"`
	RegionName         string `xml:"regionName"`
	OptInStatus        string `xml:"optInStatus"`
	ZoneType           string `xml:"zoneType"`
	GroupName          string `xml:"groupName"`
	NetworkBorderGroup string `xml:"networkBorderGroup"`
}

type ec2DescribeAvailabilityZonesResult struct {
	AvailabilityZoneInfo []ec2AvailabilityZoneXML `xml:"availabilityZoneInfo>item"`
}

// zoneFilters are the DescribeAvailabilityZones filters fakeaws
// models, each matched against what the zone answers. data.aws_
// availability_zones sends state=available by default.
var zoneFilters = ec2FilterTable[ec2AvailabilityZoneXML]{
	values: map[string]func(ec2AvailabilityZoneXML) []string{
		"zone-name":            func(z ec2AvailabilityZoneXML) []string { return []string{z.ZoneName} },
		"zone-id":              func(z ec2AvailabilityZoneXML) []string { return []string{z.ZoneId} },
		"state":                func(z ec2AvailabilityZoneXML) []string { return []string{z.ZoneState} },
		"region-name":          func(z ec2AvailabilityZoneXML) []string { return []string{z.RegionName} },
		"opt-in-status":        func(z ec2AvailabilityZoneXML) []string { return []string{z.OptInStatus} },
		"zone-type":            func(z ec2AvailabilityZoneXML) []string { return []string{z.ZoneType} },
		"group-name":           func(z ec2AvailabilityZoneXML) []string { return []string{z.GroupName} },
		"network-border-group": func(z ec2AvailabilityZoneXML) []string { return []string{z.NetworkBorderGroup} },
	},
}

// ec2FixedZoneLetters name the zones an unloaded database answers in
// every region, <region>a to c. AWS's sets differ: us-east-1 has six
// zones, ap-northeast-1 no b.
const ec2FixedZoneLetters = "abc"

// ec2Zones reads region's availability zones once, with zoneID giving
// a zone name's id. On an unloaded database they are the fixed set,
// and zoneID gives any zone name (CreateSubnet takes any) <zone>-az1.
// On a loaded one they are the AZ table's rows for (account, region),
// and zoneID gives a row's stored zone id, "" for a zone with no row.
// An unreadable loaded flag is an error, never the fixed set.
func (app *Application) ec2Zones(account, region string) ([]repository.AvailabilityZone, func(zone string) string, error) {
	loaded, err := app.repo.Loaded()
	if err != nil {
		return nil, nil, err
	}
	if !loaded {
		zones := make([]repository.AvailabilityZone, 0, len(ec2FixedZoneLetters))
		for _, letter := range ec2FixedZoneLetters {
			zones = append(zones, repository.AvailabilityZone{ // ZoneID unset: zoneID gives it
				Region: region, ZoneName: region + string(letter), State: "available",
				OptInStatus: "opt-in-not-required", ZoneType: "availability-zone",
				GroupName: region, NetworkBorderGroup: region,
			})
		}
		return zones, func(zone string) string { return zone + "-az1" }, nil
	}
	zones, err := app.repo.ListAvailabilityZones(account, region)
	if err != nil {
		return nil, nil, err
	}
	ids := make(map[string]string, len(zones))
	for _, z := range zones {
		ids[z.ZoneName] = z.ZoneID
	}
	return zones, func(zone string) string { return ids[zone] }, nil
}

// ec2DescribeAvailabilityZones answers region's zones (ec2Zones)
// through zoneFilters, ZoneName.N and ZoneId.N. A ZoneName.N or
// ZoneId.N that is none of them answers 400 InvalidParameterValue
// naming it, unless the region has none: no rows cannot show a zone
// does not exist. Without AllAvailabilityZones=true a zone whose
// opt-in-status is not-opted-in is left out, as in AWS.
//
// CRITICAL[ec2-az-loaded-never-fixed-set]: a loaded database answers
// the AZ table's rows for (account, region) with their stored zone ids,
// never the fixed a-c set; with no rows it answers an empty set classed
// empty-collection, whatever ZoneName.N it names, and an unreadable loaded flag answers 500. A
// subnet's availabilityZoneId is read through the same ec2Zones: the
// row's zone id, "" for a zone with no row, never <zone>-az1.
//
// UNVERIFIED(aws-code): InvalidParameterValue from https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html; no recording
func (app *Application) ec2DescribeAvailabilityZones(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	filters, ok := zoneFilters.read(w, req, "ZoneName.N", "ZoneId.N", "AllAvailabilityZones")
	if !ok || refuseInvalidValues(w, req.Params, map[string][]string{"AllAvailabilityZones": {"true", "false"}}) {
		return
	}
	zones, zoneID, err := app.ec2Zones(account, region)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	xs := make([]ec2AvailabilityZoneXML, len(zones))
	zoneNames, zoneIDs := make([]string, len(zones)), make([]string, len(zones))
	for i, z := range zones {
		xs[i] = ec2ZoneToXML(z, zoneID(z.ZoneName))
		zoneNames[i], zoneIDs[i] = xs[i].ZoneName, xs[i].ZoneId
	}
	names, ids := queryListValues(req.Params, "ZoneName."), queryListValues(req.Params, "ZoneId.")
	if len(zones) > 0 && (refuseUnknownZone(w, names, zoneNames, "The zone '%s' does not exist.") ||
		refuseUnknownZone(w, ids, zoneIDs, "The zone ID '%s' does not exist.")) {
		return
	}
	all := req.Params.Get("AllAvailabilityZones") == "true"
	out := ec2DescribeAvailabilityZonesResult{AvailabilityZoneInfo: []ec2AvailabilityZoneXML{}}
	for _, x := range xs {
		if !all && x.OptInStatus == "not-opted-in" ||
			len(names) > 0 && !slices.Contains(names, x.ZoneName) ||
			len(ids) > 0 && !slices.Contains(ids, x.ZoneId) ||
			!zoneFilters.matches(x, filters, nil) {
			continue
		}
		out.AvailabilityZoneInfo = append(out.AvailabilityZoneInfo, x)
	}
	if len(zones) == 0 {
		markClass(w, classEmptyCollection)
	}
	awsproto.WriteEC2QueryRPCResponse(w, req.Action, &out)
}

// ec2ZoneToXML answers z, whose id is id (ec2Zones' zoneID), in its region.
func ec2ZoneToXML(z repository.AvailabilityZone, id string) ec2AvailabilityZoneXML {
	return ec2AvailabilityZoneXML{
		ZoneName: z.ZoneName, ZoneId: id, ZoneState: z.State, RegionName: z.Region,
		OptInStatus: z.OptInStatus, ZoneType: z.ZoneType, GroupName: z.GroupName, NetworkBorderGroup: z.NetworkBorderGroup,
	}
}

// refuseUnknownZone answers 400 InvalidParameterValue, message msg
// naming it, for the first of wanted not in known, and reports whether
// it wrote.
func refuseUnknownZone(w http.ResponseWriter, wanted, known []string, msg string) bool {
	for _, v := range wanted {
		if !slices.Contains(known, v) {
			awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest, "InvalidParameterValue", fmt.Sprintf(msg, v))
			return true
		}
	}
	return false
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
// result, an empty set, and refuses every other param, an id lookup
// (VolumeId.N, ...) and Filter.N included. DescribeSnapshots reads
// Owner.N (the SDK's OwnerIds), which the scope sweep sends: an empty
// set has no owner to tell apart.
func ec2DescribeNone(w http.ResponseWriter, req awsproto.QueryRPCRequest) {
	var reads []string
	if req.Action == "DescribeSnapshots" {
		reads = []string{"Owner.N"}
	}
	if _, ok := ec2NoFilters.read(w, req, reads...); !ok {
		return
	}
	markClass(w, classEmptyCollection)
	awsproto.WriteEC2QueryRPCResponse(w, req.Action,
		&ec2DescribeNoneResult{Set: ec2EmptySet{XMLName: xml.Name{Local: ec2NoneSets[req.Action]}}})
}

// ec2Refuse is EC2's one refusal of what AWS accepts but fakeaws does
// not model: 501 NotImplemented naming, deduped and sorted bytewise,
// each of names after "<action>: not modelled by fakeaws: ", classed
// filter-refused. 501 is fakeaws's own refusal, not a claim about AWS
// (AWS answers an unknown filter name 400 InvalidParameterValue, which
// would blame valid HCL), and aws-sdk-go-v2's retryer does not retry it.
func ec2Refuse(w http.ResponseWriter, action string, names ...string) {
	names = slices.Compact(slices.Sorted(slices.Values(names)))
	markClass(w, classFilterRefused)
	awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusNotImplemented, "NotImplemented",
		fmt.Sprintf("%s: %s: %s", action, ec2NotModelled, strings.Join(names, ", ")))
}

// ec2AmazonOwner is the literal owner of the Amazon fixtures and of a
// /mock/images image that names none. An image with it answers it as
// imageOwnerAlias too; any other owner answers no alias.
const ec2AmazonOwner = "amazon"

func ec2AMIToXML(a *repository.EC2AMI) ec2ImageXML {
	x := ec2ImageXML{
		ImageId: a.ID, Name: a.Name, OwnerId: a.OwnerID,
		VirtualizationType: a.VirtualizationType, RootDeviceName: a.RootDeviceName,
		State: "available", ImageType: "machine",
	}
	if a.OwnerID == ec2AmazonOwner {
		x.ImageOwnerAlias = ec2AmazonOwner
	}
	return x
}

// AL2023AMIID is the Amazon Linux 2023 fixture, the image SSM's public
// al2023-ami-kernel-default-x86_64 parameter resolves to on a database
// that is not loaded.
const AL2023AMIID = "ami-0al2023x8664"

// ec2AMIFixtures is the canonical fixture list seeded at startup and
// lazily per region, unless the database is loaded. The
// AWS provider's documentation examples reference Amazon Linux and
// Ubuntu LTS images by canonical name; we cover both so scenarios can
// pass in either. Per concepts.md "Standing patterns" item 8 — fixture
// state, never derived from real AWS.
var ec2AMIFixtures = []repository.EC2AMI{
	{ID: "ami-0abcd1234", Name: "amzn2-ami-hvm-2.0", OwnerID: ec2AmazonOwner, VirtualizationType: "hvm", RootDeviceName: "/dev/xvda"},
	{ID: AL2023AMIID, Name: "al2023-ami-2023.6.20241010.0-kernel-6.1-x86_64", OwnerID: ec2AmazonOwner, VirtualizationType: "hvm", RootDeviceName: "/dev/xvda"},
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
	if _, ok := ec2NoFilters.read(w, req, "InstanceType.N"); !ok {
		return
	}
	wanted := queryIDs(req.Params, "InstanceType.")
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
// name.
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

// ec2DescribeInstanceAttribute answers the Attribute param from the
// instance row, or its primary ENI for sourceDestCheck.
//
// CRITICAL[ec2-instance-attributes-from-rows]: each Attribute this
// answers MUST be what RunInstances, ModifyInstanceAttribute or a load
// last stored, else AWS's default; any other Attribute MUST be refused
// through ec2Refuse, never answered with a constant, and a missing one
// MUST be 400 MissingParameter; and an unknown InstanceId MUST be 400
// InvalidInstanceID.NotFound. The provider sets disable_api_termination
// and the others from these answers, so a constant hides a
// ModifyInstanceAttribute and plans a diff. disableApiStop is stored
// and answered, but nothing enforces it: fakeaws has no StopInstances,
// which stays refused as not modelled (the default arm).
func (app *Application) ec2DescribeInstanceAttribute(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	instanceID := req.Params.Get("InstanceId")
	inst, err := app.repo.GetInstance(account, region, instanceID)
	if err != nil {
		writeInstanceError(w, instanceID, err)
		return
	}
	out := ec2DescribeInstanceAttributeResult{InstanceId: instanceID}
	switch attr := req.Params.Get("Attribute"); {
	case ec2InstanceAttributeAnswer(&out, inst, attr):
	case attr == "sourceDestCheck":
		// A terminated instance has no ENI, so no sourceDestCheck, as
		// in DescribeInstances.
		enis, err := app.instanceENIs(account)
		if err != nil {
			awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
			return
		}
		if eni := enis[instanceID]; eni != nil {
			out.SourceDestCheck = &ec2AttributeBoolValue{Value: eni.SourceDestCheck}
		}
	case attr == "":
		// UNVERIFIED(aws-code): MissingParameter from https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html; no recording
		awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest, "MissingParameter",
			"The request must contain the parameter Attribute.")
		return
	default:
		ec2Refuse(w, req.Action, "Attribute="+attr)
		return
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DescribeInstanceAttribute", &out)
}

// ec2InstanceAttributeAnswer sets attr on out from inst when attr is
// one the instance row holds, and reports whether it was.
func ec2InstanceAttributeAnswer(out *ec2DescribeInstanceAttributeResult, inst *repository.EC2Instance, attr string) bool {
	switch attr {
	case "instanceInitiatedShutdownBehavior":
		out.InstanceInitiatedShutdownBehavior = &ec2AttributeStringValue{Value: cmp.Or(inst.ShutdownBehavior, "stop")}
	case "disableApiTermination":
		out.DisableApiTermination = &ec2AttributeBoolValue{Value: inst.DisableAPITermination}
	case "disableApiStop":
		out.DisableApiStop = &ec2AttributeBoolValue{Value: inst.DisableAPIStop}
	case "userData":
		// An instance without user data answers an empty <userData/>:
		// a <value></value> reads back as user_data = sha1("") and
		// plans a diff.
		out.UserData = &ec2AttributeStringValue{Value: inst.UserData}
	case "ebsOptimized":
		out.EbsOptimized = &ec2AttributeBoolValue{Value: inst.EBSOptimized}
	default:
		return false
	}
	return true
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
	{"subnet-", "subnet", ec2SubnetNotFound, func(app *Application, account, region, id string) error {
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
	{"sgr-", "security-group-rule", "InvalidSecurityGroupRuleId.NotFound", func(app *Application, account, region, id string) error {
		_, err := app.repo.GetSecurityGroupRule(account, region, id)
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
// or returns nil and the first type the operation cannot tag.
func tagSpecifications(p url.Values, allowed ...string) (map[string][]repository.EC2Tag, string) {
	out := map[string][]repository.EC2Tag{}
	for _, spec := range queryListItems(p, "TagSpecification.") {
		rt := p.Get(spec + "ResourceType")
		if !slices.Contains(allowed, rt) {
			return nil, rt
		}
		out[rt] = append(out[rt], parseTags(p, spec+"Tag.")...)
	}
	return out, ""
}

// refuseTagSpecifications parses TagSpecification.N and writes
// InvalidParameterValue when a type is not in allowed.
func refuseTagSpecifications(w http.ResponseWriter, p url.Values, allowed ...string) (map[string][]repository.EC2Tag, bool) {
	specs, rt := tagSpecifications(p, allowed...)
	if specs == nil {
		awsproto.WriteServiceError(w, awsproto.ShapeEC2Query, http.StatusBadRequest, "InvalidParameterValue",
			fmt.Sprintf("'%s' is not a valid taggable resource type for this operation.", rt))
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
// refuses through ec2Refuse an id of a type fakeaws cannot tag, and
// then reports false.
func (app *Application) taggableResources(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) (map[string]string, bool) {
	ids := queryListValues(req.Params, "ResourceId.")
	if len(ids) == 0 {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query,
			fmt.Errorf("ResourceId.N required: %w", models.ErrConflict))
		return nil, false
	}
	out := make(map[string]string, len(ids))
	for _, id := range ids {
		i := slices.IndexFunc(ec2TaggedKinds, func(k ec2TaggedKind) bool { return strings.HasPrefix(id, k.prefix) })
		if i < 0 {
			ec2Refuse(w, req.Action, "tags on "+id)
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
	resources, ok := app.taggableResources(w, account, region, req)
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
	resources, ok := app.taggableResources(w, account, region, req)
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

// tagFilters are the DescribeTags filters fakeaws models. The provider
// filters by resource-id, and by key for single-tag lookups (the
// instance read's launch-template tags). A tag's empty value is a
// value: value=* and an empty value match it.
var tagFilters = ec2FilterTable[repository.EC2Tag]{
	values: map[string]func(repository.EC2Tag) []string{
		"resource-id":   func(t repository.EC2Tag) []string { return []string{t.ResourceID} },
		"resource-type": func(t repository.EC2Tag) []string { return []string{t.ResourceType} },
		"key":           func(t repository.EC2Tag) []string { return []string{t.Key} },
		"value":         func(t repository.EC2Tag) []string { return []string{t.Value} },
	},
	emptyIsValue: []string{"value"},
}

// ec2DescribeTags lists the region's tags matching every filter; no
// match is a 200 with an empty tagSet. An unsupported filter is
// refused rather than ignored.
func (app *Application) ec2DescribeTags(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	filters, ok := tagFilters.read(w, req)
	if !ok {
		return
	}
	tags, err := app.repo.ListTags(account, region)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeEC2Query, err)
		return
	}
	out := ec2DescribeTagsResult{TagSet: []ec2TagXML{}}
	for _, t := range tags {
		if tagFilters.matches(t, filters, nil) {
			out.TagSet = append(out.TagSet, ec2TagXML{ResourceId: t.ResourceID, ResourceType: t.ResourceType, Key: t.Key, Value: t.Value})
		}
	}
	awsproto.WriteEC2QueryRPCResponse(w, "DescribeTags", &out)
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
func (app *Application) gatherEC2StateReal(account string) (map[string]any, error) {
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

	vpcs, err := app.repo.ListVPCs(account, "")
	if err != nil {
		return nil, err
	}
	vOut := make([]map[string]any, 0, len(vpcs))
	for _, v := range vpcs {
		vOut = append(vOut, map[string]any{
			"id": v.ID, "cidr_block": v.CidrBlock, "region": v.Region, "arn": v.ARN,
		})
	}
	out["vpcs"] = vOut

	subnets, err := app.repo.ListSubnets(account, "")
	if err != nil {
		return nil, err
	}
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
	// instance has none, so its IPs are "" and its groups []. ENIs are
	// read once, so the instances and network_interfaces blocks agree.
	allENIs, err := app.repo.ListNetworkInterfaces(account, "")
	if err != nil {
		return nil, err
	}
	enis := enisByInstance(allENIs)
	instances, err := app.repo.ListInstances(account, "")
	if err != nil {
		return nil, err
	}
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
	sgs, err := app.repo.ListSecurityGroups(account, "")
	if err != nil {
		return nil, err
	}
	sgOut := make([]map[string]any, 0, len(sgs))
	for _, sg := range sgs {
		rules, err := app.repo.ListSecurityGroupRules(account, sg.Region, sg.ID)
		if errors.Is(err, models.ErrNotFound) {
			continue // deleted since the list
		}
		if err != nil {
			return nil, err
		}
		ingress, egress := sgPermissions(rules)
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
	kps, err := app.repo.ListKeyPairs(account, "")
	if err != nil {
		return nil, err
	}
	for _, kp := range kps {
		kpOut = append(kpOut, map[string]any{
			"name": kp.Name, "fingerprint": kp.Fingerprint, "region": kp.Region,
		})
	}
	out["key_pairs"] = kpOut

	// Internet gateways — account-wide list. Used by topology
	// derivation to detect public subnets.
	igws, err := app.repo.ListInternetGateways(account, "")
	if err != nil {
		return nil, err
	}
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
	rts, err := app.repo.ListRouteTables(account, "")
	if err != nil {
		return nil, err
	}
	rtOut := make([]map[string]any, 0, len(rts))
	for _, rt := range rts {
		rtOut = append(rtOut, map[string]any{
			"id": rt.ID, "vpc_id": rt.VPCID,
			"region": rt.Region, "arn": rt.ARN,
		})
	}
	out["route_tables"] = rtOut

	routes, err := app.repo.ListRoutes(account)
	if err != nil {
		return nil, err
	}
	routeOut := make([]map[string]any, 0, len(routes))
	for _, rr := range routes {
		routeOut = append(routeOut, map[string]any{
			"route_table_id":         rr.RouteTableID,
			"destination_cidr_block": rr.DestinationCidrBlock,
			"gateway_id":             rr.GatewayID,
			"nat_gateway_id":         rr.NatGatewayID,
			"instance_id":            rr.InstanceID,
			"network_interface_id":   rr.NetworkInterfaceID,
			"origin":                 rr.Origin,
			"state":                  rr.State,
		})
	}
	out["routes"] = routeOut

	assocs, err := app.repo.ListRouteTableAssociations(account)
	if err != nil {
		return nil, err
	}
	assocOut := make([]map[string]any, 0, len(assocs))
	for _, a := range assocs {
		assocOut = append(assocOut, map[string]any{
			"id":             a.ID,
			"route_table_id": a.RouteTableID,
			"subnet_id":      a.SubnetID,  // "" on a main or an edge association
			"gateway_id":     a.GatewayID, // "" unless an edge association
			"main":           a.Main,
			"state":          a.State, // "" when its recording held none
		})
	}
	out["route_table_associations"] = assocOut

	eips, err := app.repo.ListEIPs(account, "")
	if err != nil {
		return nil, err
	}
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
			"arn":                  awsproto.BuildEC2EIPARN(eip.Region, account, eip.AllocationID),
		})
	}
	out["eips"] = eipOut

	return out, nil
}

// ensureAMIFixturesForRegion lazy-seeds the canonical AMI set into a
// region the first time we observe a request scoped to it. Codex
// pass 9 BLOCKING #1: previously fixtures were only seeded for an
// 8-region slice at boot, so RunInstances/DescribeImages in any
// other region got bogus 404s on the canonical AMIs. Now any region
// the user touches becomes consistent on first contact. SeedAMI is
// idempotent so re-entry is harmless.
//
// MUST[ami-fixtures-not-seeded-when-loaded]: a loaded database's AMIs
// are the loader's rows only. Neither boot nor this lazy seed writes a
// fixture, nor does an unreadable loaded flag; /mock/images matches
// no fixture, so a non-hex fixture id is 400 like any other; SSM's
// public al2023 parameter is read from rows, ParameterNotFound until
// one is loaded.
func (app *Application) ensureAMIFixturesForRegion(account, region string) {
	if loaded, err := app.repo.Loaded(); err != nil || loaded {
		return
	}
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
