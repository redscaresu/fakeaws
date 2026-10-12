package handlers

// load_ec2_network.go — the loaders of availability zones, VPCs and
// their DNS attributes, subnets and internet gateways. Each decodes its
// Describe answer into rows and tags, and renders the rows back through
// the XML its Describe handler answers with.

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/redscaresu/fakeaws/handlers/awsproto"
	"github.com/redscaresu/fakeaws/models"
	"github.com/redscaresu/fakeaws/repository"
)

// The provider files whose reads the ignore entries cite: aws_vpc's,
// aws_subnet's, and the AZ data source that reads the most of a zone.
const (
	vpcCite    = "terraform-provider-aws@v5.100.0/internal/service/ec2/vpc_.go"
	subnetCite = "terraform-provider-aws@v5.100.0/internal/service/ec2/vpc_subnet.go"
	azCite     = "terraform-provider-aws@v5.100.0/internal/service/ec2/ec2_availability_zone_data_source.go"
)

func init() {
	ec2Paged := func(l loader) loader {
		l.requestToken, l.responseToken = "NextToken", "nextToken"
		return l
	}
	registerLoader(loader{key: LoadKey{"ec2", "DescribeAvailabilityZones"}, table: "availability_zones",
		decode: decodeZones, render: renderZones})
	registerLoader(ec2Paged(loader{key: LoadKey{"ec2", "DescribeVpcs"}, table: "ec2_vpcs",
		decode: decodeVpcs, render: renderVpcs}))
	registerLoader(loader{key: LoadKey{"ec2", "DescribeVpcAttribute"}, table: "ec2_vpcs",
		decode: decodeVpcAttribute, render: renderVpcAttribute})
	registerLoader(ec2Paged(loader{key: LoadKey{"ec2", "DescribeSubnets"}, table: "ec2_subnets",
		decode: decodeSubnets, render: renderSubnets}))
	registerLoader(ec2Paged(loader{key: LoadKey{"ec2", "DescribeInternetGateways"}, table: "ec2_internet_gateways",
		decode: decodeIgws, render: renderIgws}))
	// Elements a current answer carries that the provider never reads:
	// VPC Block Public Access states (2024), a subnet's type (EVS), a
	// subnet IPv6 block's source and address attribute (only
	// aws_vpc_ipv6_cidr_block_association reads them, from the VPC's
	// block), and a zone's long name, geography and messages.
	vpcs, subnets, zones := LoadKey{"ec2", "DescribeVpcs"}, LoadKey{"ec2", "DescribeSubnets"}, LoadKey{"ec2", "DescribeAvailabilityZones"}
	registerIgnores(
		IgnoreEntry{Key: vpcs, Path: "vpcSet/item/blockPublicAccessStates", Cite: vpcCite},
		IgnoreEntry{Key: subnets, Path: "subnetSet/item/blockPublicAccessStates", Cite: subnetCite},
		IgnoreEntry{Key: subnets, Path: "subnetSet/item/type", Cite: subnetCite},
		IgnoreEntry{Key: subnets, Path: "subnetSet/item/ipv6CidrBlockAssociationSet/item/ipSource", Cite: subnetCite},
		IgnoreEntry{Key: subnets, Path: "subnetSet/item/ipv6CidrBlockAssociationSet/item/ipv6AddressAttribute", Cite: subnetCite},
		IgnoreEntry{Key: zones, Path: "availabilityZoneInfo/item/groupLongName", Cite: azCite},
		IgnoreEntry{Key: zones, Path: "availabilityZoneInfo/item/geographySet", Cite: azCite},
		IgnoreEntry{Key: zones, Path: "availabilityZoneInfo/item/subGeographySet", Cite: azCite},
		IgnoreEntry{Key: zones, Path: "availabilityZoneInfo/item/messageSet", Cite: azCite},
	)
}

// decodeEC2 decodes ex's body into v, refusing one that does not decode
// without quoting it: the decoder's error can.
func decodeEC2(ex *loadExchange, v any) error {
	if err := xml.Unmarshal([]byte(ex.Body), v); err != nil {
		return loadRefusal("its body does not decode as " + ex.Action + "'s answer")
	}
	return nil
}

// ec2Body is the body awsproto.WriteEC2QueryRPCResponse answers.
func ec2Body(action string, payload any) []byte {
	var w bodyWriter
	awsproto.WriteEC2QueryRPCResponse(&w, action, payload)
	return w.Bytes()
}

// bodyWriter is an http.ResponseWriter that keeps only the body.
type bodyWriter struct {
	bytes.Buffer
	header http.Header
}

func (w *bodyWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *bodyWriter) WriteHeader(int) {}

// ec2TagsFromXML is a tagSet as the tags of ref's row, whose type is
// EC2's resourceType.
func ec2TagsFromXML(ref loadRef, set []ec2ResourceTagXML) []repository.EC2Tag {
	out := make([]repository.EC2Tag, len(set))
	for i, t := range set {
		out[i] = repository.EC2Tag{ResourceID: ref.ID, ResourceType: ref.Type, Key: t.Key, Value: t.Value}
	}
	return out
}

// ec2TagSet reads the stored tags of id back as a tagSet.
func ec2TagSet(tx *repository.LoadTx, id string) ([]ec2ResourceTagXML, error) {
	tags, err := tx.Tags(id)
	if err != nil {
		return nil, err
	}
	var out []ec2ResourceTagXML
	for _, t := range tags {
		out = append(out, ec2ResourceTagXML{Key: t.Key, Value: t.Value})
	}
	return out, nil
}

// ec2Write is an item's write: its row through put, then its tags.
func ec2Write(env *loadEnvelope, tags []repository.EC2Tag, put func(tx *repository.LoadTx) error) func(tx *repository.LoadTx) error {
	return func(tx *repository.LoadTx) error {
		if err := put(tx); err != nil {
			return err
		}
		return tx.PutTags(env.Account, env.Region, tags)
	}
}

// ----- Availability zones -----

func decodeZones(env *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
	var body ec2DescribeAvailabilityZonesResult
	if err := decodeEC2(ex, &body); err != nil {
		return nil, err
	}
	items := make([]loadItem, len(body.AvailabilityZoneInfo))
	for i, x := range body.AvailabilityZoneInfo {
		z := repository.AvailabilityZone{
			Region: env.Region, ZoneName: x.ZoneName, ZoneID: x.ZoneId, State: x.ZoneState, OptInStatus: x.OptInStatus,
			ZoneType: x.ZoneType, GroupName: x.GroupName, NetworkBorderGroup: x.NetworkBorderGroup,
		}
		items[i] = loadItem{loadRef: loadRef{"availability-zone", x.ZoneName}, Path: "availabilityZoneInfo/item", Index: i,
			write: func(tx *repository.LoadTx) error { return tx.PutAvailabilityZone(env.Account, z) }}
	}
	return items, nil
}

func renderZones(tx *repository.LoadTx, ids []string) ([]byte, error) {
	out := ec2DescribeAvailabilityZonesResult{AvailabilityZoneInfo: []ec2AvailabilityZoneXML{}}
	for _, name := range ids {
		z, err := tx.AvailabilityZone(name)
		if err != nil {
			return nil, err
		}
		out.AvailabilityZoneInfo = append(out.AvailabilityZoneInfo, ec2ZoneToXML(*z, z.ZoneID))
	}
	return ec2Body("DescribeAvailabilityZones", &out), nil
}

// ----- VPCs -----

// decodeVpcs loads each VPC with its tags. A VPC references its two
// DNS attributes, so one whose DescribeVpcAttribute answers were not
// recorded is refused rather than given values, and its DHCP options,
// which the reader never reads.
func decodeVpcs(env *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
	var body ec2DescribeVpcsResult
	if err := decodeEC2(ex, &body); err != nil {
		return nil, err
	}
	items := make([]loadItem, len(body.VpcSet))
	for i, x := range body.VpcSet {
		v := ec2VpcFromXML(x, env.Region)
		var refs []loadReference
		for _, attr := range ec2VpcDNSAttributes {
			refs = append(refs, loadReference{loadRef: loadRef{"vpc-attribute", vpcAttributeID(x.VpcId, attr)}})
		}
		if x.DhcpOptionsId != "" {
			refs = append(refs, loadReference{loadRef: loadRef{"dhcp-options", x.DhcpOptionsId}, Unread: true})
		}
		ref := loadRef{"vpc", x.VpcId}
		items[i] = loadItem{loadRef: ref, Path: "vpcSet/item", Index: i, Refs: refs,
			write: ec2Write(env, ec2TagsFromXML(ref, x.TagSet),
				func(tx *repository.LoadTx) error { return tx.PutVPC(env.Account, v) })}
	}
	return items, nil
}

// ec2VpcFromXML is the VPC x answers, its DNS attributes unset until
// its DescribeVpcAttribute answers load. No ARN or creation time: the
// answer holds neither.
func ec2VpcFromXML(x ec2VpcXML, region string) *repository.EC2VPC {
	v := &repository.EC2VPC{
		ID: x.VpcId, CidrBlock: x.CidrBlock, Region: region, State: x.State, OwnerID: x.OwnerId,
		IsDefault: x.IsDefault, DhcpOptionsID: x.DhcpOptionsId, InstanceTenancy: x.InstanceTenancy,
	}
	for _, a := range x.CidrBlockAssociationSet {
		v.CidrBlockAssociations = append(v.CidrBlockAssociations, repository.EC2CidrBlockAssociation{
			AssociationID: a.AssociationId, CidrBlock: a.CidrBlock, State: a.CidrBlockState.State, StatusMessage: a.CidrBlockState.StatusMessage,
		})
	}
	for _, a := range x.Ipv6CidrBlockAssociationSet {
		v.Ipv6CidrBlockAssociations = append(v.Ipv6CidrBlockAssociations, repository.EC2CidrBlockAssociation{
			AssociationID: a.AssociationId, CidrBlock: a.Ipv6CidrBlock, State: a.CidrBlockState.State, StatusMessage: a.CidrBlockState.StatusMessage,
			Ipv6Pool: a.Ipv6Pool, NetworkBorderGroup: a.NetworkBorderGroup, IPSource: a.IpSource, Ipv6AddressAttribute: a.Ipv6AddressAttribute,
		})
	}
	return v
}

func renderVpcs(tx *repository.LoadTx, ids []string) ([]byte, error) {
	out := ec2DescribeVpcsResult{VpcSet: []ec2VpcXML{}}
	for _, id := range ids {
		v, err := tx.VPC(id)
		if err != nil {
			return nil, err
		}
		x := ec2VpcToXML(v)
		if x.TagSet, err = ec2TagSet(tx, id); err != nil {
			return nil, err
		}
		out.VpcSet = append(out.VpcSet, x)
	}
	return ec2Body("DescribeVpcs", &out), nil
}

// vpcAttributeID names a VPC's attribute as a row: <vpc id>/<attribute>.
func vpcAttributeID(vpcID, attr string) string { return vpcID + "/" + attr }

// ec2VpcAttributeAnswer is a DescribeVpcAttribute answer: its vpcId,
// and each other element with its value.
type ec2VpcAttributeAnswer struct {
	VpcId  string `xml:"vpcId"`
	Values []struct {
		XMLName xml.Name
		Value   bool `xml:"value"`
	} `xml:",any"`
}

// decodeVpcAttribute sets the stored VPC's attributes of
// ec2VpcDNSAttributes the answer holds, refusing an answer that holds
// none and a VPC no exchange loaded.
func decodeVpcAttribute(env *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
	var body ec2VpcAttributeAnswer
	if err := decodeEC2(ex, &body); err != nil {
		return nil, err
	}
	var items []loadItem
	for _, x := range body.Values {
		attr, on := x.XMLName.Local, x.Value
		if !slices.Contains(ec2VpcDNSAttributes, attr) {
			continue
		}
		items = append(items, loadItem{loadRef: loadRef{"vpc-attribute", vpcAttributeID(body.VpcId, attr)}, Path: attr,
			write: func(tx *repository.LoadTx) error {
				err := tx.UpdateVPC(body.VpcId, func(v *repository.EC2VPC) { *vpcDNS(v, attr) = on })
				if errors.Is(err, models.ErrNotFound) {
					return loadRefusal(fmt.Sprintf("vpc-attribute %s names vpc %s, which no exchange loaded", vpcAttributeID(body.VpcId, attr), body.VpcId))
				}
				return err
			}})
	}
	if len(items) == 0 {
		return nil, loadRefusal("it answers neither " + strings.Join(ec2VpcDNSAttributes, " nor "))
	}
	return items, nil
}

func renderVpcAttribute(tx *repository.LoadTx, ids []string) ([]byte, error) {
	vpcID, attr, _ := strings.Cut(ids[0], "/")
	v, err := tx.VPC(vpcID)
	if err != nil {
		return nil, err
	}
	out := ec2VpcAttribute(v, attr)
	return ec2Body("DescribeVpcAttribute", &out), nil
}

// ----- Subnets -----

// decodeSubnets loads each subnet with its tags, its recorded subnetArn
// as it is, refusing one whose VPC no exchange loaded.
func decodeSubnets(env *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
	var body ec2DescribeSubnetsResult
	if err := decodeEC2(ex, &body); err != nil {
		return nil, err
	}
	items := make([]loadItem, len(body.SubnetSet))
	for i, x := range body.SubnetSet {
		s := ec2SubnetFromXML(x, env.Region)
		ref := loadRef{"subnet", x.SubnetId}
		items[i] = loadItem{loadRef: ref, Path: "subnetSet/item", Index: i,
			write: ec2Write(env, ec2TagsFromXML(ref, x.TagSet), func(tx *repository.LoadTx) error {
				err := tx.PutSubnet(env.Account, s)
				if errors.Is(err, models.ErrNotFound) {
					return loadRefusal(fmt.Sprintf("subnet %s names vpc %s, which no exchange loaded", s.ID, s.VPCID))
				}
				return err
			})}
	}
	return items, nil
}

// ec2SubnetFromXML is the subnet x answers. Its availabilityZoneId is
// not stored: the subnet answers its zone's (ec2Zones).
func ec2SubnetFromXML(x ec2SubnetXML, region string) *repository.EC2Subnet {
	s := &repository.EC2Subnet{
		ID: x.SubnetId, VPCID: x.VpcId, CidrBlock: x.CidrBlock, AvailabilityZone: x.AvailabilityZone, Region: region,
		ARN: x.SubnetArn, State: x.State, MapPublicIPOnLaunch: x.MapPublicIpOnLaunch, OwnerID: x.OwnerId,
		AvailableIPAddressCount: x.AvailableIpAddressCount, DefaultForAz: x.DefaultForAz,
		AssignIpv6AddressOnCreation: x.AssignIpv6AddressOnCreation, MapCustomerOwnedIPOnLaunch: x.MapCustomerOwnedIpOnLaunch,
		EnableDNS64: x.EnableDns64, Ipv6Native: x.Ipv6Native, EnableLniAtDeviceIndex: x.EnableLniAtDeviceIndex,
		CustomerOwnedIpv4Pool: x.CustomerOwnedIpv4Pool, OutpostARN: x.OutpostArn,
	}
	for _, a := range x.Ipv6CidrBlockAssociationSet {
		s.Ipv6CidrBlockAssociations = append(s.Ipv6CidrBlockAssociations, repository.EC2CidrBlockAssociation{
			AssociationID: a.AssociationId, CidrBlock: a.Ipv6CidrBlock, State: a.CidrBlockState.State, StatusMessage: a.CidrBlockState.StatusMessage,
		})
	}
	if o := x.PrivateDnsNameOptionsOnLaunch; o != nil {
		s.PrivateDNSNameOptionsOnLaunch = &repository.EC2PrivateDNSNameOptions{
			HostnameType: o.HostnameType, EnableResourceNameDNSARecord: o.EnableResourceNameDnsARecord,
			EnableResourceNameDNSAAAARecord: o.EnableResourceNameDnsAAAARecord,
		}
	}
	return s
}

func renderSubnets(tx *repository.LoadTx, ids []string) ([]byte, error) {
	out := ec2DescribeSubnetsResult{SubnetSet: []ec2SubnetXML{}}
	for _, id := range ids {
		s, err := tx.Subnet(id)
		if err != nil {
			return nil, err
		}
		zoneID := ""
		z, err := tx.AvailabilityZone(s.AvailabilityZone)
		switch {
		case err == nil:
			zoneID = z.ZoneID
		case !errors.Is(err, models.ErrNotFound):
			return nil, err
		}
		x := ec2SubnetToXML(s, func(string) string { return zoneID })
		if x.TagSet, err = ec2TagSet(tx, id); err != nil {
			return nil, err
		}
		out.SubnetSet = append(out.SubnetSet, x)
	}
	return ec2Body("DescribeSubnets", &out), nil
}

// ----- Internet gateways -----

// decodeIgws loads each gateway with its tags, its attachment
// referencing the VPC it names. AWS attaches a gateway to one VPC at
// most; the rendering diff refuses a second attachment.
func decodeIgws(env *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
	var body ec2DescribeIgwsResult
	if err := decodeEC2(ex, &body); err != nil {
		return nil, err
	}
	items := make([]loadItem, len(body.InternetGatewaySet))
	for i, x := range body.InternetGatewaySet {
		igw := &repository.EC2InternetGateway{ID: x.InternetGatewayId, Region: env.Region, OwnerID: x.OwnerId}
		var refs []loadReference
		if len(x.Attachments) > 0 {
			igw.VPCID, igw.AttachmentState = x.Attachments[0].VpcId, x.Attachments[0].State
			refs = []loadReference{{loadRef: loadRef{"vpc", igw.VPCID}}}
		}
		ref := loadRef{"internet-gateway", x.InternetGatewayId}
		items[i] = loadItem{loadRef: ref, Path: "internetGatewaySet/item", Index: i, Refs: refs,
			write: ec2Write(env, ec2TagsFromXML(ref, x.TagSet),
				func(tx *repository.LoadTx) error { return tx.PutInternetGateway(env.Account, igw) })}
	}
	return items, nil
}

func renderIgws(tx *repository.LoadTx, ids []string) ([]byte, error) {
	out := ec2DescribeIgwsResult{InternetGatewaySet: []ec2IgwXML{}}
	for _, id := range ids {
		igw, err := tx.InternetGateway(id)
		if err != nil {
			return nil, err
		}
		x := ec2IgwToXML(igw)
		if x.TagSet, err = ec2TagSet(tx, id); err != nil {
			return nil, err
		}
		out.InternetGatewaySet = append(out.InternetGatewaySet, x)
	}
	return ec2Body("DescribeInternetGateways", &out), nil
}
