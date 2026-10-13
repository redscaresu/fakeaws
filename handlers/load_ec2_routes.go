package handlers

// load_ec2_routes.go — the loader of route tables: each with its tags,
// its routes (the local one as recorded) and its associations under
// their recorded ids, a main association with no subnet.

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/redscaresu/fakeaws/models"
	"github.com/redscaresu/fakeaws/repository"
)

func init() {
	registerLoader(loader{key: LoadKey{"ec2", "DescribeRouteTables"}, table: "ec2_route_tables",
		requestToken: "NextToken", responseToken: "nextToken",
		decode: decodeRouteTables, render: renderRouteTables})
}

// decodeRouteTables loads each route table with its tags, routes and
// associations, referencing each route's target.
func decodeRouteTables(env *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
	var body ec2DescribeRouteTablesResult
	if err := decodeEC2(ex, &body); err != nil {
		return nil, err
	}
	items := make([]loadItem, len(body.RouteTableSet))
	for i, x := range body.RouteTableSet {
		ref := loadRef{"route-table", x.RouteTableId}
		items[i] = loadItem{loadRef: ref, Path: "routeTableSet/item", Index: i, Refs: routeTargets(x.Routes),
			write: ec2Write(env, ec2TagsFromXML(ref, x.TagSet),
				func(tx *repository.LoadTx) error { return putRouteTable(tx, env, x) })}
	}
	return items, nil
}

// routeTargets are the rows routes target, each once. An internet
// gateway must be loaded, unless its route is blackhole: AWS keeps the
// route of a deleted gateway, which no recording can hold. Every other
// target is named unresolved, as no loader loads it yet: a blackhole
// route's gateway, a NAT gateway, instance or network interface, and any
// other gatewayId (vgw-, vpce-, ...) as a "gateway". The local route's
// "local" references nothing.
func routeTargets(routes []ec2RouteXML) []loadReference {
	var refs []loadReference
	add := func(typ, id string, unread bool) {
		ref := loadReference{loadRef: loadRef{typ, id}, Unread: unread}
		if id != "" && !slices.Contains(refs, ref) {
			refs = append(refs, ref)
		}
	}
	for _, r := range routes {
		switch {
		case r.GatewayId == "local":
		case strings.HasPrefix(r.GatewayId, "igw-"):
			add("internet-gateway", r.GatewayId, r.State == "blackhole")
		default:
			add("gateway", r.GatewayId, true)
		}
		add("nat-gateway", r.NatGatewayId, true)
		add("instance", r.InstanceId, true)
		add("network-interface", r.NetworkInterfaceId, true)
	}
	return refs
}

// putRouteTable stores x, then its routes and associations, refusing a
// route table whose VPC no exchange loaded, a route with no IPv4
// destination (an IPv6 or prefix-list route, which fakeaws cannot
// hold), an association whose subnet no exchange loaded, and a second
// main association of one VPC.
func putRouteTable(tx *repository.LoadTx, env *loadEnvelope, x ec2RouteTableXML) error {
	rt := &repository.EC2RouteTable{ID: x.RouteTableId, VPCID: x.VpcId, Region: env.Region, OwnerID: x.OwnerId}
	err := tx.PutRouteTable(env.Account, rt)
	if errors.Is(err, models.ErrNotFound) {
		return loadRefusal(fmt.Sprintf("route-table %s names vpc %s, which no exchange loaded", rt.ID, rt.VPCID))
	}
	if err != nil {
		return err
	}
	for _, r := range x.Routes {
		if r.DestinationCidrBlock == "" {
			return loadRefusal(fmt.Sprintf("route-table %s holds a route with no destinationCidrBlock, which fakeaws cannot hold", rt.ID))
		}
		if err := tx.PutRoute(env.Account, &repository.EC2Route{
			RouteTableID: rt.ID, DestinationCidrBlock: r.DestinationCidrBlock, GatewayID: r.GatewayId, NatGatewayID: r.NatGatewayId,
			InstanceID: r.InstanceId, NetworkInterfaceID: r.NetworkInterfaceId, Origin: r.Origin, State: r.State,
		}); err != nil {
			return err
		}
	}
	for _, a := range x.Associations {
		assoc := &repository.EC2RouteTableAssociation{ID: a.AssociationId, RouteTableID: rt.ID, SubnetID: a.SubnetId, Main: a.Main}
		if a.AssociationState != nil {
			assoc.State = a.AssociationState.State
		}
		err := tx.PutRouteTableAssociation(env.Account, rt.VPCID, assoc)
		switch {
		case errors.Is(err, repository.ErrSecondMain):
			return loadRefusal(fmt.Sprintf("route-table %s: association %s is a second main association of vpc %s", rt.ID, assoc.ID, rt.VPCID))
		case errors.Is(err, models.ErrNotFound):
			return loadRefusal(fmt.Sprintf("route-table %s: association %s names subnet %s, which no exchange loaded", rt.ID, assoc.ID, assoc.SubnetID))
		case err != nil:
			return err
		}
	}
	return nil
}

func renderRouteTables(tx *repository.LoadTx, ids []string) ([]byte, error) {
	out := ec2DescribeRouteTablesResult{RouteTableSet: []ec2RouteTableXML{}}
	for _, id := range ids {
		rt, err := tx.RouteTable(id)
		if err != nil {
			return nil, err
		}
		routes, err := tx.Routes(id)
		if err != nil {
			return nil, err
		}
		assocs, err := tx.RouteTableAssociations(id)
		if err != nil {
			return nil, err
		}
		tags, err := ec2TagSet(tx, id)
		if err != nil {
			return nil, err
		}
		out.RouteTableSet = append(out.RouteTableSet, ec2RouteTableToXML(rt, routes, assocs, tags))
	}
	return ec2Body("DescribeRouteTables", &out), nil
}
