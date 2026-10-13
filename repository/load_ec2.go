package repository

// load_ec2.go — a load's typed writes and reads of EC2 rows, through
// LoadTx. A load holds one account's rows, so a read names a row by its
// id alone.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/redscaresu/fakeaws/models"
)

// PutVPC stores v under account.
func (lt *LoadTx) PutVPC(account string, v *EC2VPC) error { return insertVPC(lt, account, v) }

// PutSubnet stores s under account, or answers models.ErrNotFound when
// its VPC is not stored, which the subnet's foreign key would refuse.
func (lt *LoadTx) PutSubnet(account string, s *EC2Subnet) error {
	if err := lt.exists(`SELECT 1 FROM ec2_vpcs WHERE account_id = ? AND id = ?`, account, s.VPCID); err != nil {
		return err
	}
	return insertSubnet(lt, account, s)
}

// exists answers nil when query selects a row, else models.ErrNotFound
// or the query's failure.
func (lt *LoadTx) exists(query string, args ...any) error {
	var one int
	err := lt.QueryRow(query, args...).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return models.ErrNotFound
	}
	return err
}

// PutInternetGateway stores igw under account.
func (lt *LoadTx) PutInternetGateway(account string, igw *EC2InternetGateway) error {
	return insertInternetGateway(lt, account, igw)
}

// PutRouteTable stores rt under account, or answers models.ErrNotFound
// when its VPC is not stored, which its foreign key would refuse.
func (lt *LoadTx) PutRouteTable(account string, rt *EC2RouteTable) error {
	if err := lt.exists(`SELECT 1 FROM ec2_vpcs WHERE account_id = ? AND id = ?`, account, rt.VPCID); err != nil {
		return err
	}
	return insertRouteTable(lt, account, rt)
}

// PutRoute stores r under account; its route table must be stored.
func (lt *LoadTx) PutRoute(account string, r *EC2Route) error { return insertRoute(lt, account, r) }

// ErrSecondMain refuses a main association of a VPC that has one.
var ErrSecondMain = fmt.Errorf("%w: the VPC already has a main route table association", models.ErrConflict)

// PutRouteTableAssociation stores a under account, in route table
// vpcID's VPC, whose row must be stored. It answers models.ErrNotFound
// when a's subnet is not stored, and ErrSecondMain when a is main and
// the VPC has a main association, which the subnet's foreign key and
// the one-main index would refuse.
func (lt *LoadTx) PutRouteTableAssociation(account, vpcID string, a *EC2RouteTableAssociation) error {
	if a.SubnetID != "" {
		if err := lt.exists(`SELECT 1 FROM ec2_subnets WHERE account_id = ? AND id = ?`, account, a.SubnetID); err != nil {
			return err
		}
	}
	if a.Main {
		err := lt.exists(`SELECT 1 FROM ec2_route_table_associations WHERE account_id = ? AND vpc_id = ? AND main = 1`, account, vpcID)
		switch {
		case err == nil:
			return ErrSecondMain
		case !errors.Is(err, models.ErrNotFound):
			return err
		}
	}
	return insertAssociation(lt, account, vpcID, a)
}

// PutSecurityGroup stores sg under account, or answers
// models.ErrNotFound when its VPC is not stored, which its foreign key
// would refuse.
func (lt *LoadTx) PutSecurityGroup(account string, sg *EC2SecurityGroup) error {
	if err := lt.exists(`SELECT 1 FROM ec2_vpcs WHERE account_id = ? AND id = ?`, account, sg.VPCID); err != nil {
		return err
	}
	return insertSecurityGroup(lt, account, sg)
}

// ErrSourceHeld refuses a rule whose source its permission already
// holds under another rule.
var ErrSourceHeld = fmt.Errorf("%w: the permission already holds the rule's source", models.ErrConflict)

// PutSecurityGroupRule stores rule under account and region after the
// group's rules stored before it, as AuthorizeSecurityGroupRules places
// one (ruleOrdinals), so rules stored in their recorded order keep it.
// It answers models.ErrNotFound when the rule's group is not stored,
// which its foreign key would refuse, and ErrSourceHeld when a stored
// rule of its permission holds its source, which AWS never answers.
func (lt *LoadTx) PutSecurityGroupRule(account, region string, rule EC2SecurityGroupRule) error {
	if err := lt.exists(`SELECT 1 FROM ec2_security_groups WHERE account_id = ? AND id = ?`, account, rule.GroupID); err != nil {
		return err
	}
	var held bool
	if err := lt.QueryRow(ruleOrdinals, ruleMatchArgs(account, rule)...).Scan(&rule.PermOrd, &rule.SrcOrd, &held); err != nil {
		return err
	}
	if held {
		return ErrSourceHeld
	}
	return insertRule(lt, account, region, rule)
}

// ErrNoSubnet refuses a network interface whose subnet is not stored.
var ErrNoSubnet = fmt.Errorf("%w: the network interface's subnet is not stored", models.ErrNotFound)

// PutNetworkInterface stores eni under account. It answers ErrNoSubnet
// when its subnet is not stored, and models.ErrNotFound when it is
// attached to an instance that is not stored, which its foreign keys
// would refuse.
func (lt *LoadTx) PutNetworkInterface(account string, eni *EC2NetworkInterface) error {
	if err := lt.exists(`SELECT 1 FROM ec2_subnets WHERE account_id = ? AND id = ?`, account, eni.SubnetID); err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return ErrNoSubnet
		}
		return err
	}
	if eni.InstanceID != "" {
		if err := lt.exists(`SELECT 1 FROM ec2_instances WHERE account_id = ? AND id = ?`, account, eni.InstanceID); err != nil {
			return err
		}
	}
	return insertENI(lt, account, eni)
}

// PutEIP stores eip under account with its association, if any.
func (lt *LoadTx) PutEIP(account string, eip *EC2EIP) error { return insertEIP(lt, account, eip) }

// PutKeyPair stores kp under account.
func (lt *LoadTx) PutKeyPair(account string, kp *EC2KeyPair) error {
	return insertKeyPair(lt, account, kp)
}

// PutAvailabilityZone stores z under account.
func (lt *LoadTx) PutAvailabilityZone(account string, z AvailabilityZone) error {
	return putAvailabilityZone(lt, account, z)
}

// PutTags stores tags under account and region.
func (lt *LoadTx) PutTags(account, region string, tags []EC2Tag) error {
	return putTags(lt, account, region, tags)
}

// UpdateVPC applies change to the stored VPC id and saves it, or
// answers models.ErrNotFound when there is none.
func (lt *LoadTx) UpdateVPC(id string, change func(*EC2VPC)) error {
	v, err := lt.VPC(id)
	if err != nil {
		return err
	}
	change(v)
	body, _ := json.Marshal(v)
	_, err = lt.Exec(`UPDATE ec2_vpcs SET data = ? WHERE id = ?`, string(body), id)
	return err
}

// VPC reads the stored VPC id.
func (lt *LoadTx) VPC(id string) (*EC2VPC, error) {
	var v EC2VPC
	if err := lt.data(&v, `SELECT data FROM ec2_vpcs WHERE id = ?`, id); err != nil {
		return nil, err
	}
	return &v, nil
}

// Subnet reads the stored subnet id.
func (lt *LoadTx) Subnet(id string) (*EC2Subnet, error) {
	var s EC2Subnet
	if err := lt.data(&s, `SELECT data FROM ec2_subnets WHERE id = ?`, id); err != nil {
		return nil, err
	}
	return &s, nil
}

// InternetGateway reads the stored gateway id, attached to its vpc_id
// column's VPC, as GetInternetGateway reads it.
func (lt *LoadTx) InternetGateway(id string) (*EC2InternetGateway, error) {
	var data string
	var vpcID sql.NullString
	err := lt.QueryRow(`SELECT data, vpc_id FROM ec2_internet_gateways WHERE id = ?`, id).Scan(&data, &vpcID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var igw EC2InternetGateway
	if err := json.Unmarshal([]byte(data), &igw); err != nil {
		return nil, err
	}
	igw.VPCID = vpcID.String
	return &igw, nil
}

// RouteTable reads the stored route table id.
func (lt *LoadTx) RouteTable(id string) (*EC2RouteTable, error) {
	var rt EC2RouteTable
	if err := lt.data(&rt, `SELECT data FROM ec2_route_tables WHERE id = ?`, id); err != nil {
		return nil, err
	}
	return &rt, nil
}

// Routes reads the stored routes of route table id, as ListRoutes
// orders them.
func (lt *LoadTx) Routes(id string) ([]*EC2Route, error) {
	var out []*EC2Route
	for scan, err := range lt.Query(`SELECT `+routeColumns+` FROM ec2_routes WHERE route_table_id = ? ORDER BY destination_cidr_block`, id) {
		if err != nil {
			return nil, err
		}
		r, err := scanRoute(scan)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// RouteTableAssociations reads the stored associations of route table
// id, as ListRouteTableAssociations orders them.
func (lt *LoadTx) RouteTableAssociations(id string) ([]*EC2RouteTableAssociation, error) {
	var out []*EC2RouteTableAssociation
	for scan, err := range lt.Query(`SELECT `+associationColumns+` FROM ec2_route_table_associations WHERE route_table_id = ? ORDER BY id`, id) {
		if err != nil {
			return nil, err
		}
		a, err := scanAssociation(scan)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// SecurityGroup reads the stored security group id.
func (lt *LoadTx) SecurityGroup(id string) (*EC2SecurityGroup, error) {
	var sg EC2SecurityGroup
	if err := lt.data(&sg, `SELECT data FROM ec2_security_groups WHERE id = ?`, id); err != nil {
		return nil, err
	}
	return &sg, nil
}

// SecurityGroupRules reads the stored rules of security group id, as
// ListSecurityGroupRules orders them.
func (lt *LoadTx) SecurityGroupRules(id string) ([]EC2SecurityGroupRule, error) {
	var out []EC2SecurityGroupRule
	for scan, err := range lt.Query(`SELECT `+ruleColumns+` FROM ec2_security_group_rules WHERE group_id = ? ORDER BY is_egress, perm_ord, src_ord`, id) {
		if err != nil {
			return nil, err
		}
		r, err := scanRule(scan)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// SecurityGroupRule reads the stored rule id.
func (lt *LoadTx) SecurityGroupRule(id string) (EC2SecurityGroupRule, error) {
	rule, err := scanRule(lt.QueryRow(`SELECT `+ruleColumns+` FROM ec2_security_group_rules WHERE id = ?`, id).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return rule, models.ErrNotFound
	}
	return rule, err
}

// NetworkInterface reads the stored network interface id.
func (lt *LoadTx) NetworkInterface(id string) (*EC2NetworkInterface, error) {
	var eni EC2NetworkInterface
	if err := lt.data(&eni, `SELECT data FROM ec2_network_interfaces WHERE id = ?`, id); err != nil {
		return nil, err
	}
	return &eni, nil
}

// EIP reads the stored address allocationID.
func (lt *LoadTx) EIP(allocationID string) (*EC2EIP, error) {
	var eip EC2EIP
	if err := lt.data(&eip, `SELECT data FROM ec2_eips WHERE allocation_id = ?`, allocationID); err != nil {
		return nil, err
	}
	return &eip, nil
}

// EIPOfNetworkInterface reads the stored address associated with
// network interface id, nil when there is none.
func (lt *LoadTx) EIPOfNetworkInterface(id string) (*EC2EIP, error) {
	var eip EC2EIP
	err := lt.data(&eip, `SELECT data FROM ec2_eips WHERE network_interface_id = ?`, id)
	if errors.Is(err, models.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &eip, nil
}

// KeyPair reads the stored key pair named name.
func (lt *LoadTx) KeyPair(name string) (*EC2KeyPair, error) {
	var kp EC2KeyPair
	if err := lt.data(&kp, `SELECT data FROM ec2_key_pairs WHERE name = ?`, name); err != nil {
		return nil, err
	}
	return &kp, nil
}

// AvailabilityZone reads the stored zone named name.
func (lt *LoadTx) AvailabilityZone(name string) (*AvailabilityZone, error) {
	var z AvailabilityZone
	err := lt.QueryRow(`SELECT region, zone_name, zone_id, state, opt_in_status, zone_type, group_name, network_border_group
		FROM availability_zones WHERE zone_name = ?`, name).
		Scan(&z.Region, &z.ZoneName, &z.ZoneID, &z.State, &z.OptInStatus, &z.ZoneType, &z.GroupName, &z.NetworkBorderGroup)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &z, nil
}

// Tags reads the stored tags of resource id, by key, as ListTags
// orders them.
func (lt *LoadTx) Tags(id string) ([]EC2Tag, error) {
	var out []EC2Tag
	for scan, err := range lt.Query(`SELECT resource_id, resource_type, key, value FROM ec2_tags WHERE resource_id = ? ORDER BY key`, id) {
		if err != nil {
			return nil, err
		}
		var t EC2Tag
		if err := scan(&t.ResourceID, &t.ResourceType, &t.Key, &t.Value); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// data decodes the one data column query selects into v, or answers
// models.ErrNotFound when it selects no row.
func (lt *LoadTx) data(v any, query string, args ...any) error {
	var data string
	err := lt.QueryRow(query, args...).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return models.ErrNotFound
	}
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(data), v)
}
