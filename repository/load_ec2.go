package repository

// load_ec2.go — a load's typed writes and reads of EC2 rows, through
// LoadTx. A load holds one account's rows, so a read names a row by its
// id alone.

import (
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/redscaresu/fakeaws/models"
)

// PutVPC stores v under account.
func (lt *LoadTx) PutVPC(account string, v *EC2VPC) error { return insertVPC(lt, account, v) }

// PutSubnet stores s under account, or answers models.ErrNotFound when
// its VPC is not stored, which the subnet's foreign key would refuse.
func (lt *LoadTx) PutSubnet(account string, s *EC2Subnet) error {
	var one int
	err := lt.QueryRow(`SELECT 1 FROM ec2_vpcs WHERE account_id = ? AND id = ?`, account, s.VPCID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return models.ErrNotFound
	}
	if err != nil {
		return err
	}
	return insertSubnet(lt, account, s)
}

// PutInternetGateway stores igw under account.
func (lt *LoadTx) PutInternetGateway(account string, igw *EC2InternetGateway) error {
	return insertInternetGateway(lt, account, igw)
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
