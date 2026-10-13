package handlers

// load_ec2_compute.go — the loaders of network interfaces, Elastic IPs
// and key pairs. A network interface may have no instance; one attached
// to an instance is refused until instances load. An interface's
// association with an address is the address's (ec2ENIToXML), so the
// rendering diff refuses an interface whose recorded association no
// loaded address holds.

import (
	"errors"
	"fmt"

	"github.com/redscaresu/fakeaws/models"
	"github.com/redscaresu/fakeaws/repository"
)

const eniCite = "terraform-provider-aws@v5.100.0/internal/service/ec2/vpc_network_interface.go"

func init() {
	registerLoader(loader{key: LoadKey{"ec2", "DescribeNetworkInterfaces"}, table: "ec2_network_interfaces",
		requestToken: "NextToken", responseToken: "nextToken",
		decode: decodeNetworkInterfaces, render: renderNetworkInterfaces})
	registerLoader(loader{key: LoadKey{"ec2", "DescribeAddresses"}, table: "ec2_eips",
		decode: decodeAddresses, render: renderAddresses})
	registerLoader(loader{key: LoadKey{"ec2", "DescribeKeyPairs"}, table: "ec2_key_pairs",
		decode: decodeKeyPairs, render: renderKeyPairs})
	// A group's name beside its id: the interface resource and data
	// source read security_groups through flattenGroupIdentifiers, which
	// reads GroupId only.
	registerIgnores(IgnoreEntry{Key: LoadKey{"ec2", "DescribeNetworkInterfaces"}, Path: "networkInterfaceSet/item/groupSet/item/groupName", Cite: eniCite})
}

// decodeNetworkInterfaces loads each interface with its tags. It
// references its VPC and groups, and the address its association
// names; an amazon-owned public IP is held as the interface's own. One
// whose subnet, or the instance it is attached to, no exchange loaded is
// refused naming both.
func decodeNetworkInterfaces(env *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
	var body ec2DescribeNetworkInterfacesResult
	if err := decodeEC2(ex, &body); err != nil {
		return nil, err
	}
	items := make([]loadItem, len(body.NetworkInterfaceSet))
	for i, x := range body.NetworkInterfaceSet {
		eni := ec2ENIFromXML(x, env.Region)
		refs := []loadReference{{loadRef: loadRef{"vpc", x.VpcId}}}
		for _, g := range x.GroupSet {
			refs = append(refs, loadReference{loadRef: loadRef{"security-group", g.GroupId}})
		}
		if a := x.Association; a != nil && a.AllocationId != "" {
			refs = append(refs, loadReference{loadRef: loadRef{"elastic-ip", a.AllocationId}})
		}
		ref := loadRef{"network-interface", x.NetworkInterfaceId}
		items[i] = loadItem{loadRef: ref, Path: "networkInterfaceSet/item", Index: i, Refs: refs,
			write: ec2Write(env, ec2TagsFromXML(ref, x.TagSet), func(tx *repository.LoadTx) error {
				err := tx.PutNetworkInterface(env.Account, eni)
				switch {
				case errors.Is(err, repository.ErrNoSubnet):
					return loadRefusal(fmt.Sprintf("network-interface %s names subnet %s, which no exchange loaded", eni.ID, eni.SubnetID))
				case errors.Is(err, models.ErrNotFound):
					return loadRefusal(fmt.Sprintf("network-interface %s is attached to instance %s, which no exchange loaded", eni.ID, eni.InstanceID))
				}
				return err
			})}
	}
	return items, nil
}

// ec2ENIFromXML is the interface x answers.
func ec2ENIFromXML(x ec2NetworkInterfaceXML, region string) *repository.EC2NetworkInterface {
	eni := &repository.EC2NetworkInterface{
		ID: x.NetworkInterfaceId, SubnetID: x.SubnetId, VPCID: x.VpcId, PrivateIP: x.PrivateIpAddress,
		SourceDestCheck: x.SourceDestCheck, Region: region, SecurityGroupIDs: []string{},
		Description: x.Description, MacAddress: x.MacAddress, PrivateDNSName: x.PrivateDnsName,
		AvailabilityZone: x.AvailabilityZone, RequesterManaged: x.RequesterManaged, InterfaceType: x.InterfaceType,
		OwnerID: x.OwnerId, Status: x.Status,
	}
	for _, g := range x.GroupSet {
		eni.SecurityGroupIDs = append(eni.SecurityGroupIDs, g.GroupId)
	}
	if a := x.Attachment; a != nil {
		eni.InstanceID, eni.AttachmentID = a.InstanceId, a.AttachmentId
	}
	if a := x.Association; a != nil {
		eni.PublicIP = a.PublicIp
	}
	for _, ip := range x.PrivateIpAddressesSet {
		eni.PrivateIPAddresses = append(eni.PrivateIPAddresses,
			repository.EC2PrivateIPAddress{Address: ip.PrivateIpAddress, Primary: ip.Primary, PrivateDNSName: ip.PrivateDnsName})
	}
	return eni
}

func renderNetworkInterfaces(tx *repository.LoadTx, ids []string) ([]byte, error) {
	account, err := tx.Account()
	if err != nil {
		return nil, err
	}
	out := ec2DescribeNetworkInterfacesResult{NetworkInterfaceSet: []ec2NetworkInterfaceXML{}}
	for _, id := range ids {
		eni, err := tx.NetworkInterface(id)
		if err != nil {
			return nil, err
		}
		eip, err := tx.EIPOfNetworkInterface(id)
		if err != nil {
			return nil, err
		}
		x := ec2ENIToXML(account, eni, eip)
		if x.TagSet, err = ec2TagSet(tx, id); err != nil {
			return nil, err
		}
		out.NetworkInterfaceSet = append(out.NetworkInterfaceSet, x)
	}
	return ec2Body("DescribeNetworkInterfaces", &out), nil
}

// decodeAddresses loads each address with its tags and its
// association, which references the interface and the instance it
// names. No allocation time: the answer holds none.
func decodeAddresses(env *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
	var body ec2DescribeAddressesResult
	if err := decodeEC2(ex, &body); err != nil {
		return nil, err
	}
	items := make([]loadItem, len(body.AddressSet))
	for i, x := range body.AddressSet {
		eip := &repository.EC2EIP{
			AllocationID: x.AllocationId, Domain: x.Domain, PublicIP: x.PublicIp, AssociationID: x.AssociationId,
			NetworkInterfaceID: x.NetworkInterfaceId, InstanceID: x.InstanceId, PrivateIP: x.PrivateIpAddress,
			PublicIPv4Pool: x.PublicIpv4Pool, NetworkBorderGroup: x.NetworkBorderGroup, Region: env.Region,
		}
		var refs []loadReference
		if x.NetworkInterfaceId != "" {
			refs = append(refs, loadReference{loadRef: loadRef{"network-interface", x.NetworkInterfaceId}})
		}
		if x.InstanceId != "" {
			refs = append(refs, loadReference{loadRef: loadRef{"instance", x.InstanceId}})
		}
		ref := loadRef{"elastic-ip", x.AllocationId}
		items[i] = loadItem{loadRef: ref, Path: "addressesSet/item", Index: i, Refs: refs,
			write: ec2Write(env, ec2TagsFromXML(ref, x.TagSet),
				func(tx *repository.LoadTx) error { return tx.PutEIP(env.Account, eip) })}
	}
	return items, nil
}

func renderAddresses(tx *repository.LoadTx, ids []string) ([]byte, error) {
	account, err := tx.Account()
	if err != nil {
		return nil, err
	}
	out := ec2DescribeAddressesResult{AddressSet: []ec2AddressXML{}}
	for _, id := range ids {
		eip, err := tx.EIP(id)
		if err != nil {
			return nil, err
		}
		tags, err := ec2TagSet(tx, id)
		if err != nil {
			return nil, err
		}
		out.AddressSet = append(out.AddressSet, ec2AddressToXML(account, eip, tags))
	}
	return ec2Body("DescribeAddresses", &out), nil
}

// decodeKeyPairs loads each key pair by name, with its tags under its
// keyPairId, its keyType, its createTime as created_at, and the
// publicKey an IncludePublicKey read answers, which it then always
// renders.
func decodeKeyPairs(env *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
	var body ec2DescribeKeyPairsResult
	if err := decodeEC2(ex, &body); err != nil {
		return nil, err
	}
	items := make([]loadItem, len(body.KeySet))
	for i, x := range body.KeySet {
		kp := &repository.EC2KeyPair{ID: x.KeyPairId, Name: x.KeyName, KeyType: x.KeyType, PublicKey: x.PublicKey,
			Fingerprint: x.KeyFingerprint, Region: env.Region, CreatedAt: x.CreateTime}
		items[i] = loadItem{loadRef: loadRef{"key-pair", x.KeyName}, Path: "keySet/item", Index: i,
			write: ec2Write(env, ec2TagsFromXML(loadRef{"key-pair", x.KeyPairId}, x.TagSet),
				func(tx *repository.LoadTx) error { return tx.PutKeyPair(env.Account, kp) })}
	}
	return items, nil
}

func renderKeyPairs(tx *repository.LoadTx, names []string) ([]byte, error) {
	out := ec2DescribeKeyPairsResult{KeySet: []ec2KeyPairXML{}}
	for _, name := range names {
		kp, err := tx.KeyPair(name)
		if err != nil {
			return nil, err
		}
		x := ec2KeyPairToXML(kp, nil)
		x.PublicKey = kp.PublicKey
		if x.TagSet, err = ec2TagSet(tx, kp.ID); err != nil {
			return nil, err
		}
		out.KeySet = append(out.KeySet, x)
	}
	return ec2Body("DescribeKeyPairs", &out), nil
}
