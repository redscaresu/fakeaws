package handlers

// load_ec2_compute.go — the loaders of instances and their attributes,
// network interfaces, Elastic IPs, key pairs and volumes. A network interface may
// have no instance; one attached to an instance no exchange loaded is
// refused. An interface's association with an address is the address's
// (ec2ENIToXML), so the rendering diff refuses an interface whose
// recorded association no loaded address holds.

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/redscaresu/fakeaws/handlers/awsproto"
	"github.com/redscaresu/fakeaws/models"
	"github.com/redscaresu/fakeaws/repository"
)

// The provider files whose reads the ignore entries cite: aws_instance's
// and aws_network_interface's.
const (
	instanceCite = "terraform-provider-aws@v5.100.0/internal/service/ec2/ec2_instance.go"
	eniCite      = "terraform-provider-aws@v5.100.0/internal/service/ec2/vpc_network_interface.go"
)

// ec2InstanceReadAttributes are the DescribeInstanceAttribute answers
// terraform-provider-aws 5.100.0 reads an aws_instance by
// (resourceInstanceRead and readInstanceShutdownBehavior): a loaded
// instance references each, so one the recording lacks is refused
// rather than given AWS's default.
var ec2InstanceReadAttributes = []string{"instanceInitiatedShutdownBehavior", "disableApiStop", "disableApiTermination", "userData"}

// instanceItemPath is where a DescribeInstances answer holds an instance.
const instanceItemPath = "reservationSet/item/instancesSet/item"

func init() {
	registerLoader(loader{key: LoadKey{"ec2", "DescribeInstances"}, table: "ec2_instances",
		requestToken: "NextToken", responseToken: "nextToken",
		decode: decodeInstances, render: renderInstances})
	registerLoader(loader{key: LoadKey{"ec2", "DescribeInstanceAttribute"}, table: "ec2_instances",
		decode: decodeInstanceAttribute, render: renderInstanceAttribute})
	registerLoader(loader{key: LoadKey{"ec2", "DescribeNetworkInterfaces"}, table: "ec2_network_interfaces",
		requestToken: "NextToken", responseToken: "nextToken",
		decode: decodeNetworkInterfaces, render: renderNetworkInterfaces})
	registerLoader(loader{key: LoadKey{"ec2", "DescribeAddresses"}, table: "ec2_eips",
		decode: decodeAddresses, render: renderAddresses})
	registerLoader(loader{key: LoadKey{"ec2", "DescribeKeyPairs"}, table: "ec2_key_pairs",
		decode: decodeKeyPairs, render: renderKeyPairs})
	registerLoader(loader{key: LoadKey{"ec2", "DescribeVolumes"}, table: "ec2_volumes",
		typ: "volume", notFound: []string{ec2VolumeNotFound},
		requestToken: "NextToken", responseToken: "nextToken",
		decode: decodeVolumes, render: renderVolumes})
	// A group's name beside its id: the interface resource and data
	// source read security_groups through flattenGroupIdentifiers, which
	// reads GroupId only.
	enis, instances := LoadKey{"ec2", "DescribeNetworkInterfaces"}, LoadKey{"ec2", "DescribeInstances"}
	const instance = instanceItemPath + "/"
	registerIgnores(
		IgnoreEntry{Key: enis, Path: "networkInterfaceSet/item/groupSet/item/groupName", Cite: eniCite},
		// An attachment's time: flattenNetworkInterfaceAttachment reads
		// its id, device index and instance.
		IgnoreEntry{Key: enis, Path: "networkInterfaceSet/item/attachment/attachTime", Cite: eniCite},
		// What resourceInstanceRead never reads of an instance: its
		// launch index, product codes, state reason text, ENA support,
		// current boot mode and usage operation's update time; and of
		// its interfaces only the primary one's subnet, id, addresses,
		// source/dest check, association and attachment index and
		// deletion, so neither a group's name there nor the attach time.
		IgnoreEntry{Key: instances, Path: instance + "amiLaunchIndex", Cite: instanceCite},
		IgnoreEntry{Key: instances, Path: instance + "productCodes", Cite: instanceCite},
		IgnoreEntry{Key: instances, Path: instance + "reason", Cite: instanceCite},
		IgnoreEntry{Key: instances, Path: instance + "enaSupport", Cite: instanceCite},
		IgnoreEntry{Key: instances, Path: instance + "currentInstanceBootMode", Cite: instanceCite},
		IgnoreEntry{Key: instances, Path: instance + "usageOperationUpdateTime", Cite: instanceCite},
		IgnoreEntry{Key: instances, Path: instance + "networkInterfaceSet/item/groupSet/item/groupName", Cite: instanceCite},
		IgnoreEntry{Key: instances, Path: instance + "networkInterfaceSet/item/attachment/attachTime", Cite: instanceCite},
	)
}

// decodeInstances loads each instance with its tags under its
// reservation, the fields nothing else holds as recorded
// (ec2InstanceRecordedXML), and its profile's recorded ARN and id. It
// references its primary interface, whose fields in networkInterfaceSet
// must agree with the interface's own item; its key pair; each
// blockDeviceMapping volume; its ec2InstanceReadAttributes; and its
// image and profile, which the reader never reads. One whose subnet no
// exchange loaded is refused naming both.
func decodeInstances(env *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
	var body ec2DescribeInstancesResult
	if err := decodeEC2(ex, &body); err != nil {
		return nil, err
	}
	var items []loadItem
	nics := 0 // networkInterfaceSet items before this instance's, in document order
	for _, r := range body.ReservationSet {
		for _, x := range r.InstancesSet {
			inst, err := ec2InstanceFromXML(x, r.ReservationId, env)
			if err != nil {
				return nil, err
			}
			ref := loadRef{"instance", x.InstanceId}
			items = append(items, loadItem{loadRef: ref, Path: instanceItemPath, Index: len(items),
				Refs: ec2InstanceRefs(x, nics),
				write: ec2Write(env, ec2TagsFromXML(ref, x.TagSet), func(tx *repository.LoadTx) error {
					err := tx.PutInstance(env.Account, inst)
					if errors.Is(err, models.ErrNotFound) {
						return loadRefusal(fmt.Sprintf("instance %s names subnet %s, which no exchange loaded", inst.ID, inst.SubnetID))
					}
					return err
				})})
			nics += len(x.NetworkInterfaceSet)
		}
	}
	return items, nil
}

// ec2InstanceFromXML is the instance x answers in reservation r. Its
// attributes wait for its DescribeInstanceAttribute answers.
func ec2InstanceFromXML(x ec2InstanceXML, r string, env *loadEnvelope) (*repository.EC2Instance, error) {
	recorded, err := json.Marshal(x.ec2InstanceRecordedXML)
	if err != nil {
		return nil, err
	}
	inst := &repository.EC2Instance{
		ID: x.InstanceId, SubnetID: x.SubnetId, AMIID: x.ImageId, InstanceType: x.InstanceType, KeyName: x.KeyName,
		State: x.InstanceState.Name, Region: env.Region, ARN: awsproto.BuildEC2InstanceARN(env.Region, env.Account, x.InstanceId),
		CreatedAt: x.LaunchTime, ReservationID: r, Recorded: recorded,
		EC2InstanceAttributes: repository.EC2InstanceAttributes{EBSOptimized: x.EbsOptimized},
	}
	if p := x.IamProfile; p != nil {
		inst.IAMInstanceProfileName = ec2ProfileName(p.Arn)
		inst.IAMInstanceProfileARN, inst.IAMInstanceProfileID = p.Arn, p.Id
	}
	return inst, nil
}

// ec2ProfileName is the name of the instance profile arn names: its
// last segment, after any path.
func ec2ProfileName(arn string) string { return arn[strings.LastIndexByte(arn, '/')+1:] }

// ec2InstanceRefs are the rows instance x references; nics counts the
// networkInterfaceSet items its body holds before x's.
func ec2InstanceRefs(x ec2InstanceXML, nics int) []loadReference {
	refs := []loadReference{{loadRef: loadRef{"image", x.ImageId}, Unread: true}}
	if i := slices.IndexFunc(x.NetworkInterfaceSet, func(n ec2NetworkInterfaceXML) bool {
		return n.Attachment != nil && n.Attachment.DeviceIndex == 0
	}); i >= 0 {
		refs = append(refs, loadReference{loadRef: loadRef{"network-interface", x.NetworkInterfaceSet[i].NetworkInterfaceId},
			Path: instanceItemPath + "/networkInterfaceSet/item", Index: nics + i})
	}
	if x.KeyName != "" {
		refs = append(refs, loadReference{loadRef: loadRef{"key-pair", x.KeyName}})
	}
	if p := x.IamProfile; p != nil {
		refs = append(refs, loadReference{loadRef: loadRef{"instance-profile", ec2ProfileName(p.Arn)}, Unread: true})
	}
	for _, b := range x.BlockDeviceMapping {
		if b.Ebs != nil {
			refs = append(refs, loadReference{loadRef: loadRef{"volume", b.Ebs.VolumeId}})
		}
	}
	for _, attr := range ec2InstanceReadAttributes {
		refs = append(refs, loadReference{loadRef: loadRef{"instance-attribute", instanceAttributeID(x.InstanceId, attr)}})
	}
	return refs
}

func renderInstances(tx *repository.LoadTx, ids []string) ([]byte, error) {
	account, err := tx.Account()
	if err != nil {
		return nil, err
	}
	out := ec2DescribeInstancesResult{}
	for _, id := range ids {
		inst, err := tx.Instance(id)
		if err != nil {
			return nil, err
		}
		eni, err := tx.NetworkInterfaceOfInstance(id)
		if err != nil {
			return nil, err
		}
		net, err := ec2LoadedInstanceNet(tx, eni)
		if err != nil {
			return nil, err
		}
		x, err := ec2InstanceToXML(account, inst, net)
		if err != nil {
			return nil, err
		}
		if x.TagSet, err = ec2TagSet(tx, id); err != nil {
			return nil, err
		}
		out.ReservationSet = ec2Reserve(out.ReservationSet, account, inst.ReservationID, x)
	}
	return ec2Body("DescribeInstances", &out), nil
}

// ec2LoadedInstanceNet reads back what an instance on eni answers
// besides its row: eni's Elastic IP and its groups' names. A group no
// exchange loaded answers no name, as DescribeInstances' groupNames
// does: resolve has refused the interface naming it, so the render
// must not abort the load on top of that.
func ec2LoadedInstanceNet(tx *repository.LoadTx, eni *repository.EC2NetworkInterface) (ec2InstanceNet, error) {
	net := ec2InstanceNet{eni: eni, groupNames: map[string]string{}}
	if eni == nil {
		return net, nil
	}
	var err error
	if net.eip, err = tx.EIPOfNetworkInterface(eni.ID); err != nil {
		return net, err
	}
	for _, g := range eni.SecurityGroupIDs {
		sg, err := tx.SecurityGroup(g)
		switch {
		case errors.Is(err, models.ErrNotFound):
		case err != nil:
			return net, err
		default:
			net.groupNames[g] = sg.GroupName
		}
	}
	return net, nil
}

// instanceAttributeID names an instance's attribute as a row:
// <instance id>/<attribute>.
func instanceAttributeID(instanceID, attr string) string { return instanceID + "/" + attr }

// decodeInstanceAttribute sets the stored instance's attribute of
// ec2InstanceReadAttributes the answer holds, as recorded (userData's
// base64 byte-exact), refusing an answer that holds none of them and an
// instance no exchange loaded.
func decodeInstanceAttribute(env *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
	var body ec2DescribeInstanceAttributeResult
	if err := decodeEC2(ex, &body); err != nil {
		return nil, err
	}
	sets := map[string]func(*repository.EC2Instance){}
	if v := body.InstanceInitiatedShutdownBehavior; v != nil {
		sets["instanceInitiatedShutdownBehavior"] = func(i *repository.EC2Instance) { i.ShutdownBehavior = v.Value }
	}
	if v := body.DisableApiStop; v != nil {
		sets["disableApiStop"] = func(i *repository.EC2Instance) { i.DisableAPIStop = v.Value }
	}
	if v := body.DisableApiTermination; v != nil {
		sets["disableApiTermination"] = func(i *repository.EC2Instance) { i.DisableAPITermination = v.Value }
	}
	if v := body.UserData; v != nil {
		sets["userData"] = func(i *repository.EC2Instance) { i.UserData = v.Value }
	}
	var items []loadItem
	for _, attr := range ec2InstanceReadAttributes {
		set, ok := sets[attr]
		if !ok {
			continue
		}
		id := instanceAttributeID(body.InstanceId, attr)
		items = append(items, loadItem{loadRef: loadRef{"instance-attribute", id}, Path: attr,
			write: func(tx *repository.LoadTx) error {
				err := tx.UpdateInstance(body.InstanceId, set)
				if errors.Is(err, models.ErrNotFound) {
					return loadRefusal(fmt.Sprintf("instance-attribute %s names instance %s, which no exchange loaded", id, body.InstanceId))
				}
				return err
			}})
	}
	if len(items) == 0 {
		return nil, loadRefusal("it answers none of " + strings.Join(ec2InstanceReadAttributes, ", "))
	}
	return items, nil
}

func renderInstanceAttribute(tx *repository.LoadTx, ids []string) ([]byte, error) {
	instanceID, attr, _ := strings.Cut(ids[0], "/")
	inst, err := tx.Instance(instanceID)
	if err != nil {
		return nil, err
	}
	out := ec2DescribeInstanceAttributeResult{InstanceId: instanceID}
	ec2InstanceAttributeAnswer(&out, inst, attr)
	return ec2Body("DescribeInstanceAttribute", &out), nil
}

// decodeNetworkInterfaces loads each interface with its tags. It
// references its VPC and groups, and the address its association
// names; an amazon-owned public IP is held as the interface's own. One
// whose subnet, or the instance it is attached to, no exchange loaded is
// refused naming both: instances load first (ec2_instances is the
// parent table). One attached to an instance at a device index other
// than 0 is refused: an instance has only its primary interface.
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
				if a := x.Attachment; a != nil && a.InstanceId != "" && a.DeviceIndex != 0 {
					return loadRefusal(fmt.Sprintf("network-interface %s is attached to instance %s at device index %d: only an instance's primary interface (device index 0) is modelled",
						eni.ID, eni.InstanceID, a.DeviceIndex))
				}
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
		AvailabilityZone: x.AvailabilityZone, RequesterManaged: x.RequesterManaged != nil && *x.RequesterManaged, InterfaceType: x.InterfaceType,
		OwnerID: x.OwnerId, Status: x.Status,
	}
	for _, g := range x.GroupSet {
		eni.SecurityGroupIDs = append(eni.SecurityGroupIDs, g.GroupId)
	}
	if a := x.Attachment; a != nil {
		eni.InstanceID, eni.AttachmentID, eni.KeepOnTermination = a.InstanceId, a.AttachmentId, !a.DeleteOnTermination
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

// decodeVolumes loads each volume with its tags and its attachments,
// as recorded. Its snapshot and KMS key are references the reader never
// reads: snapshots are not modelled, and KMS keys live in kmsStore, not
// rows. One attached to an instance no exchange loaded, or whose
// attachment disagrees with the instance's blockDeviceMapping, is refused
// naming both (checkVolumeAttachment): instances load first (ec2_volumes
// ranks after ec2_instances).
func decodeVolumes(env *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
	var body ec2DescribeVolumesResult
	if err := decodeEC2(ex, &body); err != nil {
		return nil, err
	}
	items := make([]loadItem, len(body.VolumeSet))
	for i, x := range body.VolumeSet {
		vol := x.EC2Volume
		vol.Region = env.Region
		var refs []loadReference
		if vol.SnapshotID != "" {
			refs = append(refs, loadReference{loadRef: loadRef{"snapshot", vol.SnapshotID}, Unread: true})
		}
		if vol.KMSKeyID != "" {
			refs = append(refs, loadReference{loadRef: loadRef{"kms-key", vol.KMSKeyID}, Unread: true})
		}
		ref := loadRef{"volume", vol.ID}
		items[i] = loadItem{loadRef: ref, Path: "volumeSet/item", Index: i, Refs: refs,
			write: ec2Write(env, ec2TagsFromXML(ref, x.TagSet), func(tx *repository.LoadTx) error {
				for _, a := range vol.Attachments {
					if err := checkVolumeAttachment(tx, vol.ID, a); err != nil {
						return err
					}
				}
				return tx.PutVolume(env.Account, &vol)
			})}
	}
	return items, nil
}

// checkVolumeAttachment refuses volume id's attachment a when its
// instance no exchange loaded, or when that instance's recorded
// blockDeviceMapping names no such volume, or names it with another
// device, status, attachTime or deleteOnTermination: terminate acts on
// the volume's copy, so the two must agree. loadReference.Path cannot
// compare them: the volume's copy sits in its attachmentSet, under
// other names.
func checkVolumeAttachment(tx *repository.LoadTx, id string, a repository.EC2VolumeAttachment) error {
	inst, err := tx.Instance(a.InstanceID)
	if errors.Is(err, models.ErrNotFound) {
		return loadRefusal(fmt.Sprintf("volume %s is attached to instance %s, which no exchange loaded", id, a.InstanceID))
	}
	if err != nil {
		return err
	}
	var recorded ec2InstanceRecordedXML
	if len(inst.Recorded) > 0 {
		if err := json.Unmarshal(inst.Recorded, &recorded); err != nil {
			return err
		}
	}
	i := slices.IndexFunc(recorded.BlockDeviceMapping, func(b ec2InstanceBlockDeviceXML) bool { return b.Ebs != nil && b.Ebs.VolumeId == id })
	if i < 0 {
		return loadRefusal(fmt.Sprintf("volume %s is attached to instance %s, whose blockDeviceMapping does not name it", id, a.InstanceID))
	}
	b := recorded.BlockDeviceMapping[i]
	var differ []string
	for _, f := range []struct{ name, volume, instance string }{
		{"device", a.Device, b.DeviceName},
		{"status", a.State, b.Ebs.Status},
		{"attachTime", a.AttachTime, b.Ebs.AttachTime},
		{"deleteOnTermination", a.DeleteOnTermination, b.Ebs.DeleteOnTermination},
	} {
		if f.volume != f.instance {
			differ = append(differ, f.name)
		}
	}
	if len(differ) > 0 {
		return loadRefusal(fmt.Sprintf("volume %s: its attachment to instance %s differs from the instance's blockDeviceMapping at %s",
			id, a.InstanceID, strings.Join(differ, ", ")))
	}
	return nil
}

func renderVolumes(tx *repository.LoadTx, ids []string) ([]byte, error) {
	out := ec2DescribeVolumesResult{VolumeSet: []ec2VolumeXML{}}
	for _, id := range ids {
		vol, err := tx.Volume(id)
		if err != nil {
			return nil, err
		}
		x := ec2VolumeXML{EC2Volume: *vol}
		if x.TagSet, err = ec2TagSet(tx, id); err != nil {
			return nil, err
		}
		out.VolumeSet = append(out.VolumeSet, x)
	}
	return ec2Body("DescribeVolumes", &out), nil
}
