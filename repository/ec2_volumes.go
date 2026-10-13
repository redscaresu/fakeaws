// Package repository — EC2 volumes.
//
// fakeaws creates no volume: a load stores one (LoadTx.PutVolume), and
// terminating an instance deletes the volumes attached to it with
// deleteOnTermination true and detaches the rest (terminateVolumesTx).
// A volume's attachments live in its data, not a foreign key, since a
// multi-attach volume has several instances; its loader checks each.
// Its table is ec2_compute.go's, created before ec2_tags.go's triggers.
package repository

import (
	"database/sql"
	"encoding/json"
	"slices"
)

// EC2Volume is a loaded volume, each field as DescribeVolumes recorded
// it, so it reads back byte-exact and an absent one stays absent. Its
// xml tags are that item's, which handlers/ec2.go's ec2VolumeXML embeds
// it in; its tags are the ec2_tags rows of its id.
type EC2Volume struct {
	ID                 string                `json:"volume_id" xml:"volumeId"`
	Size               string                `json:"size,omitempty" xml:"size,omitempty"`
	SnapshotID         string                `json:"snapshot_id,omitempty" xml:"snapshotId,omitempty"`
	AvailabilityZone   string                `json:"availability_zone,omitempty" xml:"availabilityZone,omitempty"`
	State              string                `json:"state,omitempty" xml:"status,omitempty"`
	CreateTime         string                `json:"create_time,omitempty" xml:"createTime,omitempty"`
	Attachments        []EC2VolumeAttachment `json:"attachments,omitempty" xml:"attachmentSet>item"`
	VolumeType         string                `json:"volume_type,omitempty" xml:"volumeType,omitempty"`
	Iops               string                `json:"iops,omitempty" xml:"iops,omitempty"`
	Throughput         string                `json:"throughput,omitempty" xml:"throughput,omitempty"`
	Encrypted          string                `json:"encrypted,omitempty" xml:"encrypted,omitempty"`
	KMSKeyID           string                `json:"kms_key_id,omitempty" xml:"kmsKeyId,omitempty"`
	MultiAttachEnabled string                `json:"multi_attach_enabled,omitempty" xml:"multiAttachEnabled,omitempty"`
	Region             string                `json:"region" xml:"-"`
}

// EC2VolumeAttachment is one item of a volume's attachmentSet.
type EC2VolumeAttachment struct {
	VolumeID            string `json:"volume_id,omitempty" xml:"volumeId,omitempty"`
	InstanceID          string `json:"instance_id,omitempty" xml:"instanceId,omitempty"`
	Device              string `json:"device,omitempty" xml:"device,omitempty"`
	State               string `json:"state,omitempty" xml:"status,omitempty"`
	AttachTime          string `json:"attach_time,omitempty" xml:"attachTime,omitempty"`
	DeleteOnTermination string `json:"delete_on_termination,omitempty" xml:"deleteOnTermination,omitempty"`
}

func insertVolume(ex execer, account string, v *EC2Volume) error {
	body, _ := json.Marshal(v)
	_, err := ex.Exec(`INSERT INTO ec2_volumes (account_id, region, id, data) VALUES (?, ?, ?, ?)`,
		account, v.Region, v.ID, string(body))
	return mapInsertError(err)
}

// ListVolumes returns the account's volumes, optionally scoped to a
// region (empty = all regions), ordered by id.
func (r *Repository) ListVolumes(account, region string) ([]*EC2Volume, error) {
	rows, err := r.db.Query(`SELECT data FROM ec2_volumes WHERE account_id = ? AND (? = '' OR region = ?) ORDER BY id`,
		account, region, region)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*EC2Volume
	for rows.Next() {
		v, err := scanVolume(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func scanVolume(scan func(...any) error) (*EC2Volume, error) {
	var data string
	if err := scan(&data); err != nil {
		return nil, err
	}
	var v EC2Volume
	return &v, json.Unmarshal([]byte(data), &v)
}

// terminateVolumesTx deletes each volume whose attachment to instance
// id has deleteOnTermination true, and detaches the others from it:
// one left with no attachment is available.
func terminateVolumesTx(tx *sql.Tx, account, id string) error {
	rows, err := tx.Query(`SELECT data FROM ec2_volumes WHERE account_id = ? AND EXISTS
		(SELECT 1 FROM json_each(data, '$.attachments') a WHERE json_extract(a.value, '$.instance_id') = ?)`, account, id)
	if err != nil {
		return err
	}
	var vols []*EC2Volume
	for rows.Next() {
		v, err := scanVolume(rows.Scan)
		if err != nil {
			rows.Close()
			return err
		}
		vols = append(vols, v)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, v := range vols {
		if err := terminateVolumeTx(tx, account, id, v); err != nil {
			return err
		}
	}
	return nil
}

func terminateVolumeTx(tx *sql.Tx, account, id string, v *EC2Volume) error {
	mine := func(a EC2VolumeAttachment) bool { return a.InstanceID == id }
	if slices.ContainsFunc(v.Attachments, func(a EC2VolumeAttachment) bool { return mine(a) && a.DeleteOnTermination == "true" }) {
		_, err := tx.Exec(`DELETE FROM ec2_volumes WHERE account_id = ? AND id = ?`, account, v.ID)
		return err
	}
	v.Attachments = slices.DeleteFunc(v.Attachments, mine)
	if len(v.Attachments) == 0 {
		v.State = "available"
	}
	body, _ := json.Marshal(v)
	_, err := tx.Exec(`UPDATE ec2_volumes SET data = ? WHERE account_id = ? AND id = ?`, string(body), account, v.ID)
	return err
}
