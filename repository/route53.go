// Package repository — Route53 hosted zones, record sets, and changes.
//
// Per fakeaws/PLAN.md § "Phase 5 — DNS + secrets (S47)" — Route53 is
// global (no region in ARN). The two load-bearing contracts at this
// layer:
//
// 1. Non-empty-zone delete refusal: DeleteHostedZone counts records
//    other than the default NS + SOA pair and rejects if any exist
//    (concepts.md "Standing patterns" item 11).
// 2. Transactional batch on ChangeResourceRecordSets: validate ALL
//    changes before applying any (concepts.md "Standing patterns"
//    item 7). Implemented at the handler layer; this file ships the
//    underlying record-set CRUD primitives.
//
// Default NS + SOA record sets are seeded automatically on
// CreateHostedZone — they're how AWS surfaces "this zone is empty
// of user records" without the API needing a separate concept.
package repository

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/redscaresu/fakeaws/models"
)

var route53Migrations = []string{
	`CREATE TABLE IF NOT EXISTS route53_hosted_zones (
		account_id  TEXT NOT NULL,
		id          TEXT NOT NULL,
		name        TEXT NOT NULL,
		comment     TEXT NOT NULL DEFAULT '',
		private     INTEGER NOT NULL DEFAULT 0,
		arn         TEXT NOT NULL,
		data        TEXT NOT NULL,
		created_at  TEXT NOT NULL,
		PRIMARY KEY (account_id, id)
	)`,
	`CREATE TABLE IF NOT EXISTS route53_record_sets (
		account_id     TEXT NOT NULL,
		zone_id        TEXT NOT NULL,
		name           TEXT NOT NULL,
		type           TEXT NOT NULL,
		ttl            INTEGER NOT NULL DEFAULT 300,
		records        TEXT NOT NULL DEFAULT '[]',
		alias_target   TEXT NOT NULL DEFAULT '',
		set_identifier TEXT NOT NULL DEFAULT '',
		PRIMARY KEY (account_id, zone_id, name, type, set_identifier),
		FOREIGN KEY (account_id, zone_id) REFERENCES route53_hosted_zones(account_id, id) ON DELETE CASCADE
	)`,
	`CREATE TABLE IF NOT EXISTS route53_changes (
		account_id   TEXT NOT NULL,
		change_id    TEXT NOT NULL,
		zone_id      TEXT NOT NULL,
		status       TEXT NOT NULL DEFAULT 'INSYNC',
		submitted_at TEXT NOT NULL,
		PRIMARY KEY (account_id, change_id)
	)`,
}

func init() {
	registeredMigrations = append(registeredMigrations, route53Migrations...)
	prependResetTables([]string{
		"route53_record_sets",
		"route53_changes",
		"route53_hosted_zones",
	})
}

// ----- Typed wire shapes -----

type Route53HostedZone struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Comment   string `json:"comment,omitempty"`
	Private   bool   `json:"private"`
	ARN       string `json:"arn"`
	CreatedAt string `json:"created_at"`
}

type Route53RecordSet struct {
	ZoneID        string   `json:"zone_id"`
	Name          string   `json:"name"`
	Type          string   `json:"type"`
	TTL           int      `json:"ttl"`
	Records       []string `json:"records,omitempty"`
	AliasTarget   string   `json:"alias_target,omitempty"` // raw JSON
	SetIdentifier string   `json:"set_identifier,omitempty"`
}

type Route53Change struct {
	ID          string `json:"id"`
	ZoneID      string `json:"zone_id"`
	Status      string `json:"status"`
	SubmittedAt string `json:"submitted_at"`
}

// ----- Hosted Zone -----

func (r *Repository) CreateHostedZone(account string, z *Route53HostedZone) error {
	body, _ := json.Marshal(z)
	priv := 0
	if z.Private {
		priv = 1
	}
	if _, err := r.db.Exec(
		`INSERT INTO route53_hosted_zones (account_id, id, name, comment, private, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		account, z.ID, z.Name, z.Comment, priv, z.ARN, string(body), z.CreatedAt,
	); err != nil {
		return mapInsertError(err)
	}
	// Seed default NS + SOA records — every Route53 zone gets these.
	for _, rs := range []Route53RecordSet{
		{ZoneID: z.ID, Name: z.Name, Type: "NS", TTL: 172800,
			Records: []string{"ns-fakeaws-1.awsdns-99.net.", "ns-fakeaws-2.awsdns-99.com."}},
		{ZoneID: z.ID, Name: z.Name, Type: "SOA", TTL: 900,
			Records: []string{"ns-fakeaws-1.awsdns-99.net. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400"}},
	} {
		rs := rs
		if err := r.PutRecordSet(account, &rs); err != nil {
			return err
		}
	}
	return nil
}

func (r *Repository) GetHostedZone(account, id string) (*Route53HostedZone, error) {
	var data string
	err := r.db.QueryRow(
		`SELECT data FROM route53_hosted_zones WHERE account_id = ? AND id = ?`,
		account, id,
	).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var z Route53HostedZone
	if err := json.Unmarshal([]byte(data), &z); err != nil {
		return nil, err
	}
	return &z, nil
}

func (r *Repository) ListHostedZones(account string) ([]*Route53HostedZone, error) {
	rows, err := r.db.Query(`SELECT data FROM route53_hosted_zones WHERE account_id = ? ORDER BY id`, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Route53HostedZone
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var z Route53HostedZone
		if err := json.Unmarshal([]byte(data), &z); err != nil {
			return nil, err
		}
		out = append(out, &z)
	}
	return out, rows.Err()
}

// DeleteHostedZone refuses with ErrConflict if the zone has any
// records other than the default NS + SOA. Per concepts.md "Standing
// patterns" item 11.
func (r *Repository) DeleteHostedZone(account, id string) error {
	z, err := r.GetHostedZone(account, id)
	if err != nil {
		return err
	}
	var n int
	if err := r.db.QueryRow(
		`SELECT COUNT(*) FROM route53_record_sets WHERE account_id = ? AND zone_id = ? AND NOT (type IN ('NS','SOA') AND name = ?)`,
		account, id, z.Name,
	).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return fmt.Errorf("hosted zone %q has %d non-default record(s); delete them first: %w", id, n, models.ErrConflict)
	}
	res, err := r.db.Exec(`DELETE FROM route53_hosted_zones WHERE account_id = ? AND id = ?`, account, id)
	if err != nil {
		return mapDeleteError(err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return models.ErrNotFound
	}
	return nil
}

// ----- Record Sets -----

func (r *Repository) PutRecordSet(account string, rs *Route53RecordSet) error {
	if _, err := r.GetHostedZone(account, rs.ZoneID); err != nil {
		return err
	}
	recordsJSON, _ := json.Marshal(rs.Records)
	// PutRecordSet is upsert by (zone, name, type, set_identifier).
	_, err := r.db.Exec(
		`INSERT OR REPLACE INTO route53_record_sets (account_id, zone_id, name, type, ttl, records, alias_target, set_identifier) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		account, rs.ZoneID, rs.Name, rs.Type, rs.TTL, string(recordsJSON), rs.AliasTarget, rs.SetIdentifier,
	)
	return err
}

func (r *Repository) GetRecordSet(account, zoneID, name, recordType, setID string) (*Route53RecordSet, error) {
	var ttl int
	var recordsJSON, alias string
	err := r.db.QueryRow(
		`SELECT ttl, records, alias_target FROM route53_record_sets WHERE account_id = ? AND zone_id = ? AND name = ? AND type = ? AND set_identifier = ?`,
		account, zoneID, name, recordType, setID,
	).Scan(&ttl, &recordsJSON, &alias)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var records []string
	_ = json.Unmarshal([]byte(recordsJSON), &records)
	return &Route53RecordSet{
		ZoneID: zoneID, Name: name, Type: recordType, TTL: ttl,
		Records: records, AliasTarget: alias, SetIdentifier: setID,
	}, nil
}

func (r *Repository) ListRecordSets(account, zoneID string) ([]*Route53RecordSet, error) {
	if _, err := r.GetHostedZone(account, zoneID); err != nil {
		return nil, err
	}
	rows, err := r.db.Query(
		`SELECT name, type, ttl, records, alias_target, set_identifier FROM route53_record_sets WHERE account_id = ? AND zone_id = ? ORDER BY name, type, set_identifier`,
		account, zoneID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Route53RecordSet
	for rows.Next() {
		var rs Route53RecordSet
		var recordsJSON string
		rs.ZoneID = zoneID
		if err := rows.Scan(&rs.Name, &rs.Type, &rs.TTL, &recordsJSON, &rs.AliasTarget, &rs.SetIdentifier); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(recordsJSON), &rs.Records)
		out = append(out, &rs)
	}
	return out, rows.Err()
}

func (r *Repository) DeleteRecordSet(account, zoneID, name, recordType, setID string) error {
	res, err := r.db.Exec(
		`DELETE FROM route53_record_sets WHERE account_id = ? AND zone_id = ? AND name = ? AND type = ? AND set_identifier = ?`,
		account, zoneID, name, recordType, setID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return models.ErrNotFound
	}
	return nil
}

// ----- Changes -----

func (r *Repository) RecordChange(account string, c *Route53Change) error {
	_, err := r.db.Exec(
		`INSERT INTO route53_changes (account_id, change_id, zone_id, status, submitted_at) VALUES (?, ?, ?, ?, ?)`,
		account, c.ID, c.ZoneID, c.Status, c.SubmittedAt,
	)
	return err
}

func (r *Repository) GetChange(account, id string) (*Route53Change, error) {
	var c Route53Change
	c.ID = id
	err := r.db.QueryRow(
		`SELECT zone_id, status, submitted_at FROM route53_changes WHERE account_id = ? AND change_id = ?`,
		account, id,
	).Scan(&c.ZoneID, &c.Status, &c.SubmittedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}
