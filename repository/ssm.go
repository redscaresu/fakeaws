// Package repository — SSM Parameter Store parameters.
//
// One row per parameter holds its current version only; parameter
// history (GetParameterHistory) is not modelled. PutParameter is one
// SQL statement in both modes, so the no-overwrite create is an atomic
// compare-and-set: of N racing puts on one name, exactly one inserts.
package repository

import (
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/redscaresu/fakeaws/models"
)

var ssmMigrations = []string{
	`CREATE TABLE IF NOT EXISTS ssm_parameters (
		account_id      TEXT NOT NULL,
		region          TEXT NOT NULL,
		name            TEXT NOT NULL,
		type            TEXT NOT NULL,
		value           TEXT NOT NULL,
		version         INTEGER NOT NULL,
		description     TEXT NOT NULL,
		allowed_pattern TEXT NOT NULL,
		data_type       TEXT NOT NULL,
		key_id          TEXT NOT NULL,
		tier            TEXT NOT NULL,
		tags            TEXT NOT NULL,
		last_modified   TEXT NOT NULL,
		PRIMARY KEY (account_id, region, name)
	)`,
}

func init() {
	registeredMigrations = append(registeredMigrations, ssmMigrations...)
	prependResetTables([]string{"ssm_parameters"})
}

// SSMParameter is a stored parameter at its current version.
type SSMParameter struct {
	Name           string
	Type           string
	Value          string
	Version        int64
	Description    string
	AllowedPattern string
	DataType       string
	KeyID          string
	Tier           string
	Tags           map[string]string
	Region         string
	LastModified   string
}

// SSMParameterPut is one PutParameter call. A nil optional field takes
// the AWS default on create and keeps the stored value on overwrite:
// terraform-provider-aws sends Description, DataType and KeyId on update
// only when they change.
type SSMParameterPut struct {
	Name           string
	Type           string
	Value          string
	AllowedPattern string
	Description    *string
	DataType       *string
	KeyID          *string
	Tier           *string
	Tags           map[string]string
	Region         string
	Now            string
}

const ssmInsert = `INSERT INTO ssm_parameters (account_id, region, name, type, value, version, description, allowed_pattern, data_type, key_id, tier, tags, last_modified)
	VALUES (:account, :region, :name, :type, :value, 1, COALESCE(:description, ''), :allowed_pattern,
		COALESCE(:data_type, 'text'), COALESCE(:key_id, ''), COALESCE(:tier, 'Standard'), :tags, :now)`

const ssmOverwrite = ` ON CONFLICT (account_id, region, name) DO UPDATE SET
	type = excluded.type, value = excluded.value, version = version + 1,
	allowed_pattern = excluded.allowed_pattern, last_modified = excluded.last_modified,
	description = COALESCE(:description, description), data_type = COALESCE(:data_type, data_type),
	key_id = COALESCE(:key_id, key_id), tier = COALESCE(:tier, tier)`

// PutSSMParameter creates or, with overwrite, replaces a parameter and
// returns its new version. Without overwrite an existing name is
// models.ErrConflict and the stored parameter is untouched.
func (r *Repository) PutSSMParameter(account string, p *SSMParameterPut, overwrite bool) (int64, error) {
	tags, err := json.Marshal(p.Tags)
	if err != nil {
		return 0, err
	}
	stmt := ssmInsert
	if overwrite {
		stmt += ssmOverwrite
	}
	var version int64
	err = r.db.QueryRow(stmt+" RETURNING version",
		sql.Named("account", account), sql.Named("region", p.Region), sql.Named("name", p.Name),
		sql.Named("type", p.Type), sql.Named("value", p.Value), sql.Named("allowed_pattern", p.AllowedPattern),
		sql.Named("description", p.Description), sql.Named("data_type", p.DataType),
		sql.Named("key_id", p.KeyID), sql.Named("tier", p.Tier),
		sql.Named("tags", string(tags)), sql.Named("now", p.Now),
	).Scan(&version)
	return version, mapInsertError(err)
}

// ssmRefMatch matches a row by name or by its ARN (the provider passes
// the ARN after an import by ARN), so an ARN in another region or
// account never matches. Bind the reference twice.
const ssmRefMatch = `(name = ? OR 'arn:aws:ssm:' || region || ':' || account_id || ':parameter/' || ltrim(name, '/') = ?)`

const ssmSelect = `SELECT name, type, value, version, description, allowed_pattern, data_type, key_id, tier, tags, region, last_modified FROM ssm_parameters`

func scanSSMParameter(row interface{ Scan(...any) error }) (SSMParameter, error) {
	var p SSMParameter
	var tags string
	err := row.Scan(&p.Name, &p.Type, &p.Value, &p.Version, &p.Description, &p.AllowedPattern,
		&p.DataType, &p.KeyID, &p.Tier, &tags, &p.Region, &p.LastModified)
	if err != nil {
		return p, err
	}
	return p, json.Unmarshal([]byte(tags), &p.Tags)
}

// GetSSMParameter looks a parameter up by name or ARN and returns
// models.ErrNotFound when neither matches.
func (r *Repository) GetSSMParameter(account, region, ref string) (*SSMParameter, error) {
	p, err := scanSSMParameter(r.db.QueryRow(ssmSelect+` WHERE account_id = ? AND region = ? AND `+ssmRefMatch, account, region, ref, ref))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// ListSSMParameters lists a region's parameters by name; region "" lists
// every region.
func (r *Repository) ListSSMParameters(account, region string) ([]SSMParameter, error) {
	rows, err := r.db.Query(ssmSelect+` WHERE account_id = ? AND (? = '' OR region = ?) ORDER BY region, name`, account, region, region)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SSMParameter
	for rows.Next() {
		p, err := scanSSMParameter(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeleteSSMParameter returns models.ErrNotFound for an unknown name.
func (r *Repository) DeleteSSMParameter(account, region, name string) error {
	res, err := r.db.Exec(`DELETE FROM ssm_parameters WHERE account_id = ? AND region = ? AND name = ?`, account, region, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return models.ErrNotFound
	}
	return nil
}

// PatchSSMParameterTags applies an RFC 7396 merge patch to a parameter's
// tags in one statement: a string value sets that tag, nil removes it.
// ref is a name or ARN; models.ErrNotFound when neither matches.
func (r *Repository) PatchSSMParameterTags(account, region, ref string, patch map[string]any) error {
	b, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	res, err := r.db.Exec(`UPDATE ssm_parameters SET tags = json_patch(tags, ?) WHERE account_id = ? AND region = ? AND `+ssmRefMatch,
		string(b), account, region, ref, ref)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return models.ErrNotFound
	}
	return nil
}
