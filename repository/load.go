package repository

// load.go — the transaction POST /mock/load replaces every row in, and
// LoadTx, the only handle a loader reads and writes through.

import (
	"database/sql"
	"errors"
	"fmt"
	"iter"
	"slices"
)

// LoadTx is a load's transaction. A loader reads and writes only
// through it: the db has one connection, which the transaction holds,
// so a loader that reaches the Repository's own handle (any Repository
// method, or the handlers' account read) waits for it forever.
// Per-service files (load_<service>.go) build typed reads and writes on
// Exec, QueryRow and Query; Render reads the stored rows back through
// them.
//
// It remembers a failed statement. SQLite ends the transaction itself
// on some failures (SQLITE_FULL, IOERR, BUSY, NOMEM), after which a
// later write would commit on its own, so a load stops once Failed is
// true, whatever error, refusal or nil the loader returned. Only this
// file touches sqlTx (TestLoadTx_OnlyLoadGoTouchesTheTx), and every
// method here records its statement's failure through fail.
type LoadTx struct {
	sqlTx  *sql.Tx
	failed bool
}

// Exec runs a statement inside the load's transaction. It is the Exec
// of execer, so the inserts a lone write uses serve a load too.
func (lt *LoadTx) Exec(query string, args ...any) (sql.Result, error) {
	res, err := lt.sqlTx.Exec(query, args...)
	return res, lt.fail(err)
}

// QueryRow runs a one-row query inside the load's transaction. Its
// failure surfaces at the row's Scan, which records it as Exec does.
func (lt *LoadTx) QueryRow(query string, args ...any) *LoadRow {
	return &LoadRow{lt: lt, row: lt.sqlTx.QueryRow(query, args...)}
}

// LoadRow is QueryRow's row.
type LoadRow struct {
	lt  *LoadTx
	row *sql.Row
}

// Scan copies the row into dest, as sql.Row's Scan does, and records
// any failure but sql.ErrNoRows: no row is an answer (a parent not
// stored), on which a loader may refuse.
func (r *LoadRow) Scan(dest ...any) error {
	err := r.row.Scan(dest...)
	if errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return r.lt.fail(err)
}

// Query runs a query inside the load's transaction and yields, for each
// row it selects, that row's Scan. A failure of the query, a Scan or the
// rows is recorded as Exec's is; the query's and the rows' are yielded
// with a nil Scan and end the rows. The rows are closed however the
// loop ends.
func (lt *LoadTx) Query(query string, args ...any) iter.Seq2[func(dest ...any) error, error] {
	return func(yield func(func(dest ...any) error, error) bool) {
		rows, err := lt.sqlTx.Query(query, args...)
		if err != nil {
			yield(nil, lt.fail(err))
			return
		}
		defer rows.Close()
		scan := func(dest ...any) error { return lt.fail(rows.Scan(dest...)) }
		for rows.Next() {
			if !yield(scan, nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(nil, lt.fail(err))
		}
	}
}

// Account reads the account the load stores, which every row it writes
// is under.
func (lt *LoadTx) Account() (string, error) {
	var account string
	err := lt.QueryRow(`SELECT account_id FROM identity WHERE id = 1`).Scan(&account)
	return account, err
}

// Failed reports whether a statement has failed in this transaction.
func (lt *LoadTx) Failed() bool { return lt.failed }

// fail records err, when there is one, and returns it.
func (lt *LoadTx) fail(err error) error {
	if err != nil {
		lt.failed = true
	}
	return err
}

// LoadRank is table's place in the order a load writes tables in:
// resetTables reversed, so a table comes after every table it references
// (TestLoad_ResetTablesChildrenFirst pins that). ok is false for a table
// resetTables does not hold.
func LoadRank(table string) (rank int, ok bool) {
	i := slices.Index(resetTables, table)
	return len(resetTables) - 1 - i, i >= 0
}

// loadUnlink clears a table's references to its own rows before Load
// deletes them: its RESTRICT FK refuses deleting a row another row
// still references (a read replica's source), and DELETE visits rows
// in rowid order, so a source goes before its replica.
var loadUnlink = map[string]string{
	"rds_db_instances": `UPDATE rds_db_instances SET replicate_source_db = NULL`,
}

// Load replaces every row in one transaction, with FKs on: it deletes
// every resetTables row, children first, stores id marked loaded, then
// runs fill. An error from any step, fill's included, rolls it all back.
// Unlike Reset it leaves the snapshot alone, so a restore brings back
// the rows a load replaced.
func (r *Repository) Load(id Identity, fill func(*LoadTx) error) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, table := range resetTables {
		if unlink, ok := loadUnlink[table]; ok {
			if _, err := tx.Exec(unlink); err != nil {
				return fmt.Errorf("load: unlink %s: %w", table, err)
			}
		}
		if _, err := tx.Exec("DELETE FROM " + table); err != nil {
			return fmt.Errorf("load: clear %s: %w", table, err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO identity (id, account_id, region, loaded) VALUES (1, ?, ?, 1)`,
		id.AccountID, id.Region); err != nil {
		return fmt.Errorf("load: store identity: %w", err)
	}
	if err := fill(&LoadTx{sqlTx: tx}); err != nil {
		return err
	}
	return tx.Commit()
}
