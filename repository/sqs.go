// Package repository — SQS queues and messages.
//
// Per fakeaws/PLAN.md § "Phase 4 — Containers + queues (S46)" — SQS
// at v1 supports queue CRUD + minimal SendMessage / ReceiveMessage /
// DeleteMessage. visibility_timeout is collapsed: ReceiveMessage
// returns visible messages (ones whose visible_after <= now), bumps
// receive_count, and stamps a fresh visible_after = now + visibility
// _timeout_seconds. DeleteMessage removes by receipt_handle.
//
// Per the S46-T0 pitfalls:
//   - FIFO queues end in `.fifo` and have FifoQueue=true (handler
//     enforces).
//   - RedrivePolicy is a JSON-encoded string (not a HCL block) —
//     stored opaquely in the attributes JSON column.
package repository

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/redscaresu/fakeaws/models"
)

// SQSDeletedQueueTombstone is the synthetic queue name in-flight
// messages get rebadged to when their parent queue is deleted. Per
// concepts.md "Standing patterns" item 12 (tombstone-semantics-on-
// parent-delete) — without this, downstream consumers race against
// deletion. Mirror of fakegcp pass-25 Pub/Sub pattern.
//
// The tombstone queue is NOT a real SQS queue (no row in sqs_queues);
// it's a sentinel value that lets fakeaws preserve message audit
// trail without surfacing a phantom queue in /mock/state.
const SQSDeletedQueueTombstone = "_deleted-queue_"

var sqsMigrations = []string{
	`CREATE TABLE IF NOT EXISTS sqs_queues (
		account_id TEXT NOT NULL,
		region     TEXT NOT NULL,
		name       TEXT NOT NULL,
		queue_url  TEXT NOT NULL,
		arn        TEXT NOT NULL,
		attributes TEXT NOT NULL DEFAULT '{}',
		fifo       INTEGER NOT NULL DEFAULT 0,
		data       TEXT NOT NULL,
		created_at TEXT NOT NULL,
		PRIMARY KEY (account_id, region, name)
	)`,
	// NB: NO foreign key from sqs_messages → sqs_queues. The
	// tombstone-on-parent-delete contract requires DeleteSQSQueue to
	// rebadge in-flight messages to the synthetic deleted-queue
	// tombstone BEFORE the parent row goes away. A SQLite FK with
	// CASCADE would hard-delete the messages and break the contract.
	`CREATE TABLE IF NOT EXISTS sqs_messages (
		account_id     TEXT NOT NULL,
		region         TEXT NOT NULL,
		queue_name     TEXT NOT NULL,
		message_id     TEXT NOT NULL,
		body           TEXT NOT NULL,
		receipt_handle TEXT NOT NULL DEFAULT '',
		visible_after  INTEGER NOT NULL DEFAULT 0,
		receive_count  INTEGER NOT NULL DEFAULT 0,
		created_at     TEXT NOT NULL,
		PRIMARY KEY (account_id, region, queue_name, message_id)
	)`,
}

func init() {
	registeredMigrations = append(registeredMigrations, sqsMigrations...)
	prependResetTables([]string{
		"sqs_messages",
		"sqs_queues",
	})
}

// ----- Typed wire shapes -----

type SQSQueue struct {
	Name       string            `json:"name"`
	QueueURL   string            `json:"queue_url"`
	ARN        string            `json:"arn"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Fifo       bool              `json:"fifo"`
	Region     string            `json:"region"`
	CreatedAt  string            `json:"created_at"`
}

type SQSMessage struct {
	QueueName     string `json:"queue_name"`
	MessageID     string `json:"message_id"`
	Body          string `json:"body"`
	ReceiptHandle string `json:"receipt_handle,omitempty"`
	VisibleAfter  int64  `json:"visible_after"` // unix seconds
	ReceiveCount  int    `json:"receive_count"`
	Region        string `json:"region"`
	CreatedAt     string `json:"created_at"`
}

// ----- Queue CRUD -----

func (r *Repository) CreateSQSQueue(account string, q *SQSQueue) error {
	body, _ := json.Marshal(q)
	attrJSON := "{}"
	if q.Attributes != nil {
		ab, _ := json.Marshal(q.Attributes)
		attrJSON = string(ab)
	}
	fifo := 0
	if q.Fifo {
		fifo = 1
	}
	_, err := r.db.Exec(
		`INSERT INTO sqs_queues (account_id, region, name, queue_url, arn, attributes, fifo, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		account, q.Region, q.Name, q.QueueURL, q.ARN, attrJSON, fifo, string(body), q.CreatedAt,
	)
	return mapInsertError(err)
}

func (r *Repository) GetSQSQueue(account, region, name string) (*SQSQueue, error) {
	var data string
	err := r.db.QueryRow(
		`SELECT data FROM sqs_queues WHERE account_id = ? AND region = ? AND name = ?`,
		account, region, name,
	).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var q SQSQueue
	if err := json.Unmarshal([]byte(data), &q); err != nil {
		return nil, err
	}
	return &q, nil
}

// ListSQSQueues returns queues for the account, optionally scoped to
// a region. Pass region="" to enumerate every region — used by the
// /mock/state gatherer (Codex pass 1 SUGGEST item A — fixed).
func (r *Repository) ListSQSQueues(account, region string) ([]*SQSQueue, error) {
	var rows *sql.Rows
	var err error
	if region == "" {
		rows, err = r.db.Query(`SELECT data FROM sqs_queues WHERE account_id = ? ORDER BY region, name`, account)
	} else {
		rows, err = r.db.Query(
			`SELECT data FROM sqs_queues WHERE account_id = ? AND region = ? ORDER BY name`,
			account, region,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*SQSQueue
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var q SQSQueue
		if err := json.Unmarshal([]byte(data), &q); err != nil {
			return nil, err
		}
		out = append(out, &q)
	}
	return out, rows.Err()
}

// DeleteSQSQueue rebadges in-flight messages to the deleted-queue
// tombstone before deleting the parent row. Per concepts.md "Standing
// patterns" item 12: without rebadging, downstream consumers race
// against deletion. Codex pass 1 BLOCKING #2 fix.
func (r *Repository) DeleteSQSQueue(account, region, name string) error {
	if name == SQSDeletedQueueTombstone {
		// Don't allow callers to nuke the tombstone — that's where
		// in-flight messages from previously-deleted queues live.
		return fmt.Errorf("cannot delete the tombstone queue: %w", models.ErrConflict)
	}
	if _, err := r.GetSQSQueue(account, region, name); err != nil {
		return err
	}
	// Rebadge first — atomic-ish at the SQL level (single UPDATE).
	if _, err := r.db.Exec(
		`UPDATE sqs_messages SET queue_name = ? WHERE account_id = ? AND region = ? AND queue_name = ?`,
		SQSDeletedQueueTombstone, account, region, name,
	); err != nil {
		return fmt.Errorf("rebadge messages to tombstone: %w", err)
	}
	res, err := r.db.Exec(
		`DELETE FROM sqs_queues WHERE account_id = ? AND region = ? AND name = ?`,
		account, region, name,
	)
	if err != nil {
		return mapDeleteError(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return models.ErrNotFound
	}
	return nil
}

// CountSQSTombstonedMessages returns the number of messages currently
// rebadged under the tombstone queue. Used by regression tests + the
// /mock/state gatherer.
func (r *Repository) CountSQSTombstonedMessages(account, region string) (int, error) {
	var n int
	err := r.db.QueryRow(
		`SELECT COUNT(*) FROM sqs_messages WHERE account_id = ? AND region = ? AND queue_name = ?`,
		account, region, SQSDeletedQueueTombstone,
	).Scan(&n)
	return n, err
}

// ----- Message ops -----

func (r *Repository) SendSQSMessage(account, region string, m *SQSMessage) error {
	if m.QueueName == SQSDeletedQueueTombstone {
		// Tombstone queue is read-only — never accept new sends.
		return fmt.Errorf("cannot send to tombstone queue: %w", models.ErrNotFound)
	}
	if _, err := r.GetSQSQueue(account, region, m.QueueName); err != nil {
		return err
	}
	_, err := r.db.Exec(
		`INSERT INTO sqs_messages (account_id, region, queue_name, message_id, body, receipt_handle, visible_after, receive_count, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		account, region, m.QueueName, m.MessageID, m.Body, m.ReceiptHandle, m.VisibleAfter, m.ReceiveCount, m.CreatedAt,
	)
	return mapInsertError(err)
}

// ReceiveSQSMessages fetches up to maxMessages visible messages,
// bumps receive_count, and stamps a fresh receipt_handle + visible_after
// (now + visibilityTimeoutSeconds). Returns the messages with their
// new receipt handles.
func (r *Repository) ReceiveSQSMessages(account, region, queueName string, now int64, maxMessages, visibilityTimeoutSeconds int) ([]*SQSMessage, error) {
	if _, err := r.GetSQSQueue(account, region, queueName); err != nil {
		return nil, err
	}
	rows, err := r.db.Query(
		`SELECT message_id, body, receive_count FROM sqs_messages
		 WHERE account_id = ? AND region = ? AND queue_name = ? AND visible_after <= ?
		 ORDER BY created_at LIMIT ?`,
		account, region, queueName, now, maxMessages,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type pending struct {
		id, body string
		count    int
	}
	var picked []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.body, &p.count); err != nil {
			return nil, err
		}
		picked = append(picked, p)
	}
	rows.Close()

	out := make([]*SQSMessage, 0, len(picked))
	for _, p := range picked {
		newHandle := "rh-" + p.id + "-" + randSuffix()
		newVisible := now + int64(visibilityTimeoutSeconds)
		if _, err := r.db.Exec(
			`UPDATE sqs_messages SET receipt_handle = ?, visible_after = ?, receive_count = receive_count + 1 WHERE account_id = ? AND region = ? AND queue_name = ? AND message_id = ?`,
			newHandle, newVisible, account, region, queueName, p.id,
		); err != nil {
			return nil, err
		}
		out = append(out, &SQSMessage{
			QueueName: queueName, MessageID: p.id, Body: p.body,
			ReceiptHandle: newHandle, VisibleAfter: newVisible,
			ReceiveCount: p.count + 1, Region: region,
		})
	}
	return out, nil
}

func (r *Repository) DeleteSQSMessage(account, region, queueName, receiptHandle string) error {
	res, err := r.db.Exec(
		`DELETE FROM sqs_messages WHERE account_id = ? AND region = ? AND queue_name = ? AND receipt_handle = ?`,
		account, region, queueName, receiptHandle,
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

// ----- helpers -----

func randSuffix() string {
	const charset = "abcdef0123456789"
	b := make([]byte, 8)
	for i := range b {
		b[i] = charset[i%len(charset)]
	}
	return string(b)
}
