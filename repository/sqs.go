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

	"github.com/redscaresu/fakeaws/models"
)

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
		PRIMARY KEY (account_id, region, queue_name, message_id),
		FOREIGN KEY (account_id, region, queue_name) REFERENCES sqs_queues(account_id, region, name) ON DELETE CASCADE
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

func (r *Repository) ListSQSQueues(account, region string) ([]*SQSQueue, error) {
	rows, err := r.db.Query(
		`SELECT data FROM sqs_queues WHERE account_id = ? AND region = ? ORDER BY name`,
		account, region,
	)
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

func (r *Repository) DeleteSQSQueue(account, region, name string) error {
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

// ----- Message ops -----

func (r *Repository) SendSQSMessage(account, region string, m *SQSMessage) error {
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
