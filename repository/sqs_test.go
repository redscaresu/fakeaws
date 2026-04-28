package repository

import (
	"errors"
	"testing"

	"github.com/redscaresu/fakeaws/models"
)

func TestSQSQueueCRUD(t *testing.T) {
	r := setupRepo(t)
	q := &SQSQueue{
		Name: "orders", QueueURL: "http://localhost/queue/orders",
		ARN: "arn:aws:sqs:us-east-1:000000000000:orders",
		Attributes: map[string]string{"VisibilityTimeout": "30"},
		Region: testRegion, CreatedAt: "t",
	}
	if err := r.CreateSQSQueue(testAccount, q); err != nil {
		t.Fatalf("CreateSQSQueue: %v", err)
	}
	got, err := r.GetSQSQueue(testAccount, testRegion, "orders")
	if err != nil {
		t.Fatalf("GetSQSQueue: %v", err)
	}
	if got.Attributes["VisibilityTimeout"] != "30" {
		t.Errorf("attributes round-trip: %v", got.Attributes)
	}
	if err := r.DeleteSQSQueue(testAccount, testRegion, "orders"); err != nil {
		t.Errorf("DeleteSQSQueue: %v", err)
	}
}

func TestSQSMessageLifecycle(t *testing.T) {
	r := setupRepo(t)
	r.CreateSQSQueue(testAccount, &SQSQueue{
		Name: "orders", QueueURL: "url", ARN: "arn", Region: testRegion, CreatedAt: "t",
	})

	// SendMessage on missing queue → 404.
	if err := r.SendSQSMessage(testAccount, testRegion, &SQSMessage{
		QueueName: "missing", MessageID: "m1", Body: "hi", CreatedAt: "t",
	}); !errors.Is(err, models.ErrNotFound) {
		t.Errorf("Send on missing queue: want ErrNotFound, got %v", err)
	}

	// Send 2 messages.
	r.SendSQSMessage(testAccount, testRegion, &SQSMessage{QueueName: "orders", MessageID: "m1", Body: "hello", CreatedAt: "t"})
	r.SendSQSMessage(testAccount, testRegion, &SQSMessage{QueueName: "orders", MessageID: "m2", Body: "world", CreatedAt: "t"})

	// Receive both — visibility timeout 30s.
	msgs, err := r.ReceiveSQSMessages(testAccount, testRegion, "orders", 1000, 10, 30)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("Receive count: got %d want 2", len(msgs))
	}
	for _, m := range msgs {
		if m.ReceiptHandle == "" {
			t.Errorf("receipt handle missing: %#v", m)
		}
		if m.ReceiveCount != 1 {
			t.Errorf("receive_count: got %d want 1", m.ReceiveCount)
		}
	}

	// Re-Receive immediately — both still in-flight (visible_after = now+30,
	// we pass now=1000 so visible_after = 1030, still > 1000).
	msgs2, _ := r.ReceiveSQSMessages(testAccount, testRegion, "orders", 1000, 10, 30)
	if len(msgs2) != 0 {
		t.Errorf("in-flight messages should not re-deliver: %d", len(msgs2))
	}

	// After visibility timeout elapses, they're visible again.
	msgs3, _ := r.ReceiveSQSMessages(testAccount, testRegion, "orders", 1100, 10, 30)
	if len(msgs3) != 2 {
		t.Errorf("messages should re-deliver after timeout: %d", len(msgs3))
	}

	// Delete one by receipt handle.
	rh := msgs3[0].ReceiptHandle
	if err := r.DeleteSQSMessage(testAccount, testRegion, "orders", rh); err != nil {
		t.Errorf("DeleteSQSMessage: %v", err)
	}

	// Delete with stale handle → 404.
	if err := r.DeleteSQSMessage(testAccount, testRegion, "orders", "stale-handle"); !errors.Is(err, models.ErrNotFound) {
		t.Errorf("Delete stale handle: want ErrNotFound, got %v", err)
	}
}

// TestSQSQueueDeleteRebadgesMessages pins the tombstone-on-parent-
// delete contract. Messages must NOT vanish on queue delete — they
// rebadge to the SQSDeletedQueueTombstone sentinel queue so audit
// trail is preserved. Codex pass 1 BLOCKING #2.
func TestSQSQueueDeleteRebadgesMessages(t *testing.T) {
	r := setupRepo(t)
	r.CreateSQSQueue(testAccount, &SQSQueue{Name: "q", QueueURL: "u", ARN: "a", Region: testRegion, CreatedAt: "t"})
	r.SendSQSMessage(testAccount, testRegion, &SQSMessage{QueueName: "q", MessageID: "m", Body: "x", CreatedAt: "t"})

	// Pre-delete: 0 tombstoned messages.
	n0, _ := r.CountSQSTombstonedMessages(testAccount, testRegion)
	if n0 != 0 {
		t.Fatalf("pre-delete tombstone count: %d want 0", n0)
	}

	if err := r.DeleteSQSQueue(testAccount, testRegion, "q"); err != nil {
		t.Fatalf("DeleteSQSQueue: %v", err)
	}

	// Post-delete: message survives under the tombstone sentinel.
	n1, _ := r.CountSQSTombstonedMessages(testAccount, testRegion)
	if n1 != 1 {
		t.Errorf("post-delete tombstone count: %d want 1", n1)
	}

	// Send to the deleted queue still 404s (queue's gone).
	if err := r.SendSQSMessage(testAccount, testRegion, &SQSMessage{QueueName: "q", MessageID: "m2", Body: "y", CreatedAt: "t"}); !errors.Is(err, models.ErrNotFound) {
		t.Errorf("Send to deleted queue: want ErrNotFound, got %v", err)
	}

	// Send to the tombstone queue is also rejected (read-only sentinel).
	if err := r.SendSQSMessage(testAccount, testRegion, &SQSMessage{
		QueueName: SQSDeletedQueueTombstone, MessageID: "m3", Body: "z", CreatedAt: "t",
	}); !errors.Is(err, models.ErrNotFound) {
		t.Errorf("Send to tombstone: want ErrNotFound, got %v", err)
	}
}
