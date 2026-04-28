package repository

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/redscaresu/fakeaws/models"
)

func TestDynamoDBTableCRUD(t *testing.T) {
	r := setupRepo(t)
	tab := &DynamoDBTable{
		Name: "Users", HashKey: "id",
		Attributes: []DynamoDBAttributeDef{{Name: "id", Type: "S"}},
		BillingMode: "PAY_PER_REQUEST",
		Region: testRegion, ARN: "arn", CreatedAt: "t",
	}
	if err := r.CreateDynamoDBTable(testAccount, tab); err != nil {
		t.Fatalf("CreateDynamoDBTable: %v", err)
	}

	got, err := r.GetDynamoDBTable(testAccount, testRegion, "Users")
	if err != nil {
		t.Fatalf("GetDynamoDBTable: %v", err)
	}
	if got.HashKey != "id" {
		t.Errorf("hash_key: %q", got.HashKey)
	}
	if got.Status != "ACTIVE" {
		t.Errorf("status default: %q want ACTIVE", got.Status)
	}

	if err := r.DeleteDynamoDBTable(testAccount, testRegion, "Users"); err != nil {
		t.Fatalf("DeleteDynamoDBTable: %v", err)
	}
	if _, err := r.GetDynamoDBTable(testAccount, testRegion, "Users"); !errors.Is(err, models.ErrNotFound) {
		t.Errorf("after delete: %v", err)
	}
}

func TestDynamoDBItemPutGetDelete(t *testing.T) {
	r := setupRepo(t)
	r.CreateDynamoDBTable(testAccount, &DynamoDBTable{
		Name: "Users", HashKey: "id",
		Attributes: []DynamoDBAttributeDef{{Name: "id", Type: "S"}},
		Region: testRegion, ARN: "arn", CreatedAt: "t",
	})

	itemBody := json.RawMessage(`{"id":{"S":"alice"},"age":{"N":"30"}}`)
	item := &DynamoDBItem{
		TableName: "Users", HashValue: "alice", Item: itemBody,
	}
	if err := r.PutDynamoDBItem(testAccount, testRegion, item); err != nil {
		t.Fatalf("PutDynamoDBItem: %v", err)
	}

	// Get round-trips.
	got, err := r.GetDynamoDBItem(testAccount, testRegion, "Users", "alice", "")
	if err != nil {
		t.Fatalf("GetDynamoDBItem: %v", err)
	}
	if string(got.Item) != string(itemBody) {
		t.Errorf("item round-trip: got %s want %s", got.Item, itemBody)
	}

	// PutItem is upsert — same key replaces.
	updated := json.RawMessage(`{"id":{"S":"alice"},"age":{"N":"31"}}`)
	r.PutDynamoDBItem(testAccount, testRegion, &DynamoDBItem{
		TableName: "Users", HashValue: "alice", Item: updated,
	})
	got, _ = r.GetDynamoDBItem(testAccount, testRegion, "Users", "alice", "")
	if string(got.Item) != string(updated) {
		t.Errorf("upsert: got %s want %s", got.Item, updated)
	}

	// Item under missing table → 404.
	if err := r.PutDynamoDBItem(testAccount, testRegion, &DynamoDBItem{
		TableName: "Missing", HashValue: "x", Item: json.RawMessage(`{}`),
	}); !errors.Is(err, models.ErrNotFound) {
		t.Errorf("PutItem on missing table: want ErrNotFound, got %v", err)
	}

	// Delete + re-get → 404.
	r.DeleteDynamoDBItem(testAccount, testRegion, "Users", "alice", "")
	if _, err := r.GetDynamoDBItem(testAccount, testRegion, "Users", "alice", ""); !errors.Is(err, models.ErrNotFound) {
		t.Errorf("after delete: %v", err)
	}
}

func TestDynamoDBTableDeleteCASCADESItems(t *testing.T) {
	r := setupRepo(t)
	r.CreateDynamoDBTable(testAccount, &DynamoDBTable{
		Name: "Users", HashKey: "id",
		Attributes: []DynamoDBAttributeDef{{Name: "id", Type: "S"}},
		Region: testRegion, ARN: "arn", CreatedAt: "t",
	})
	r.PutDynamoDBItem(testAccount, testRegion, &DynamoDBItem{
		TableName: "Users", HashValue: "a", Item: json.RawMessage(`{"id":{"S":"a"}}`),
	})

	if err := r.DeleteDynamoDBTable(testAccount, testRegion, "Users"); err != nil {
		t.Fatalf("DeleteDynamoDBTable: %v", err)
	}
	if _, err := r.GetDynamoDBItem(testAccount, testRegion, "Users", "a", ""); !errors.Is(err, models.ErrNotFound) {
		t.Errorf("CASCADE: item should be gone after table delete, got %v", err)
	}
}

func TestDynamoDBScanReturnsAllItems(t *testing.T) {
	r := setupRepo(t)
	r.CreateDynamoDBTable(testAccount, &DynamoDBTable{
		Name: "Users", HashKey: "id",
		Attributes: []DynamoDBAttributeDef{{Name: "id", Type: "S"}},
		Region: testRegion, ARN: "arn", CreatedAt: "t",
	})
	r.PutDynamoDBItem(testAccount, testRegion, &DynamoDBItem{TableName: "Users", HashValue: "a", Item: json.RawMessage(`{"id":{"S":"a"}}`)})
	r.PutDynamoDBItem(testAccount, testRegion, &DynamoDBItem{TableName: "Users", HashValue: "b", Item: json.RawMessage(`{"id":{"S":"b"}}`)})

	items, err := r.ScanDynamoDBTable(testAccount, testRegion, "Users")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(items) != 2 {
		t.Errorf("Scan: got %d items want 2", len(items))
	}
}
