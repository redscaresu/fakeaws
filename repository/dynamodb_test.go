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

// TestDynamoDBItemRegionIsolation pins the Codex pass 6 BLOCKING #1
// fix: same-named tables in different regions must hold their own
// item sets without bleeding across regions.
func TestDynamoDBItemRegionIsolation(t *testing.T) {
	r := setupRepo(t)
	// Create two tables with the same name in different regions.
	for _, region := range []string{"us-east-1", "eu-west-1"} {
		if err := r.CreateDynamoDBTable(testAccount, &DynamoDBTable{
			Name: "Users", HashKey: "id",
			Attributes: []DynamoDBAttributeDef{{Name: "id", Type: "S"}},
			Region: region, ARN: "arn:" + region, CreatedAt: "t",
		}); err != nil {
			t.Fatalf("CreateDynamoDBTable %s: %v", region, err)
		}
	}
	// Put items in each region.
	r.PutDynamoDBItem(testAccount, "us-east-1", &DynamoDBItem{
		TableName: "Users", HashValue: "alice",
		Item: []byte(`{"id":{"S":"alice"},"region":{"S":"us-east-1"}}`),
	})
	r.PutDynamoDBItem(testAccount, "eu-west-1", &DynamoDBItem{
		TableName: "Users", HashValue: "alice",
		Item: []byte(`{"id":{"S":"alice"},"region":{"S":"eu-west-1"}}`),
	})

	// Each region returns its own item — no cross-region bleed.
	usItem, _ := r.GetDynamoDBItem(testAccount, "us-east-1", "Users", "alice", "")
	euItem, _ := r.GetDynamoDBItem(testAccount, "eu-west-1", "Users", "alice", "")
	if string(usItem.Item) == string(euItem.Item) {
		t.Errorf("region isolation violated — items match: %s", usItem.Item)
	}
	if !contains(string(usItem.Item), "us-east-1") {
		t.Errorf("us-east-1 item bled: %s", usItem.Item)
	}
	if !contains(string(euItem.Item), "eu-west-1") {
		t.Errorf("eu-west-1 item bled: %s", euItem.Item)
	}

	// Delete in one region leaves the other intact.
	r.DeleteDynamoDBItem(testAccount, "us-east-1", "Users", "alice", "")
	if _, err := r.GetDynamoDBItem(testAccount, "eu-west-1", "Users", "alice", ""); err != nil {
		t.Errorf("eu-west-1 item should survive us-east-1 delete: %v", err)
	}
}

// contains is a tiny strings.Contains shim — avoids importing strings
// just for the regression assertion above.
func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
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
