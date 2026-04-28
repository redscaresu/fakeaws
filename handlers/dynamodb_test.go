package handlers_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func ddbCall(t *testing.T, srv *httptest.Server, region, op string, body string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/dynamodb/region/"+region, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "DynamoDB_20120810."+op)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /dynamodb %s: %v", op, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

func TestDynamoDB_TableLifecycle(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"

	// CreateTable.
	resp, body := ddbCall(t, srv, region, "CreateTable", `{
		"TableName": "Users",
		"AttributeDefinitions": [{"AttributeName":"id","AttributeType":"S"}],
		"KeySchema": [{"AttributeName":"id","KeyType":"HASH"}],
		"BillingMode": "PAY_PER_REQUEST"
	}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateTable: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `"TableName":"Users"`) {
		t.Errorf("CreateTable body: %s", body)
	}

	// DescribeTable.
	resp, body = ddbCall(t, srv, region, "DescribeTable", `{"TableName":"Users"}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"TableStatus":"ACTIVE"`) {
		t.Errorf("DescribeTable: %d %s", resp.StatusCode, body)
	}

	// DescribeTable on missing → 404.
	resp, _ = ddbCall(t, srv, region, "DescribeTable", `{"TableName":"Missing"}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("DescribeTable missing: got %d, want 404", resp.StatusCode)
	}

	// DeleteTable.
	resp, _ = ddbCall(t, srv, region, "DeleteTable", `{"TableName":"Users"}`)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DeleteTable: %d", resp.StatusCode)
	}
}

func TestDynamoDB_PutGetDeleteItem(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"
	ddbCall(t, srv, region, "CreateTable", `{
		"TableName": "Users",
		"AttributeDefinitions": [{"AttributeName":"id","AttributeType":"S"}],
		"KeySchema": [{"AttributeName":"id","KeyType":"HASH"}]
	}`)

	// PutItem.
	resp, _ := ddbCall(t, srv, region, "PutItem", `{
		"TableName": "Users",
		"Item": {"id":{"S":"alice"},"age":{"N":"30"}}
	}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PutItem: %d", resp.StatusCode)
	}

	// GetItem returns the item.
	resp, body := ddbCall(t, srv, region, "GetItem", `{
		"TableName": "Users",
		"Key": {"id":{"S":"alice"}}
	}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"alice"`) {
		t.Errorf("GetItem: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `"30"`) {
		t.Errorf("GetItem age: %s", body)
	}

	// GetItem on missing key returns 200 + empty body (per AWS contract).
	resp, body = ddbCall(t, srv, region, "GetItem", `{
		"TableName": "Users",
		"Key": {"id":{"S":"bob"}}
	}`)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GetItem missing key: got %d, want 200; body=%s", resp.StatusCode, body)
	}
	if strings.Contains(string(body), `"Item":`) {
		t.Errorf("GetItem missing key should not include Item field: %s", body)
	}

	// DeleteItem.
	resp, _ = ddbCall(t, srv, region, "DeleteItem", `{
		"TableName": "Users",
		"Key": {"id":{"S":"alice"}}
	}`)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DeleteItem: %d", resp.StatusCode)
	}
}

func TestDynamoDB_PutItemMissingTable404(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, _ := ddbCall(t, srv, "us-east-1", "PutItem", `{
		"TableName": "Missing",
		"Item": {"id":{"S":"x"}}
	}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("PutItem missing table: got %d, want 404", resp.StatusCode)
	}
}

func TestDynamoDB_ScanReturnsAllItems(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"
	ddbCall(t, srv, region, "CreateTable", `{
		"TableName": "Users",
		"AttributeDefinitions": [{"AttributeName":"id","AttributeType":"S"}],
		"KeySchema": [{"AttributeName":"id","KeyType":"HASH"}]
	}`)
	ddbCall(t, srv, region, "PutItem", `{"TableName":"Users","Item":{"id":{"S":"a"}}}`)
	ddbCall(t, srv, region, "PutItem", `{"TableName":"Users","Item":{"id":{"S":"b"}}}`)
	resp, body := ddbCall(t, srv, region, "Scan", `{"TableName":"Users"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Scan: %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), `"Count":2`) {
		t.Errorf("Scan count: %s", body)
	}
}

func TestDynamoDB_UnknownOperation404(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, _ := ddbCall(t, srv, "us-east-1", "BatchGetItem", `{}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Unknown op: got %d, want 404", resp.StatusCode)
	}
}
