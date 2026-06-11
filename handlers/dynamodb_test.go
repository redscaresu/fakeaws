package handlers_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ddbCall(t *testing.T, srv *httptest.Server, region, op string, body string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/dynamodb/region/"+region, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "DynamoDB_20120810."+op)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err, "POST /dynamodb %s", op)
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
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateTable: %s", body)
	assert.Contains(t, string(body), `"TableName":"Users"`, "CreateTable body: %s", body)

	// DescribeTable.
	resp, body = ddbCall(t, srv, region, "DescribeTable", `{"TableName":"Users"}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DescribeTable status")
	assert.Contains(t, string(body), `"TableStatus":"ACTIVE"`, "DescribeTable body: %s", body)

	// DescribeTable on missing → 404.
	resp, _ = ddbCall(t, srv, region, "DescribeTable", `{"TableName":"Missing"}`)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "DescribeTable missing")

	// DeleteTable.
	resp, _ = ddbCall(t, srv, region, "DeleteTable", `{"TableName":"Users"}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DeleteTable")
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
	require.Equal(t, http.StatusOK, resp.StatusCode, "PutItem")

	// GetItem returns the item.
	resp, body := ddbCall(t, srv, region, "GetItem", `{
		"TableName": "Users",
		"Key": {"id":{"S":"alice"}}
	}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "GetItem status")
	assert.Contains(t, string(body), `"alice"`, "GetItem: %s", body)
	assert.Contains(t, string(body), `"30"`, "GetItem age: %s", body)

	// GetItem on missing key returns 200 + empty body (per AWS contract).
	resp, body = ddbCall(t, srv, region, "GetItem", `{
		"TableName": "Users",
		"Key": {"id":{"S":"bob"}}
	}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "GetItem missing key; body=%s", body)
	assert.NotContains(t, string(body), `"Item":`, "GetItem missing key should not include Item field: %s", body)

	// DeleteItem.
	resp, _ = ddbCall(t, srv, region, "DeleteItem", `{
		"TableName": "Users",
		"Key": {"id":{"S":"alice"}}
	}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DeleteItem")
}

func TestDynamoDB_PutItemMissingTable404(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, _ := ddbCall(t, srv, "us-east-1", "PutItem", `{
		"TableName": "Missing",
		"Item": {"id":{"S":"x"}}
	}`)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "PutItem missing table")
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
	require.Equal(t, http.StatusOK, resp.StatusCode, "Scan")
	assert.Contains(t, string(body), `"Count":2`, "Scan count: %s", body)
}

func TestDynamoDB_UnknownOperation404(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, _ := ddbCall(t, srv, "us-east-1", "BatchGetItem", `{}`)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "Unknown op")
}
