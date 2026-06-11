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

func sqsCall(t *testing.T, srv *httptest.Server, op, body string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/sqs/region/us-east-1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-amz-json-1.0")
	req.Header.Set("X-Amz-Target", "AmazonSQS."+op)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err, "POST /sqs %s", op)
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

func TestSQS_QueueLifecycle(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	// CreateQueue.
	resp, body := sqsCall(t, srv, "CreateQueue", `{"QueueName":"orders"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateQueue: %s", body)
	assert.Contains(t, string(body), `"QueueUrl"`, "CreateQueue body: %s", body)

	// GetQueueUrl.
	resp, body = sqsCall(t, srv, "GetQueueUrl", `{"QueueName":"orders"}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "GetQueueUrl status")
	assert.Contains(t, string(body), `orders`, "GetQueueUrl: %s", body)

	// ListQueues.
	_, body = sqsCall(t, srv, "ListQueues", `{}`)
	assert.Contains(t, string(body), "orders", "ListQueues: %s", body)

	// GetQueueUrl on missing → 404.
	resp, _ = sqsCall(t, srv, "GetQueueUrl", `{"QueueName":"missing"}`)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "GetQueueUrl missing")
}

func TestSQS_FIFOSuffixContract(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	// FIFO name without FifoQueue=true → 409.
	resp, _ := sqsCall(t, srv, "CreateQueue", `{"QueueName":"orders.fifo"}`)
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "FIFO suffix without FifoQueue")

	// FifoQueue=true without .fifo suffix → 409.
	resp, _ = sqsCall(t, srv, "CreateQueue", `{"QueueName":"orders","Attributes":{"FifoQueue":"true"}}`)
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "FifoQueue without .fifo suffix")

	// Both → success.
	resp, _ = sqsCall(t, srv, "CreateQueue", `{"QueueName":"orders.fifo","Attributes":{"FifoQueue":"true"}}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "FIFO both")
}

func TestSQS_MessageLifecycle(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, body := sqsCall(t, srv, "CreateQueue", `{"QueueName":"q"}`)
	// Extract QueueUrl roughly.
	urlStart := strings.Index(string(body), `"QueueUrl":"`) + len(`"QueueUrl":"`)
	urlEnd := strings.Index(string(body)[urlStart:], `"`) + urlStart
	queueURL := string(body)[urlStart:urlEnd]

	// SendMessage.
	resp, body := sqsCall(t, srv, "SendMessage", `{"QueueUrl":"`+queueURL+`","MessageBody":"hello"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "SendMessage: %s", body)

	// ReceiveMessage.
	resp, body = sqsCall(t, srv, "ReceiveMessage", `{"QueueUrl":"`+queueURL+`"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "ReceiveMessage")
	assert.Contains(t, string(body), "hello", "ReceiveMessage body: %s", body)
	rhStart := strings.Index(string(body), `"ReceiptHandle":"`) + len(`"ReceiptHandle":"`)
	rhEnd := strings.Index(string(body)[rhStart:], `"`) + rhStart
	rh := string(body)[rhStart:rhEnd]

	// In-flight: re-receive returns nothing.
	_, body = sqsCall(t, srv, "ReceiveMessage", `{"QueueUrl":"`+queueURL+`"}`)
	assert.NotContains(t, string(body), "hello", "in-flight should not re-deliver immediately: %s", body)

	// DeleteMessage.
	resp, _ = sqsCall(t, srv, "DeleteMessage", `{"QueueUrl":"`+queueURL+`","ReceiptHandle":"`+rh+`"}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "DeleteMessage")
}
