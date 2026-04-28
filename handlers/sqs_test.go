package handlers_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func sqsCall(t *testing.T, srv *httptest.Server, op, body string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/sqs/region/us-east-1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-amz-json-1.0")
	req.Header.Set("X-Amz-Target", "AmazonSQS."+op)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("POST /sqs %s: %v", op, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

func TestSQS_QueueLifecycle(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	// CreateQueue.
	resp, body := sqsCall(t, srv, "CreateQueue", `{"QueueName":"orders"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateQueue: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `"QueueUrl"`) {
		t.Errorf("CreateQueue body: %s", body)
	}

	// GetQueueUrl.
	resp, body = sqsCall(t, srv, "GetQueueUrl", `{"QueueName":"orders"}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `orders`) {
		t.Errorf("GetQueueUrl: %d %s", resp.StatusCode, body)
	}

	// ListQueues.
	_, body = sqsCall(t, srv, "ListQueues", `{}`)
	if !strings.Contains(string(body), "orders") {
		t.Errorf("ListQueues: %s", body)
	}

	// GetQueueUrl on missing → 404.
	resp, _ = sqsCall(t, srv, "GetQueueUrl", `{"QueueName":"missing"}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GetQueueUrl missing: got %d", resp.StatusCode)
	}
}

func TestSQS_FIFOSuffixContract(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	// FIFO name without FifoQueue=true → 409.
	resp, _ := sqsCall(t, srv, "CreateQueue", `{"QueueName":"orders.fifo"}`)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("FIFO suffix without FifoQueue: got %d, want 409", resp.StatusCode)
	}

	// FifoQueue=true without .fifo suffix → 409.
	resp, _ = sqsCall(t, srv, "CreateQueue", `{"QueueName":"orders","Attributes":{"FifoQueue":"true"}}`)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("FifoQueue without .fifo suffix: got %d, want 409", resp.StatusCode)
	}

	// Both → success.
	resp, _ = sqsCall(t, srv, "CreateQueue", `{"QueueName":"orders.fifo","Attributes":{"FifoQueue":"true"}}`)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("FIFO both: got %d", resp.StatusCode)
	}
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
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("SendMessage: %d %s", resp.StatusCode, body)
	}

	// ReceiveMessage.
	resp, body = sqsCall(t, srv, "ReceiveMessage", `{"QueueUrl":"`+queueURL+`"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ReceiveMessage: %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "hello") {
		t.Errorf("ReceiveMessage body: %s", body)
	}
	rhStart := strings.Index(string(body), `"ReceiptHandle":"`) + len(`"ReceiptHandle":"`)
	rhEnd := strings.Index(string(body)[rhStart:], `"`) + rhStart
	rh := string(body)[rhStart:rhEnd]

	// In-flight: re-receive returns nothing.
	_, body = sqsCall(t, srv, "ReceiveMessage", `{"QueueUrl":"`+queueURL+`"}`)
	if strings.Contains(string(body), "hello") {
		t.Errorf("in-flight should not re-deliver immediately: %s", body)
	}

	// DeleteMessage.
	resp, _ = sqsCall(t, srv, "DeleteMessage", `{"QueueUrl":"`+queueURL+`","ReceiptHandle":"`+rh+`"}`)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DeleteMessage: %d", resp.StatusCode)
	}
}
