package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/redscaresu/fakeaws/handlers/awsproto"
	"github.com/redscaresu/fakeaws/models"
	"github.com/redscaresu/fakeaws/repository"
)

// SQS dispatcher. Per fakeaws/PLAN.md § "Phase 4 — Containers + queues":
// SQS speaks JSON 1.0 with X-Amz-Target headers (post-2023 protocol
// modernization). Endpoint: /sqs/region/<region>.

func (app *Application) registerSQSRoutes(r chi.Router) {
	r.Post("/sqs/region/{region}", app.handleSQS)
}

func (app *Application) handleSQS(w http.ResponseWriter, r *http.Request) {
	region := chi.URLParam(r, "region")
	req, err := awsproto.ParseXAmzTarget(r)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON10,
			fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}
	const account = awsproto.FakeAccountID

	// M68 fix: emit QueueUrls using the request's actual host so the
	// SDK can route subsequent calls (ListQueueTags, GetQueueAttributes,
	// SendMessage, etc.) back to the same fakeaws instance. The
	// previous synthetic `sqs.<region>.fakeaws.local` host doesn't
	// resolve, breaking the apply path for every terraform-provider-aws
	// SQS resource.
	host := sqsRequestHost(r)

	switch req.Operation {
	case "CreateQueue":
		app.sqsCreateQueue(w, host, account, region, req)
	case "GetQueueUrl":
		app.sqsGetQueueURL(w, host, account, region, req)
	case "GetQueueAttributes":
		app.sqsGetQueueAttributes(w, account, region, req)
	case "ListQueues":
		app.sqsListQueues(w, host, account, region, req)
	case "DeleteQueue":
		app.sqsDeleteQueue(w, account, region, req)
	case "SendMessage":
		app.sqsSendMessage(w, account, region, req)
	case "ReceiveMessage":
		app.sqsReceiveMessage(w, account, region, req)
	case "DeleteMessage":
		app.sqsDeleteMessage(w, account, region, req)
	case "ListQueueTags":
		// terraform-provider-aws's aws_sqs_queue Read flow always
		// calls ListQueueTags after CreateQueue. We don't persist
		// tags yet — return an empty Tags map so the Read flow
		// completes without ResourceNotFoundException.
		awsproto.WriteJSON10Response(w, http.StatusOK, map[string]any{"Tags": map[string]string{}})
	case "TagQueue", "UntagQueue":
		// No-op until we persist tags. Real AWS returns an empty body
		// on success for both ops; the SDK is happy with {}.
		awsproto.WriteJSON10Response(w, http.StatusOK, map[string]any{})
	case "SetQueueAttributes":
		// aws_sqs_queue Update path patches attributes after the
		// initial Create. We accept silently for now (the apply →
		// plan-no-op gate doesn't verify per-attribute round-trip
		// for SQS yet); a future ticket can persist + echo back.
		awsproto.WriteJSON10Response(w, http.StatusOK, map[string]any{})
	default:
		awsproto.WriteAWSError(w, awsproto.ShapeJSON10,
			fmt.Errorf("SQS operation %q not yet implemented in fakeaws v1: %w", req.Operation, models.ErrNotFound))
	}
}

// sqsQueueURL returns the URL for a queue, in the path-style shape
// real AWS emits: <scheme>://<host>/<account>/<queue>. The provider
// (terraform-provider-aws) validates this URL with a regex that
// expects exactly that shape — extra path segments cause an
// "SQS Queue URL is in the incorrect format" error.
//
// The host comes from the request's Host header so the URL is
// reachable from wherever the SDK first reached fakeaws (M68 fix —
// the earlier `sqs.<region>.fakeaws.local` synthetic host resolved
// nowhere and broke every follow-up ListQueueTags / GetQueueAttributes
// call). The region isn't part of the URL itself (real AWS encodes
// it in the subdomain, e.g. sqs.us-east-1.amazonaws.com); we don't
// preserve it here because the queue-name + account uniquely
// identify the queue and our handlers don't need region for lookup
// once the queue is created.
//
// Queue-scoped operations (SendMessage, DeleteMessage, etc.) put the
// QueueUrl in their JSON request body — the SDK still POSTs to the
// service endpoint configured via terraform-provider-aws's endpoints
// block — so fakeaws's existing /sqs/region/{region} routes handle
// every call. The QueueUrl is just an identifier the body parser
// extracts the queue name from.
func sqsQueueURL(host, region, queueName string) string {
	return fmt.Sprintf("http://%s/%s/%s",
		host, awsproto.FakeAccountID, queueName)
}

// sqsRequestHost returns the host fakeaws was reached at for this
// request. Honors X-Forwarded-Host when present so reverse-proxied
// deployments work; otherwise falls back to r.Host (the standard
// HTTP/1.1 Host header). If both are empty, returns "127.0.0.1:8082"
// as the last-resort default so unit tests that bypass the HTTP
// server still get a valid URL.
func sqsRequestHost(r *http.Request) string {
	if h := r.Header.Get("X-Forwarded-Host"); h != "" {
		return h
	}
	if r.Host != "" {
		return r.Host
	}
	return "127.0.0.1:8082"
}

// ----- Queue ops -----

func (app *Application) sqsCreateQueue(w http.ResponseWriter, host, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		QueueName  string            `json:"QueueName"`
		Attributes map[string]string `json:"Attributes,omitempty"`
	}
	if err := json.Unmarshal(req.Body, &in); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON10, fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}
	if in.QueueName == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON10,
			fmt.Errorf("QueueName required: %w", models.ErrConflict))
		return
	}
	// FIFO queue contract per S46-T0 pitfall: name must end in
	// `.fifo` AND attributes.FifoQueue == "true". Mismatch rejects.
	fifoNamed := strings.HasSuffix(in.QueueName, ".fifo")
	fifoAttr := in.Attributes != nil && in.Attributes["FifoQueue"] == "true"
	if fifoNamed != fifoAttr {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON10,
			fmt.Errorf("FIFO queue name suffix must match FifoQueue attribute (name=%q FifoQueue=%t): %w",
				in.QueueName, fifoAttr, models.ErrConflict))
		return
	}
	q := &repository.SQSQueue{
		Name: in.QueueName, Region: region,
		// QueueURL kept on the repo row for backwards compat with
		// /mock/state consumers, but emitted by sqsQueueURL(host, ...)
		// in responses so the URL is always reachable.
		QueueURL:   sqsQueueURL(host, region, in.QueueName),
		ARN:        awsproto.BuildSQSQueueARN(region, in.QueueName),
		Attributes: in.Attributes,
		Fifo:       fifoNamed,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	if err := app.repo.CreateSQSQueue(account, q); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON10, err)
		return
	}
	awsproto.WriteJSON10Response(w, http.StatusOK, map[string]any{
		"QueueUrl": sqsQueueURL(host, region, in.QueueName),
	})
}

func (app *Application) sqsGetQueueURL(w http.ResponseWriter, host, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		QueueName string `json:"QueueName"`
	}
	json.Unmarshal(req.Body, &in)
	q, err := app.repo.GetSQSQueue(account, region, in.QueueName)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON10, err)
		return
	}
	awsproto.WriteJSON10Response(w, http.StatusOK, map[string]any{
		"QueueUrl": sqsQueueURL(host, q.Region, q.Name),
	})
}

func (app *Application) sqsGetQueueAttributes(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		QueueUrl string `json:"QueueUrl"`
	}
	json.Unmarshal(req.Body, &in)
	name := queueNameFromURL(in.QueueUrl)
	q, err := app.repo.GetSQSQueue(account, region, name)
	if err != nil {
		// Service-specific 404 code so terraform-provider-aws's
		// destroy-wait recognises "queue is gone" as successful
		// deletion. The generic ResourceNotFoundException bubbles
		// out of the wait state machine as a fatal error (same
		// pattern as M61 for RDS).
		awsproto.WriteServiceError(w, awsproto.ShapeJSON10, http.StatusBadRequest,
			"AWS.SimpleQueueService.NonExistentQueue",
			fmt.Sprintf("The specified queue does not exist: %s", in.QueueUrl))
		return
	}
	attrs := map[string]string{
		"QueueArn": q.ARN,
	}
	for k, v := range q.Attributes {
		attrs[k] = v
	}
	awsproto.WriteJSON10Response(w, http.StatusOK, map[string]any{
		"Attributes": attrs,
	})
}

func (app *Application) sqsListQueues(w http.ResponseWriter, host, account, region string, req awsproto.XAmzTargetRequest) {
	queues, err := app.repo.ListSQSQueues(account, region)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON10, err)
		return
	}
	urls := make([]string, 0, len(queues))
	for _, q := range queues {
		urls = append(urls, sqsQueueURL(host, q.Region, q.Name))
	}
	awsproto.WriteJSON10Response(w, http.StatusOK, map[string]any{
		"QueueUrls": urls,
	})
}

func (app *Application) sqsDeleteQueue(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		QueueUrl string `json:"QueueUrl"`
	}
	json.Unmarshal(req.Body, &in)
	if err := app.repo.DeleteSQSQueue(account, region, queueNameFromURL(in.QueueUrl)); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON10, err)
		return
	}
	awsproto.WriteJSON10Response(w, http.StatusOK, map[string]any{})
}

// ----- Message ops -----

func (app *Application) sqsSendMessage(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		QueueUrl    string `json:"QueueUrl"`
		MessageBody string `json:"MessageBody"`
	}
	if err := json.Unmarshal(req.Body, &in); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON10, fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}
	queueName := queueNameFromURL(in.QueueUrl)
	id := sqsRandID()
	m := &repository.SQSMessage{
		QueueName: queueName, MessageID: id, Body: in.MessageBody,
		Region: region, CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := app.repo.SendSQSMessage(account, region, m); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON10, err)
		return
	}
	awsproto.WriteJSON10Response(w, http.StatusOK, map[string]any{
		"MessageId": id,
	})
}

func (app *Application) sqsReceiveMessage(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		QueueUrl            string `json:"QueueUrl"`
		MaxNumberOfMessages int    `json:"MaxNumberOfMessages,omitempty"`
		VisibilityTimeout   int    `json:"VisibilityTimeout,omitempty"`
	}
	json.Unmarshal(req.Body, &in)
	if in.MaxNumberOfMessages == 0 {
		in.MaxNumberOfMessages = 1
	}
	if in.VisibilityTimeout == 0 {
		in.VisibilityTimeout = 30
	}
	queueName := queueNameFromURL(in.QueueUrl)
	now := time.Now().UTC().Unix()
	msgs, err := app.repo.ReceiveSQSMessages(account, region, queueName, now, in.MaxNumberOfMessages, in.VisibilityTimeout)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON10, err)
		return
	}
	out := make([]map[string]any, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, map[string]any{
			"MessageId":     m.MessageID,
			"Body":          m.Body,
			"ReceiptHandle": m.ReceiptHandle,
		})
	}
	awsproto.WriteJSON10Response(w, http.StatusOK, map[string]any{
		"Messages": out,
	})
}

func (app *Application) sqsDeleteMessage(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		QueueUrl      string `json:"QueueUrl"`
		ReceiptHandle string `json:"ReceiptHandle"`
	}
	json.Unmarshal(req.Body, &in)
	queueName := queueNameFromURL(in.QueueUrl)
	if err := app.repo.DeleteSQSMessage(account, region, queueName, in.ReceiptHandle); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON10, err)
		return
	}
	awsproto.WriteJSON10Response(w, http.StatusOK, map[string]any{})
}

// queueNameFromURL extracts the queue name from a queue URL of the
// shape http://sqs.<region>.fakeaws.local/<account>/<name> or the
// real AWS shape https://sqs.<region>.amazonaws.com/<account>/<name>.
// Both are last-segment-after-`/`.
func queueNameFromURL(queueURL string) string {
	idx := strings.LastIndex(queueURL, "/")
	if idx < 0 {
		return queueURL
	}
	return queueURL[idx+1:]
}

func sqsRandID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ----- /mock/state gather -----

func (app *Application) gatherSQSStateReal() map[string]any {
	const account = awsproto.FakeAccountID
	out := map[string]any{
		"queues":              []any{},
		"messages":            []any{},
		"tombstoned_messages": 0,
	}
	queues, _ := app.repo.ListSQSQueues(account, "")
	qOut := make([]map[string]any, 0, len(queues))
	for _, q := range queues {
		qOut = append(qOut, map[string]any{
			"name": q.Name, "url": q.QueueURL, "arn": q.ARN,
			"fifo": q.Fifo, "region": q.Region,
		})
	}
	out["queues"] = qOut

	// Codex pass 7 BLOCKING #2: messages collection now surfaces in
	// /mock/state so update-phase verification can see send/receive
	// mutations. Tombstoned messages are filtered out of this list
	// (they get a separate counter below) but still backed in SQLite.
	msgs, _ := app.repo.ListSQSMessages(account, "")
	mOut := make([]map[string]any, 0, len(msgs))
	totalTombstoned := 0
	for _, m := range msgs {
		if m.QueueName == repository.SQSDeletedQueueTombstone {
			totalTombstoned++
			continue
		}
		mOut = append(mOut, map[string]any{
			"queue_name":    m.QueueName,
			"message_id":    m.MessageID,
			"body":          m.Body,
			"receive_count": m.ReceiveCount,
			"visible_after": m.VisibleAfter,
			"region":        m.Region,
		})
	}
	out["messages"] = mOut
	out["tombstoned_messages"] = totalTombstoned
	return out
}
