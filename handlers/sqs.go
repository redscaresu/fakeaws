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

	switch req.Operation {
	case "CreateQueue":
		app.sqsCreateQueue(w, account, region, req)
	case "GetQueueUrl":
		app.sqsGetQueueURL(w, account, region, req)
	case "GetQueueAttributes":
		app.sqsGetQueueAttributes(w, account, region, req)
	case "ListQueues":
		app.sqsListQueues(w, account, region, req)
	case "DeleteQueue":
		app.sqsDeleteQueue(w, account, region, req)
	case "SendMessage":
		app.sqsSendMessage(w, account, region, req)
	case "ReceiveMessage":
		app.sqsReceiveMessage(w, account, region, req)
	case "DeleteMessage":
		app.sqsDeleteMessage(w, account, region, req)
	default:
		awsproto.WriteAWSError(w, awsproto.ShapeJSON10,
			fmt.Errorf("SQS operation %q not yet implemented in fakeaws v1: %w", req.Operation, models.ErrNotFound))
	}
}

// sqsQueueURL returns the canonical fake URL for a queue. Real AWS:
// https://sqs.<region>.amazonaws.com/<account>/<name>. We emit a
// path-style URL on the fakeaws host so terraform-provider-aws can
// round-trip it through SDK builds without DNS shenanigans.
func sqsQueueURL(region, queueName string) string {
	return fmt.Sprintf("http://sqs.%s.fakeaws.local/%s/%s",
		region, awsproto.FakeAccountID, queueName)
}

// ----- Queue ops -----

func (app *Application) sqsCreateQueue(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
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
		QueueURL:  sqsQueueURL(region, in.QueueName),
		ARN:       awsproto.BuildSQSQueueARN(region, in.QueueName),
		Attributes: in.Attributes,
		Fifo:       fifoNamed,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	if err := app.repo.CreateSQSQueue(account, q); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON10, err)
		return
	}
	awsproto.WriteJSON10Response(w, http.StatusOK, map[string]any{
		"QueueUrl": q.QueueURL,
	})
}

func (app *Application) sqsGetQueueURL(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		QueueName string `json:"QueueName"`
	}
	json.Unmarshal(req.Body, &in)
	q, err := app.repo.GetSQSQueue(account, region, in.QueueName)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON10, err)
		return
	}
	awsproto.WriteJSON10Response(w, http.StatusOK, map[string]any{"QueueUrl": q.QueueURL})
}

func (app *Application) sqsGetQueueAttributes(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		QueueUrl string `json:"QueueUrl"`
	}
	json.Unmarshal(req.Body, &in)
	name := queueNameFromURL(in.QueueUrl)
	q, err := app.repo.GetSQSQueue(account, region, name)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON10, err)
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

func (app *Application) sqsListQueues(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	queues, err := app.repo.ListSQSQueues(account, region)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON10, err)
		return
	}
	urls := make([]string, 0, len(queues))
	for _, q := range queues {
		urls = append(urls, q.QueueURL)
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
		"queues": []any{},
	}
	queues, _ := app.repo.ListSQSQueues(account, "us-east-1")
	qOut := make([]map[string]any, 0, len(queues))
	for _, q := range queues {
		qOut = append(qOut, map[string]any{
			"name": q.Name, "url": q.QueueURL, "arn": q.ARN,
			"fifo": q.Fifo, "region": q.Region,
		})
	}
	out["queues"] = qOut
	return out
}
