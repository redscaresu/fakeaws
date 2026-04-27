package awsproto

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// XAmzTargetRequest is the parsed form of a JSON 1.0 / 1.1 request
// dispatched via the X-Amz-Target header. Service is the prefix
// before the dot (e.g., "DynamoDB_20120810"); Operation is the
// suffix after (e.g., "PutItem"). Body is the raw bytes — the caller
// unmarshals into the operation-specific struct.
type XAmzTargetRequest struct {
	Target    string // full "Service.Operation" header value
	Service   string
	Operation string
	Body      []byte
}

// ParseXAmzTarget reads the X-Amz-Target header and the request body.
// Returns an error if the header is missing, malformed, or the body
// can't be read.
//
// Used by DynamoDB (JSON 1.1), SQS (JSON 1.0), and SecretsManager
// (JSON 1.1).
func ParseXAmzTarget(r *http.Request) (XAmzTargetRequest, error) {
	target := r.Header.Get("X-Amz-Target")
	if target == "" {
		return XAmzTargetRequest{}, fmt.Errorf("missing X-Amz-Target header")
	}
	parts := strings.SplitN(target, ".", 2)
	if len(parts) != 2 {
		return XAmzTargetRequest{}, fmt.Errorf("malformed X-Amz-Target %q (expect Service.Operation)", target)
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return XAmzTargetRequest{}, fmt.Errorf("read body: %w", err)
	}
	return XAmzTargetRequest{
		Target:    target,
		Service:   parts[0],
		Operation: parts[1],
		Body:      body,
	}, nil
}

// WriteJSON10Response marshals payload and writes a JSON 1.0 success
// response (used by SQS post-2023). Sets the protocol-specific
// content-type so the SDK parses correctly.
func WriteJSON10Response(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.0")
	w.WriteHeader(status)
	if payload == nil {
		return
	}
	body, err := json.Marshal(payload)
	if err != nil {
		// Don't try to be clever — the handler should have validated
		// the payload. We've already committed the status code.
		return
	}
	_, _ = w.Write(body)
}

// WriteJSON11Response marshals payload and writes a JSON 1.1 success
// response (used by DynamoDB and SecretsManager).
func WriteJSON11Response(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(status)
	if payload == nil {
		return
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	_, _ = w.Write(body)
}

// WriteJSONRESTResponse marshals payload as plain JSON for JSON-REST
// services (EKS).
func WriteJSONRESTResponse(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if payload == nil {
		return
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	_, _ = w.Write(body)
}

// DecodeJSONBody is a thin wrapper around json.NewDecoder for handlers
// that prefer to decode directly into a typed struct. Returns the body
// bytes alongside the decode error so handlers can include the raw
// payload in their error response if helpful.
func DecodeJSONBody(r *http.Request, dst any) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return body, fmt.Errorf("unmarshal: %w", err)
	}
	return body, nil
}
