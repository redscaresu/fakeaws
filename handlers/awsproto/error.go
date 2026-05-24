package awsproto

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"

	"github.com/redscaresu/fakeaws/models"
)

// errorMapping captures everything a per-protocol writer needs to turn
// a domain error into the right wire shape: HTTP status, AWS-spec error
// code, default message, and "type" suffix used by JSON 1.0/1.1.
type errorMapping struct {
	Status  int
	Code    string
	Message string
	Type    string // for JSON-1.x: "ResourceNotFoundException" etc.
}

// mapDomainError translates a domain sentinel from package models into
// the protocol-neutral fields each wire writer needs. The Code field
// uses AWS-spec common error codes (per the SDK's
// AWS_QUERY_ERROR_CODE / SDK_ERROR_CODE tables).
//
// New domain sentinels go here first, then per-protocol writers below
// pick up the new mapping for free. There are no protocol-specific
// codepaths for the same sentinel.
func mapDomainError(err error) errorMapping {
	switch {
	case errors.Is(err, models.ErrNotFound):
		return errorMapping{
			Status:  http.StatusNotFound,
			Code:    "ResourceNotFoundException",
			Message: "The specified resource does not exist.",
			Type:    "ResourceNotFoundException",
		}
	case errors.Is(err, models.ErrInUse):
		return errorMapping{
			Status:  http.StatusConflict,
			Code:    "ResourceInUseException",
			Message: "The resource is in use by another resource and cannot be deleted.",
			Type:    "ResourceInUseException",
		}
	case errors.Is(err, models.ErrTerminalState):
		return errorMapping{
			Status:  http.StatusConflict,
			Code:    "InvalidRequestException",
			Message: "The resource is in a terminal state and cannot be transitioned.",
			Type:    "InvalidRequestException",
		}
	case errors.Is(err, models.ErrConflict):
		return errorMapping{
			Status:  http.StatusConflict,
			Code:    "ConflictException",
			Message: "The request conflicts with the current resource state.",
			Type:    "ConflictException",
		}
	default:
		return errorMapping{
			Status:  http.StatusInternalServerError,
			Code:    "InternalFailure",
			Message: err.Error(),
			Type:    "InternalFailure",
		}
	}
}

// WriteServiceError emits a 404/409/etc. with a service-specific AWS
// error code (e.g. "DBInstanceNotFound", "SecretNotFoundException")
// instead of the generic mapping mapDomainError produces. Some SDK
// wait-state-machines check the exact service code rather than the
// generic ResourceNotFoundException — terraform-provider-aws's RDS
// delete-wait, for example, only treats "DBInstanceNotFound" as
// "resource is gone, deletion complete"; returning the generic code
// bubbles up as a hard error and breaks destroy.
//
// status: HTTP status code (typically 404 or 409).
// code: AWS-spec error code, e.g. "DBInstanceNotFound".
// message: human-readable message body.
func WriteServiceError(w http.ResponseWriter, shape WireShape, status int, code, message string) {
	m := errorMapping{Status: status, Code: code, Message: message, Type: code}
	switch shape {
	case ShapeXML:
		writeXMLError(w, m)
	case ShapeQueryRPC:
		writeQueryRPCError(w, m)
	case ShapeJSON10:
		writeJSON10Error(w, m)
	case ShapeJSON11:
		writeJSON11Error(w, m)
	case ShapeJSONREST:
		writeJSONRESTError(w, m)
	default:
		writeJSON11Error(w, m)
	}
}

// WriteAWSError dispatches the error to the right per-protocol writer.
// Caller passes the wire shape this handler speaks; awsproto knows how
// to render the response.
//
// This is the **only** entry point handlers should use to return
// domain errors. Per concepts.md § "Anti-patterns explicitly forbidden"
// — "No untested error-shape mappings": every distinct domain error
// reaches at least one handler test asserting the response body.
func WriteAWSError(w http.ResponseWriter, shape WireShape, err error) {
	mapping := mapDomainError(err)
	switch shape {
	case ShapeXML:
		writeXMLError(w, mapping)
	case ShapeQueryRPC:
		writeQueryRPCError(w, mapping)
	case ShapeJSON10:
		writeJSON10Error(w, mapping)
	case ShapeJSON11:
		writeJSON11Error(w, mapping)
	case ShapeJSONREST:
		writeJSONRESTError(w, mapping)
	default:
		// Unknown shape — fall back to generic JSON. Logged so the
		// caller's bug surfaces.
		writeJSON11Error(w, mapping)
	}
}

// WireShape identifies one of the five AWS wire formats fakeaws models.
// Handlers pass their shape to WriteAWSError so the right per-protocol
// writer fires.
type WireShape int

const (
	ShapeUnknown WireShape = iota
	ShapeXML               // S3, Route53
	ShapeQueryRPC          // EC2, RDS, IAM
	ShapeJSON10            // SQS
	ShapeJSON11            // DynamoDB, SecretsManager
	ShapeJSONREST          // EKS
)

// String returns the human-readable shape name (test fixture friendly).
func (s WireShape) String() string {
	switch s {
	case ShapeXML:
		return "xml"
	case ShapeQueryRPC:
		return "queryrpc"
	case ShapeJSON10:
		return "json10"
	case ShapeJSON11:
		return "json11"
	case ShapeJSONREST:
		return "jsonrest"
	default:
		return "unknown"
	}
}

// xmlErrorEnvelope is the wire shape S3 / Route53 emit: a top-level
// <Error> with Code, Message, and a synthetic RequestId so the SDK
// has something to log even when we don't track requests.
type xmlErrorEnvelope struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	RequestID string   `xml:"RequestId"`
}

func writeXMLError(w http.ResponseWriter, m errorMapping) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(m.Status)
	body, _ := xml.MarshalIndent(xmlErrorEnvelope{
		Code:      m.Code,
		Message:   m.Message,
		RequestID: "fakeaws-synthetic",
	}, "", "  ")
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(body)
}

// queryRPCErrorEnvelope wraps the XML-error inside a Query-API
// <ErrorResponse> envelope, which is what EC2 / RDS / IAM emit. The
// SDK parses ErrorResponse.Error.{Code,Message,Type}.
type queryRPCErrorEnvelope struct {
	XMLName   xml.Name             `xml:"ErrorResponse"`
	Error     queryRPCErrorPayload `xml:"Error"`
	RequestID string               `xml:"RequestId"`
}
type queryRPCErrorPayload struct {
	Type    string `xml:"Type"`
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

func writeQueryRPCError(w http.ResponseWriter, m errorMapping) {
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(m.Status)
	body, _ := xml.MarshalIndent(queryRPCErrorEnvelope{
		Error: queryRPCErrorPayload{
			Type:    "Sender",
			Code:    m.Code,
			Message: m.Message,
		},
		RequestID: "fakeaws-synthetic",
	}, "", "  ")
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(body)
}

// jsonError is the wire shape JSON 1.0 / 1.1 / JSON-REST share. The
// `__type` field is what the SDK parses to decide which exception type
// to surface to the caller. Different protocols use slightly different
// content-types; the body shape itself is identical.
type jsonError struct {
	Type    string `json:"__type"`
	Message string `json:"message"`
}

func writeJSON10Error(w http.ResponseWriter, m errorMapping) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.0")
	w.WriteHeader(m.Status)
	body, _ := json.Marshal(jsonError{Type: m.Type, Message: m.Message})
	_, _ = w.Write(body)
}

func writeJSON11Error(w http.ResponseWriter, m errorMapping) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(m.Status)
	body, _ := json.Marshal(jsonError{Type: m.Type, Message: m.Message})
	_, _ = w.Write(body)
}

func writeJSONRESTError(w http.ResponseWriter, m errorMapping) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(m.Status)
	body, _ := json.Marshal(jsonError{Type: m.Type, Message: m.Message})
	_, _ = w.Write(body)
}

// formatError is a thin convenience used by handler-side tests that
// want the same wire bytes the writer would emit. Shouldn't be used in
// handler code — handlers call WriteAWSError directly.
func formatError(shape WireShape, err error) (int, string, []byte) {
	mapping := mapDomainError(err)
	w := newCapture()
	switch shape {
	case ShapeXML:
		writeXMLError(w, mapping)
	case ShapeQueryRPC:
		writeQueryRPCError(w, mapping)
	case ShapeJSON10:
		writeJSON10Error(w, mapping)
	case ShapeJSON11:
		writeJSON11Error(w, mapping)
	case ShapeJSONREST:
		writeJSONRESTError(w, mapping)
	default:
		return 0, "", nil
	}
	return w.status, w.headers.Get("Content-Type"), w.body
}

// captureWriter is a minimal http.ResponseWriter for test-side capture
// so we don't have to spin up an httptest.Server just to inspect a
// rendered error envelope.
type captureWriter struct {
	headers http.Header
	body    []byte
	status  int
}

func newCapture() *captureWriter { return &captureWriter{headers: http.Header{}} }
func (c *captureWriter) Header() http.Header { return c.headers }
func (c *captureWriter) Write(b []byte) (int, error) {
	c.body = append(c.body, b...)
	return len(b), nil
}
func (c *captureWriter) WriteHeader(s int) { c.status = s }

// debugDescribe is used only by the audit test at the bottom of
// awsproto_test.go to produce diagnostic output when a cell fails. It
// is not part of the package's public surface.
func debugDescribe(shape WireShape, err error) string {
	status, ct, body := formatError(shape, err)
	return fmt.Sprintf("shape=%s err=%v status=%d ct=%s body=%s",
		shape, err, status, ct, string(body))
}
