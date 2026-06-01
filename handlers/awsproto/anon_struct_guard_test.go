package awsproto

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestWriteQueryRPCResponse_PanicsOnAnonMultiFieldStruct pins the
// N4 runtime guard. The historical footgun: a handler passes
// `&struct { A []string; B bool }{}` directly, xml.Encoder rejects
// the anonymous-type with "unsupported type," marshalInnerXML emits
// a `<!-- marshal error -->` comment inside the result wrapper, and
// the response is 200 with broken XML. Loose tests passed but live
// curl revealed the bug.
//
// Post-fix: the assertNotAnonStruct guard panics at the call site
// before any bytes are written, with a message naming the offending
// type and pointing at the canonical named-struct pattern.
func TestWriteQueryRPCResponse_PanicsOnAnonMultiFieldStruct(t *testing.T) {
	rec := httptest.NewRecorder()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for anonymous multi-field struct, got none")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("expected string panic, got %T: %v", r, r)
		}
		// Message must name the offending function AND point at the
		// named-struct fix pattern so the developer knows where to go.
		if !strings.Contains(msg, "WriteQueryRPCResponse") {
			t.Errorf("panic missing function name; got: %s", msg)
		}
		if !strings.Contains(msg, "anonymous multi-field struct") {
			t.Errorf("panic missing diagnosis; got: %s", msg)
		}
		if !strings.Contains(msg, "iamGetUserPolicyResult") {
			t.Errorf("panic missing canonical-pattern pointer; got: %s", msg)
		}
	}()
	WriteQueryRPCResponse(rec, "Anything", &struct {
		Foo []string
		Bar bool
	}{Foo: []string{"x"}, Bar: true})
}

// TestWriteEC2QueryRPCResponse_PanicsOnAnonMultiFieldStruct mirrors
// the IAM-shape test for the EC2 wire format. Same guard, same
// motivation.
func TestWriteEC2QueryRPCResponse_PanicsOnAnonMultiFieldStruct(t *testing.T) {
	rec := httptest.NewRecorder()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for anonymous multi-field struct, got none")
		}
		msg, _ := r.(string)
		if !strings.Contains(msg, "WriteEC2QueryRPCResponse") {
			t.Errorf("panic should name the entry point; got: %s", msg)
		}
	}()
	WriteEC2QueryRPCResponse(rec, "DescribeAnything", &struct {
		A int
		B int
	}{A: 1, B: 2})
}

// TestWriteQueryRPCResponse_AllowsNamedStruct confirms the guard's
// happy path. A named struct (even unexported and even with multiple
// fields) MUST pass through cleanly — this is the canonical pattern
// the panic message points at.
type namedRoundTripResult struct {
	One []string `xml:"One>member,omitempty"`
	Two bool     `xml:"Two"`
}

func TestWriteQueryRPCResponse_AllowsNamedStruct(t *testing.T) {
	rec := httptest.NewRecorder()
	// No defer/recover: this must NOT panic.
	WriteQueryRPCResponse(rec, "Test", &namedRoundTripResult{Two: true})
	body := rec.Body.String()
	if !strings.Contains(body, "<TestResult>") {
		t.Errorf("missing <TestResult> wrapper: %s", body)
	}
	if strings.Contains(body, "marshal error") {
		t.Errorf("named struct should not produce marshal-error comment: %s", body)
	}
}

// TestWriteQueryRPCResponse_SingleFieldAnonStruct_TolerableBreakage
// documents the carve-out for single-field anonymous structs and the
// reason behind it.
//
// Finding from the N4 work: single-field anonymous structs DO produce
// the same `<!-- marshal error: xml: unsupported type -->` comment that
// multi-field ones do. The XML body is technically broken (no
// <Groups>...</Groups> element emitted). BUT — the existing
// `iamListGroupsForUser` handler uses this shape, and the
// terraform-provider-aws XML parser tolerates the malformed body
// because it's looking for `Groups>member` children: when neither
// `Groups` nor `member` elements are found, the parser treats the
// list as empty. Empty groups list is exactly what the destroy-
// preflight wants (no groups to detach before DeleteUser).
//
// So single-field anon structs work BY ACCIDENT: the marshal-error
// comment IS in the body, but the provider's "missing element ==
// empty list" tolerance happens to give the correct semantic.
//
// Why not panic anyway? Because tightening the guard would force a
// refactor of `iamListGroupsForUser` and any other one-field anon
// callers, with no actual behavioural fix — the response output
// would change from "comment instead of empty list" to "named empty
// list," which the provider already treats identically. Churn-only
// refactor.
//
// Future work (separate ticket): convert iamListGroupsForUser to a
// named struct anyway, on aesthetic + future-proofing grounds.
// When that lands, tighten the guard's NumField check from `> 1` to
// `> 0`.
func TestWriteQueryRPCResponse_SingleFieldAnonStruct_TolerableBreakage(t *testing.T) {
	rec := httptest.NewRecorder()
	// No panic — guard intentionally exempts single-field.
	WriteQueryRPCResponse(rec, "ListGroupsForUser", &struct {
		Groups []string `xml:"Groups>member,omitempty"`
	}{})
	body := rec.Body.String()
	if !strings.Contains(body, "<ListGroupsForUserResult>") {
		t.Errorf("missing result wrapper: %s", body)
	}
	// Document the actual (broken-but-tolerated) behaviour. If this
	// flips to "no marshal error" — e.g. xml.Encoder learns to handle
	// anonymous structs in a future Go release — that's strictly an
	// improvement and the test should be updated to forbid the
	// marshal-error comment outright.
	if !strings.Contains(body, "marshal error") {
		t.Logf("UPDATE: xml.Encoder now handles single-field anon structs cleanly. Tighten this test to forbid 'marshal error' and consider tightening the guard's NumField threshold.")
	}
}

// TestWriteQueryRPCResponse_NilPayloadIsHandled confirms nil
// payload (a legitimate use — no <Result> wrapper emitted) is not
// dereferenced by the guard.
func TestWriteQueryRPCResponse_NilPayloadIsHandled(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteQueryRPCResponse(rec, "AttachUserPolicy", nil)
	body := rec.Body.String()
	if strings.Contains(body, "<AttachUserPolicyResult>") {
		t.Errorf("nil payload should skip the Result wrapper: %s", body)
	}
	if !strings.Contains(body, "<AttachUserPolicyResponse>") {
		t.Errorf("nil payload should still emit the outer envelope: %s", body)
	}
}
