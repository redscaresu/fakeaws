package awsproto

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
)

// QueryRPCRequest is the parsed form of a Query-RPC request. Used by
// EC2, RDS, and IAM. Action selects the operation; Version pins the
// API year-month-day; Params is everything else.
type QueryRPCRequest struct {
	Action  string
	Version string
	Params  url.Values
}

// ParseQueryRPC reads a Query-RPC request body. The format is
// application/x-www-form-urlencoded with Action=<op>&Version=<api>
// plus per-action parameters. Returns an error if Action is missing
// or the body fails to parse.
//
// Caller is expected to have validated the Content-Type before
// calling — this helper is just the body parser.
func ParseQueryRPC(r *http.Request) (QueryRPCRequest, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return QueryRPCRequest{}, fmt.Errorf("read body: %w", err)
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return QueryRPCRequest{}, fmt.Errorf("parse form: %w", err)
	}
	action := values.Get("Action")
	if action == "" {
		return QueryRPCRequest{}, fmt.Errorf("missing Action parameter")
	}
	version := values.Get("Version")
	values.Del("Action")
	values.Del("Version")
	return QueryRPCRequest{
		Action:  action,
		Version: version,
		Params:  values,
	}, nil
}

// WriteQueryRPCResponse emits the IAM / RDS envelope shape:
//
//	<{Action}Response>
//	  <{Action}Result>
//	    ...payload...
//	  </{Action}Result>
//	  <ResponseMetadata><RequestId>...</RequestId></ResponseMetadata>
//	</{Action}Response>
//
// The payload is rendered inside <{Action}Result> with the Go-type
// wrapper element stripped — see marshalInnerXML for the rule that
// distinguishes a "transparent" Result struct (no XMLName tag, type
// name leaks as `<iamListRolePoliciesResult>`) from a legitimate AWS
// element (XMLName set to e.g. `AccessKey`).
//
// For EC2-style responses without a <{Action}Result> wrapper, use
// WriteEC2QueryRPCResponse instead. EC2's wire shape places the
// payload as a direct child of <{Action}Response>.
func WriteQueryRPCResponse(w http.ResponseWriter, action string, payload any) {
	if payload != nil {
		assertNotAnonStruct(payload, "WriteQueryRPCResponse")
	}
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xml.Header))
	fmt.Fprintf(w, "<%sResponse>\n", action)
	if payload != nil {
		fmt.Fprintf(w, "  <%sResult>\n", action)
		writeMarshalledPayload(w, payload, "    ")
		fmt.Fprintf(w, "  </%sResult>\n", action)
	}
	fmt.Fprintf(w, "  <ResponseMetadata>\n    <RequestId>fakeaws-synthetic</RequestId>\n  </ResponseMetadata>\n")
	fmt.Fprintf(w, "</%sResponse>\n", action)
}

// WriteEC2QueryRPCResponse emits the EC2 envelope shape:
//
//	<{Action}Response>
//	  <requestId>fakeaws-synthetic</requestId>
//	  ...payload...
//	</{Action}Response>
//
// EC2 has no <{Action}Result> wrapper — the response body is a
// direct child of <{Action}Response>, and the request id uses
// camelCase (`requestId`) instead of the PascalCase
// `<ResponseMetadata><RequestId>` block. terraform-provider-aws's
// EC2 XML parser keys off this exact shape; the IAM-style envelope
// hid <vpc> / <instance> / etc. behind an extra wrapper that the
// parser couldn't see through, panicking the provider plugin on
// nil dereference (M51).
func WriteEC2QueryRPCResponse(w http.ResponseWriter, action string, payload any) {
	if payload != nil {
		assertNotAnonStruct(payload, "WriteEC2QueryRPCResponse")
	}
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xml.Header))
	fmt.Fprintf(w, "<%sResponse>\n", action)
	fmt.Fprintf(w, "  <requestId>fakeaws-synthetic</requestId>\n")
	if payload != nil {
		writeMarshalledPayload(w, payload, "  ")
	}
	fmt.Fprintf(w, "</%sResponse>\n", action)
}

// assertNotAnonStruct panics if payload is an anonymous multi-field
// struct (one with no declared type name AND more than one field).
//
// Background: xml.Encoder's reflection-based marshaller refuses
// anonymous-struct types — it returns
// `xml: unsupported type: struct { ... }` which marshalInnerXML
// converts to a `<!-- marshal error: ... -->` comment inside the
// result wrapper. The HTTP response is still 200 (loose tests
// passed), but the body was empty/malformed, breaking the provider's
// XML parser at the boundary. This footgun bit the 2026-06-01
// session twice (T1 GetUserPolicy initially; Ticket A first-wave
// destroy-preflight handlers SSH/MFA/SigningCerts/ServiceCreds —
// `fd8e5d1` flipped them to named structs).
//
// Single-field anonymous structs happen to slip past xml.Encoder
// (`iamListGroupsForUser` uses one and works) but only by accident.
// This guard is conservative: panics only on >1 field so existing
// single-field anon-struct callers keep working without a forced
// refactor.
//
// Panics with a message that names the offending Go type and points
// at the canonical named-struct pattern. Fires at first call, so
// every test that exercises a handler with this misuse fails
// immediately at the assertion (clear stack trace) — versus
// silently emitting a broken response.
func assertNotAnonStruct(payload any, fn string) {
	v := reflect.ValueOf(payload)
	for v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return
	}
	t := v.Type()
	// t.Name() == "" identifies anonymous structs (declared inline
	// at the call site). Named types — even unexported ones like
	// iamGetUserPolicyResult — always have a non-empty Name.
	if t.Name() != "" {
		return
	}
	if t.NumField() <= 1 {
		// Single-field anon structs marshal correctly by accident.
		// Leave them — flagging would force a churn-only refactor.
		return
	}
	panic(fmt.Sprintf(
		"%s: payload is an anonymous multi-field struct (%s), which xml.Encoder rejects with 'unsupported type'. Declare a named struct (e.g. `type iamListXResult struct { ... }`) and pass &iamListXResult{...} instead. See iamGetUserPolicyResult in handlers/iam.go for the canonical pattern (no XMLName field; package-private name strips the wrapper via marshalInnerXML).",
		fn, t.String(),
	))
}

// writeMarshalledPayload marshals payload to XML and writes it to w
// at the given indent. Calls marshalInnerXML to strip the Go-type
// wrapper element that xml.Encoder always produces, but ONLY when
// the payload struct doesn't set XMLName explicitly (legitimate AWS
// element names like `<AccessKey>` are preserved).
func writeMarshalledPayload(w io.Writer, payload any, indent string) {
	body, err := marshalInnerXML(payload, indent)
	if err != nil {
		fmt.Fprintf(w, "%s<!-- marshal error: %v -->\n", indent, err)
		return
	}
	_, _ = w.Write(body)
}

// marshalInnerXML serialises payload to XML, then conditionally
// strips the outer element xml.Encoder adds (matching the struct's
// Go type name when XMLName is unset).
//
// Distinguishing transparent wrappers from legitimate elements:
//   - If the marshalled body's outer element starts with a lowercase
//     letter, it's a Go-type leak (Go package-internal types are
//     lowercase-prefix by convention: ec2CreateVpcResult,
//     iamListRolePoliciesResult). Strip it.
//   - If the outer element starts uppercase, it's the AWS element
//     name set via XMLName (Role, AccessKey, Vpc). Preserve it.
//
// The stripped form preserves indentation by prepending the indent
// to every line of the remaining body.
func marshalInnerXML(payload any, indent string) ([]byte, error) {
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)
	enc.Indent(indent, "  ")
	if err := enc.Encode(payload); err != nil {
		return nil, err
	}
	if err := enc.Flush(); err != nil {
		return nil, err
	}
	body := buf.Bytes()
	// Find the outer element name.
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) < 2 || trimmed[0] != '<' {
		// Fallback — emit as-is + newline.
		return append(body, '\n'), nil
	}
	// Element name ends at the first space, `>`, or `/`.
	nameEnd := 1
	for nameEnd < len(trimmed) && trimmed[nameEnd] != '>' && trimmed[nameEnd] != ' ' && trimmed[nameEnd] != '/' {
		nameEnd++
	}
	name := string(trimmed[1:nameEnd])
	if name == "" || name[0] < 'a' || name[0] > 'z' {
		// Uppercase-prefix → legitimate AWS element, keep wrapper.
		return append(body, '\n'), nil
	}
	// Lowercase-prefix → Go-type leak, strip outer wrapper.
	openEnd := bytes.IndexByte(body, '>')
	closeStart := bytes.LastIndex(body, []byte("</"+name))
	if openEnd < 0 || closeStart <= openEnd {
		return append(body, '\n'), nil
	}
	inner := bytes.TrimRight(body[openEnd+1:closeStart], " \t\n")
	inner = bytes.TrimLeft(inner, "\n")
	out := make([]byte, 0, len(inner)+1)
	out = append(out, inner...)
	out = append(out, '\n')
	return out, nil
}

// IsQueryRPCContentType returns true when the request looks like a
// Query-RPC submission. Used by handlers that share a chi route across
// query-rpc and other shapes.
func IsQueryRPCContentType(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	return strings.HasPrefix(ct, "application/x-www-form-urlencoded")
}
