package awsproto

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
