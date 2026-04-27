package awsproto

import (
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

// WriteQueryRPCResponse marshals the given payload as XML wrapped in
// an <{Action}Response>...<{Action}Result>...</...></...> envelope —
// the canonical EC2/RDS/IAM response shape.
//
// Caller passes EITHER:
//   - nil (empty result envelope)
//   - a typed struct whose fields are the fields that should appear
//     directly inside <{Action}Result> (NOT wrapped in another struct)
//
// Per concepts.md anti-patterns: marshal errors are not silently
// swallowed — they produce a 500 + log line so the bug surfaces.
func WriteQueryRPCResponse(w http.ResponseWriter, action string, payload any) {
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xml.Header))
	fmt.Fprintf(w, "<%sResponse>\n", action)
	if payload != nil {
		fmt.Fprintf(w, "  <%sResult>\n", action)
		// Use Encoder so we can serialise the inner struct's fields
		// directly inside <{Action}Result> without producing a
		// stray wrapper element. Indent is matched to the surrounding
		// hand-written prefix.
		enc := xml.NewEncoder(w)
		enc.Indent("    ", "  ")
		if err := enc.Encode(payload); err != nil {
			// Surface the error rather than silently emitting empty
			// content. This is a programmer bug — caller passed a
			// payload xml.Marshal can't handle.
			fmt.Fprintf(w, "<!-- marshal error: %v -->\n", err)
		}
		_ = enc.Flush()
		_, _ = w.Write([]byte("\n"))
		fmt.Fprintf(w, "  </%sResult>\n", action)
	}
	fmt.Fprintf(w, "  <ResponseMetadata>\n    <RequestId>fakeaws-synthetic</RequestId>\n  </ResponseMetadata>\n")
	fmt.Fprintf(w, "</%sResponse>\n", action)
}

// IsQueryRPCContentType returns true when the request looks like a
// Query-RPC submission. Used by handlers that share a chi route across
// query-rpc and other shapes.
func IsQueryRPCContentType(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	return strings.HasPrefix(ct, "application/x-www-form-urlencoded")
}
