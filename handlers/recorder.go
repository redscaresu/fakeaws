package handlers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
)

// requestClass says how fakeaws answered a request. It does not come
// from the status: a site marks it, and only an unmarked answer is
// classed by status.
type requestClass string

const (
	classAnsweredFromRows requestClass = "answered-from-rows"
	classUnimplemented    requestClass = "unimplemented-501"

	// Not every gap is marked: concepts.md item 7 states which gaps never
	// are (an ignored parameter, a 200 that stores nothing, an always-empty
	// or always-404 answer), with examples; they record answered-from-rows.

	// CRITICAL[request-log-not-modelled-404]: the default arm of EC2,
	// IAM, RDS, DynamoDB, SQS, Secrets Manager and KMS marks an
	// unknown action not-modelled-404. Its 404 ResourceNotFoundException
	// is wire-identical to a missing row's, so only the mark tells them
	// apart. A modelled action that stores nothing is not marked.
	classNotModelled404 requestClass = "not-modelled-404"

	// CRITICAL[request-log-filter-refused]: a site that refuses what real
	// AWS would accept but fakeaws does not model (a filter, a parameter,
	// a tag resource type, or a required-parameter check stricter than
	// AWS's) marks filter-refused: every EC2 site through ec2Refuse, 501
	// NotImplemented, RDS and Route53 at 400, SSM at 501. A refusal AWS
	// makes too, a modelled 409 and a filter or parameter fakeaws ignores
	// rather than refuses stay answered-from-rows.
	classFilterRefused requestClass = "filter-refused"

	// CRITICAL[request-log-empty-collection]: only ec2DescribeNone, the
	// Describe of a resource fakeaws never creates, and
	// DescribeAvailabilityZones on a loaded database with no zone rows
	// for the region mark empty-collection. Other always-empty answers,
	// and an empty answer read from rows, stay answered-from-rows.
	classEmptyCollection requestClass = "empty-collection"
)

// requestEntry is one recorded provider request, as GET /mock/requests
// returns it. Its path and params hold values (a bucket, a key, a
// parameter value), so it lives only in process memory.
type requestEntry struct {
	Method         string       `json:"method"`
	Path           string       `json:"path"`
	Status         int          `json:"status"`
	Classification requestClass `json:"classification"`
	readSetEntry
}

// ADR-0041's read-set protocols.
const (
	protocolQuery = "query"
	protocolJSON  = "json"
	protocolREST  = "rest"
)

// serviceProtocols is the protocol each LandedServices id speaks: its
// dispatcher calls awsproto.ParseQueryRPC (query) or
// awsproto.ParseXAmzTarget (json), or it routes by path (rest).
var serviceProtocols = map[string]string{
	"ec2": protocolQuery, "iam": protocolQuery, "rds": protocolQuery, "sts": protocolQuery,
	"dynamodb": protocolJSON, "kms": protocolJSON, "secretsmanager": protocolJSON, "sqs": protocolJSON, "ssm": protocolJSON,
	"eks": protocolREST, "route53": protocolREST, "s3": protocolREST,
}

// readSetEntry is a request as ADR-0041's read-set entry.
//
// CRITICAL[request-log-read-set-entry]: a query entry's action is the
// form body's Action and its params every other field but Version, one
// string each; a json entry's action is the operation after the dot in
// X-Amz-Target and its params the body's JSON object, verbatim; a rest
// entry's action is "<METHOD> <route pattern>" and its params the raw
// path and query, so two S3 subresources on one bucket differ in
// params.query. A body that does not parse, a query body that repeats
// a key or a json body that is not an object records null params. A
// path no landed service owns records an empty service, protocol and
// action, and a request chi routes to no handler (its NotFound or
// MethodNotAllowed) an empty action.
type readSetEntry struct {
	Service  string `json:"service"`
	Protocol string `json:"protocol"`
	Action   string `json:"action"`
	Params   any    `json:"params"`
}

// restParams is a rest entry's params.
type restParams struct {
	Path  string `json:"path"`
	Query string `json:"query"`
}

// readSet is r's read-set entry, but for a rest entry's action, which
// needs the route chi has not matched yet. It reads a query or json
// body, never through r.ParseForm, and puts back one that reads the
// same; on a read error it records no action, since the handler reads
// the same error and refuses. It never reads a rest body, so an S3
// upload is not buffered.
func readSet(r *http.Request) readSetEntry {
	e := readSetEntry{Service: serviceOf(r.URL.Path)}
	e.Protocol = serviceProtocols[e.Service]
	switch e.Protocol {
	case protocolREST:
		e.Params = restParams{Path: r.URL.EscapedPath(), Query: r.URL.RawQuery}
	case protocolQuery:
		if body, err := replayBody(r); err == nil {
			e.Action, e.Params = queryReadSet(body)
		}
	case protocolJSON:
		if body, err := replayBody(r); err == nil {
			e.Action, e.Params = jsonReadSet(r.Header.Get("X-Amz-Target"), body)
		}
	}
	return e
}

// replayBody reads r's body and puts back a reader of the same bytes,
// then the same read error, so the handler reads what it would have.
func replayBody(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	var replay io.Reader = bytes.NewReader(body)
	if err != nil {
		replay = io.MultiReader(replay, errReader{err})
	}
	r.Body = io.NopCloser(replay)
	return body, err
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

// queryReadSet is a form body's Action, as awsproto.ParseQueryRPC reads
// it, and its other fields but Version.
func queryReadSet(body []byte) (string, map[string]string) {
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return "", nil
	}
	params := map[string]string{}
	for k, v := range values {
		if len(v) != 1 {
			return values.Get("Action"), nil
		}
		if k != "Action" && k != "Version" {
			params[k] = v[0]
		}
	}
	return values.Get("Action"), params
}

// jsonReadSet is target's operation, as awsproto.ParseXAmzTarget reads
// it, and body when it is a JSON object.
func jsonReadSet(target string, body []byte) (string, json.RawMessage) {
	_, op, _ := strings.Cut(target, ".")
	body = bytes.TrimSpace(body)
	if !bytes.HasPrefix(body, []byte("{")) || !json.Valid(body) {
		return op, nil
	}
	return op, body
}

// routePattern is the route chi matched, each mount's "/*" joint
// dropped. Unlike chi's RoutePattern it keeps the trailing slash, so an
// S3 bucket route is "/s3/{bucket}/", as ADR-0041 writes it.
func routePattern(r *http.Request) string {
	p := strings.Join(chi.RouteContext(r.Context()).RoutePatterns, "")
	for strings.Contains(p, "/*/") || strings.Contains(p, "//") {
		p = strings.ReplaceAll(strings.ReplaceAll(p, "/*/", "/"), "//", "/")
	}
	return p
}

// auditEntry is one /mock/state audit entry: a request log entry
// without its method, path and params.
//
// CRITICAL[state-audit-no-values]: an audit entry carries exactly
// service, protocol, action, status and class, never a path, params or
// values: infrafactory writes /mock/state into run artifacts. service
// is a LandedServices id, or empty for any other path. A query or json
// action is client text, so the audit carries it only in an operation
// name's shape (operationName), else empty; a rest action is the
// method and the route chi matched, never the path.
type auditEntry struct {
	Service  string       `json:"service"`
	Protocol string       `json:"protocol"`
	Action   string       `json:"action"`
	Status   int          `json:"status"`
	Class    requestClass `json:"class"`
}

// requestLog is the request log: a mutex-guarded slice, not SQLite, so
// the db and the snapshot never hold a request and no request waits on
// the db's one connection. /mock/reset clears it; snapshot and restore
// leave it; a restart empties it. A nil *requestLog records nothing.
type requestLog struct {
	mu      sync.Mutex
	entries []requestEntry
}

func (l *requestLog) append(e requestEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, e)
}

func (l *requestLog) clear() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = nil
}

func (l *requestLog) list() []requestEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]requestEntry{}, l.entries...)
}

// operationName is the shape of an AWS operation name.
var operationName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,127}$`)

// audit is the log as /mock/state's audit block.
func (l *requestLog) audit() []auditEntry {
	out := []auditEntry{}
	if l == nil {
		return out
	}
	for _, e := range l.list() {
		action := e.Action
		if e.Protocol != protocolREST && !operationName.MatchString(action) {
			action = ""
		}
		out = append(out, auditEntry{Service: e.Service, Protocol: e.Protocol, Action: action, Status: e.Status, Class: e.Classification})
	}
	return out
}

// serviceOf is path's first segment when it names a landed service.
func serviceOf(path string) string {
	seg, _, _ := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	if slices.Contains(LandedServices, seg) {
		return seg
	}
	return ""
}

// recordingWriter catches the status a handler writes, the class it
// marks and whether the router found no handler.
type recordingWriter struct {
	http.ResponseWriter
	status   int
	class    requestClass
	unrouted bool
}

func (w *recordingWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *recordingWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// classification is the marked class, else unimplemented-501 for a
// status of 500 or more and answered-from-rows for anything else.
//
// CRITICAL[request-log-unimplemented-501]: the router's NotFound and
// MethodNotAllowed and every writeUnimplemented record unimplemented-501
// (unless the site marks again after it), as does an unmarked 5xx; a 5xx
// is never answered-from-rows. A marked class wins over the status, and
// the last mark wins.
func (w *recordingWriter) classification() requestClass {
	switch {
	case w.class != "":
		return w.class
	case w.status >= http.StatusInternalServerError:
		return classUnimplemented
	default:
		return classAnsweredFromRows
	}
}

// markClass sets the class w's request records; a later mark replaces
// it. It is a no-op when fakeaws is not recording. Mark only a gap:
// answered-from-rows is what an unmarked answer below 500 records.
func markClass(w http.ResponseWriter, class requestClass) {
	if rw, ok := w.(*recordingWriter); ok {
		rw.class = class
	}
}

// markUnrouted says chi routed w's request to no handler. It is a no-op
// when fakeaws is not recording.
func markUnrouted(w http.ResponseWriter) {
	if rw, ok := w.(*recordingWriter); ok {
		rw.unrouted = true
	}
}

// recordRequests appends every request outside /mock and /healthz to
// the log once its handler returns, so entries are in completion order
// and a rest entry's route is the one chi matched.
//
// CRITICAL[request-log-panic-recorded]: it runs inside
// middleware.Recoverer, so it sees a handler panic before Recoverer
// swallows it and records 500 unimplemented-501, whatever status the
// handler wrote first; a panic is never answered-from-rows.
func (app *Application) recordRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/mock" || strings.HasPrefix(r.URL.Path, "/mock/") {
			next.ServeHTTP(w, r)
			return
		}
		path := r.URL.Path // before stripRegionRootSlash rewrites it
		rs := readSet(r)
		rw := &recordingWriter{ResponseWriter: w}
		panicked := true
		defer func() { // runs while a panic unwinds on to Recoverer
			switch {
			case panicked:
				rw.status, rw.class = http.StatusInternalServerError, classUnimplemented
			case rw.status == 0:
				rw.status = http.StatusOK // net/http's answer when a handler writes nothing
			}
			switch {
			case rw.unrouted:
				rs.Action = ""
			case rs.Protocol == protocolREST:
				rs.Action = r.Method + " " + routePattern(r)
			}
			app.requests.append(requestEntry{Method: r.Method, Path: path, Status: rw.status, Classification: rw.classification(), readSetEntry: rs})
		}()
		next.ServeHTTP(rw, r)
		panicked = false
	})
}

func (app *Application) handleMockRequests(w http.ResponseWriter, _ *http.Request) {
	writeJSONStatus(w, http.StatusOK, map[string]any{"requests": app.requests.list()})
}

func (app *Application) handleMockRequestsClear(w http.ResponseWriter, _ *http.Request) {
	app.requests.clear()
	writeJSONStatus(w, http.StatusOK, map[string]any{"status": "ok"})
}
