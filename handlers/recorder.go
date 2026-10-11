package handlers

import (
	"net/http"
	"slices"
	"strings"
	"sync"
)

// requestClass says how fakeaws answered a request. It does not come
// from the status: a site marks it, and only an unmarked answer is
// classed by status.
type requestClass string

const (
	classAnsweredFromRows requestClass = "answered-from-rows"
	classUnimplemented    requestClass = "unimplemented-501"
)

// requestEntry is one recorded provider request, as GET /mock/requests
// returns it. Its path holds values (a bucket, a key, a secret name), so
// it lives only in process memory.
type requestEntry struct {
	Method         string       `json:"method"`
	Path           string       `json:"path"`
	Status         int          `json:"status"`
	Classification requestClass `json:"classification"`
}

// auditEntry is one /mock/state audit entry. protocol and action are
// empty until the request log reads the action.
//
// CRITICAL[state-audit-no-values]: an audit entry carries exactly
// service, protocol, action, status and class, never a path, params or
// values: infrafactory writes /mock/state into run artifacts. service
// is a LandedServices id, or empty for any other path.
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

// audit is the log as /mock/state's audit block.
func (l *requestLog) audit() []auditEntry {
	out := []auditEntry{}
	if l == nil {
		return out
	}
	for _, e := range l.list() {
		out = append(out, auditEntry{Service: serviceOf(e.Path), Status: e.Status, Class: e.Classification})
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

// recordingWriter catches the status a handler writes and the class it
// marks.
type recordingWriter struct {
	http.ResponseWriter
	status int
	class  requestClass
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
// MethodNotAllowed and every writeUnimplemented record unimplemented-501,
// as does an unmarked 5xx; a 5xx is never answered-from-rows. A marked
// class wins over the status, and the last mark wins.
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

// recordRequests appends every request outside /mock and /healthz to
// the log once its handler returns, so entries are in completion order.
//
// CRITICAL[request-log-panic-recorded]: it is installed before
// middleware.Recoverer, so a handler that panics is recorded with the
// 500 Recoverer writes, never as answered-from-rows.
func (app *Application) recordRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/mock" || strings.HasPrefix(r.URL.Path, "/mock/") {
			next.ServeHTTP(w, r)
			return
		}
		path := r.URL.Path // before stripRegionRootSlash rewrites it
		rw := &recordingWriter{ResponseWriter: w}
		next.ServeHTTP(rw, r)
		if rw.status == 0 {
			rw.status = http.StatusOK // net/http's answer when a handler writes nothing
		}
		app.requests.append(requestEntry{Method: r.Method, Path: path, Status: rw.status, Classification: rw.classification()})
	})
}

func (app *Application) handleMockRequests(w http.ResponseWriter, _ *http.Request) {
	writeJSONStatus(w, http.StatusOK, map[string]any{"requests": app.requests.list()})
}

func (app *Application) handleMockRequestsClear(w http.ResponseWriter, _ *http.Request) {
	app.requests.clear()
	writeJSONStatus(w, http.StatusOK, map[string]any{"status": "ok"})
}
