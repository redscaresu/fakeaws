// Package handlers wires the HTTP surface for fakeaws.
//
// One *Application owns one chi router and one repository handle.
// Per-service handlers (handlers/iam.go, handlers/s3.go, etc.) attach
// their routes inside RegisterRoutes. Per concepts.md § "Lessons we are
// explicitly carrying over" item 1: single-binary, single-process,
// no plugin layer.
package handlers

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/redscaresu/fakeaws/repository"
)

// Application is the top-level wiring struct. Holds the chi router
// and the repository handle.
type Application struct {
	router     *chi.Mux
	repo       *repository.Repository
	echo       bool
	dbPath     string
	adminToken string
	requests   *requestLog // nil unless Options.RecordRequests
	// loadMaxBytes is Options.LoadMaxBytes.
	loadMaxBytes int64
	// identityMu is held shared by every AWS request, /mock/images and
	// /mock/state, from the account read to the last read or write, and
	// exclusively by everything that changes the identity or the db
	// handle (setIdentity, /mock/reset, /mock/restore, /mock/load) and
	// by /mock/snapshot, so none of them lands between a handler's
	// account read and the rows it reads or writes under that account.
	identityMu sync.RWMutex
}

// Options configures an Application and the address it serves on.
type Options struct {
	// DBPath is ":memory:" for in-memory SQLite or a filesystem path
	// for persistent storage.
	DBPath string
	// Echo toggles per-request method+path logging, useful for
	// discovering unimplemented endpoints.
	Echo bool
	// Bind is the listen host; empty listens on all interfaces.
	Bind string
	Port int
	// AdminToken, when set, gates /mock/* behind a loopback-Origin
	// check and `Authorization: Bearer <AdminToken>`.
	AdminToken string
	// AccountID, when set, is stored as the account fakeaws answers as,
	// with Region; NewApplication refuses a different account on a
	// database that is not empty. Empty leaves the stored identity alone.
	AccountID string
	Region    string
	// RecordRequests keeps an in-process log of every provider request,
	// served on GET /mock/requests. The log holds request values, so
	// NewApplication refuses it without an AdminToken.
	//
	// CRITICAL[request-log-off-by-default]: without it nothing is
	// recorded, /mock/state's audit is [], and /mock/requests and
	// /mock/requests/clear are the router's 501.
	RecordRequests bool
	// LoadMaxBytes, when above 0, serves POST /mock/load, which takes a
	// recorded read of at most this many bytes; 0 leaves it unrouted.
	// cmd/fakeaws refuses it without an AdminToken.
	LoadMaxBytes int64
}

// ListenAddr is the address to listen on.
//
// CRITICAL[listen-addr-default-all-interfaces]: an empty Bind gives
// ":<port>", all interfaces, as fakeaws always listened, so callers that
// reach it from another host or a published container port keep
// working; a set Bind, IPv6 included, is joined as host:port.
func (o Options) ListenAddr() string {
	return net.JoinHostPort(o.Bind, strconv.Itoa(o.Port))
}

// ErrRecordRequestsNeedsAdminToken is NewApplication's refusal of
// RecordRequests without an AdminToken.
var ErrRecordRequestsNeedsAdminToken = errors.New("recording requests needs an admin token: the log holds request values")

// NewApplication boots an Application from opts.
//
// In S43-T4 this attaches the admin (/mock/*) routes; S43-T5/T6 add
// IAM; S43-T7/T8 add S3; later phases add the rest.
//
// CRITICAL[request-log-needs-admin-token]: RecordRequests without an
// AdminToken is ErrRecordRequestsNeedsAdminToken before the db opens, so
// no caller can serve the log, whose paths hold values, unauthenticated.
func NewApplication(opts Options) (*Application, error) {
	if opts.RecordRequests && opts.AdminToken == "" {
		return nil, ErrRecordRequestsNeedsAdminToken
	}
	repo, err := repository.New(opts.DBPath)
	if err != nil {
		return nil, err
	}
	app := &Application{
		router:       chi.NewRouter(),
		repo:         repo,
		echo:         opts.Echo,
		dbPath:       opts.DBPath,
		adminToken:   opts.AdminToken,
		loadMaxBytes: opts.LoadMaxBytes,
	}

	app.router.Use(middleware.Recoverer)
	if opts.RecordRequests {
		app.requests = &requestLog{}
		app.router.Use(app.recordRequests) // inside Recoverer, to see the panic
	}
	app.router.Use(stripRegionRootSlash)
	if opts.Echo {
		app.router.Use(echoMiddleware)
	}
	app.RegisterRoutes(app.router)
	if err := app.boot(opts); err != nil {
		_ = repo.Close()
		return nil, err
	}
	return app, nil
}

// boot stores opts' identity when one is set, then, unless the
// database is loaded, gives each VPC stored without one its default
// security group and seeds the AMI fixture set under the stored
// account in every "common" region. This is safe to run on every boot
// — both are idempotent.
func (app *Application) boot(opts Options) error {
	if opts.AccountID != "" {
		if err := app.setIdentity(repository.Identity{AccountID: opts.AccountID, Region: opts.Region}); err != nil {
			return err
		}
	}
	account, err := app.AccountID()
	if err != nil {
		return err
	}
	if err := app.repo.BackfillDefaultGroups(newDefaultGroup); err != nil {
		return fmt.Errorf("backfill default security groups: %w", err)
	}
	loaded, err := app.repo.Loaded()
	if err != nil {
		return fmt.Errorf("read loaded flag: %w", err)
	}
	if loaded {
		return nil
	}
	return app.SeedEC2AMIFixtures(account, []string{
		"us-east-1", "us-east-2", "us-west-1", "us-west-2",
		"eu-west-1", "eu-west-2", "eu-central-1", "ap-southeast-1",
	})
}

// Router returns the chi router for serving HTTP traffic.
func (app *Application) Router() http.Handler { return app.router }

// Repository exposes the underlying repository handle. Mostly used by
// tests and handler-side helpers; everyday code should reach for the
// typed methods on Application.
func (app *Application) Repository() *repository.Repository { return app.repo }

// Close releases any resources the Application holds. Safe to call
// multiple times.
func (app *Application) Close() error {
	if app.repo == nil {
		return nil
	}
	err := app.repo.Close()
	app.repo = nil
	return err
}

// RegisterRoutes attaches every handler to the router. New services
// add a single call here (e.g., app.registerIAMRoutes(r)) — that's the
// "adding a service is one Go file" contract.
func (app *Application) RegisterRoutes(r chi.Router) {
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	app.registerAdminRoutes(r)
	r.Group(func(r chi.Router) {
		r.Use(app.holdIdentity)
		app.registerIAMRoutes(r)
		app.registerS3Routes(r)
		app.registerEC2Routes(r)
		app.registerRDSRoutes(r)
		app.registerDynamoDBRoutes(r)
		app.registerEKSRoutes(r)
		app.registerSQSRoutes(r)
		app.registerRoute53Routes(r)
		app.registerSecretsManagerRoutes(r)
		app.registerKMSRoutes(r)
		app.registerSTSRoutes(r)
		app.registerSSMRoutes(r)
	})
	// Everything else 501s with an UNIMPLEMENTED log line so the next
	// caller sees what's missing — no Moto-style silent fallback.
	r.NotFound(unimplementedHandler)
	r.MethodNotAllowed(unimplementedHandler)
}

// unimplementedHandler is the router's NotFound and MethodNotAllowed: it
// marks the request unrouted, returns 501 and logs it. Per concepts.md
// § "Anti-patterns explicitly forbidden" — no silent 200s.
// Callers see exactly what's missing.
func unimplementedHandler(w http.ResponseWriter, r *http.Request) {
	markUnrouted(w)
	writeUnimplemented(w, r.Method+" "+r.URL.Path)
}

// writeUnimplemented is unimplementedHandler for a dispatcher that
// routed the request but does not model its action; what names it.
// It marks unimplemented-501; a caller may mark another class after.
func writeUnimplemented(w http.ResponseWriter, what string) {
	markClass(w, classUnimplemented)
	log.Printf("UNIMPLEMENTED: %s", what)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	_, _ = w.Write([]byte(`{"error":"unimplemented","message":"fakeaws does not yet model this endpoint; see logs for the method+path"}`))
}

// regionRoot matches a service's region endpoint with a trailing slash,
// e.g. /ssm/region/us-east-1/. smithy-go 1.28.2 keeps the trailing slash
// when it joins a path-style BaseEndpoint with an operation path of "/",
// so SDK clients now send that form.
var regionRoot = regexp.MustCompile(`^/[a-z0-9-]+/region/[^/]+/$`)

// stripRegionRootSlash routes /<svc>/region/<region>/ like
// /<svc>/region/<region>. Only the region root: S3 paths keep their
// trailing slash, where it is meaningful.
func stripRegionRootSlash(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if regionRoot.MatchString(r.URL.Path) {
			r.URL.Path = r.URL.Path[:len(r.URL.Path)-1]
			r.URL.RawPath = ""
		}
		next.ServeHTTP(w, r)
	})
}

// holdIdentity holds identityMu shared for the whole request.
func (app *Application) holdIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		app.identityMu.RLock()
		defer app.identityMu.RUnlock()
		next.ServeHTTP(w, r)
	})
}

func echoMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("echo: %s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
