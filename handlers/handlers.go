// Package handlers wires the HTTP surface for fakeaws.
//
// One *Application owns one chi router and one repository handle.
// Per-service handlers (handlers/iam.go, handlers/s3.go, etc.) attach
// their routes inside RegisterRoutes. Per concepts.md § "Lessons we are
// explicitly carrying over" item 1: single-binary, single-process,
// no plugin layer.
package handlers

import (
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/redscaresu/fakeaws/repository"
)

// Application is the top-level wiring struct. Holds the chi router
// and the repository handle.
type Application struct {
	router *chi.Mux
	repo   *repository.Repository
	echo   bool
	dbPath string
}

// NewApplication boots an Application. dbPath is ":memory:" for
// in-memory SQLite or a filesystem path for persistent storage. echo
// toggles per-request method+path logging — useful for discovering
// unimplemented endpoints during provider integration testing.
//
// In S43-T4 this attaches the admin (/mock/*) routes; S43-T5/T6 add
// IAM; S43-T7/T8 add S3; later phases add the rest.
func NewApplication(dbPath string, echo bool) (*Application, error) {
	repo, err := repository.New(dbPath)
	if err != nil {
		return nil, err
	}
	app := &Application{
		router: chi.NewRouter(),
		repo:   repo,
		echo:   echo,
		dbPath: dbPath,
	}

	app.router.Use(middleware.Recoverer)
	if echo {
		app.router.Use(echoMiddleware)
	}
	app.RegisterRoutes(app.router)
	// AMI fixture set lives in every "common" region by default. This
	// is safe to run on every boot — repository.SeedAMI is idempotent.
	if err := app.SeedEC2AMIFixtures("000000000000", []string{
		"us-east-1", "us-east-2", "us-west-1", "us-west-2",
		"eu-west-1", "eu-west-2", "eu-central-1", "ap-southeast-1",
	}); err != nil {
		return nil, err
	}
	return app, nil
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
	app.registerIAMRoutes(r)
	app.registerS3Routes(r)
	app.registerEC2Routes(r)
	app.registerRDSRoutes(r)
	app.registerDynamoDBRoutes(r)
	app.registerEKSRoutes(r)
	// Everything else 501s with an UNIMPLEMENTED log line so the next
	// caller sees what's missing — no Moto-style silent fallback.
	r.NotFound(unimplementedHandler)
	r.MethodNotAllowed(unimplementedHandler)
}

// unimplementedHandler returns 501 and logs the request. Per
// concepts.md § "Anti-patterns explicitly forbidden" — no silent 200s.
// Callers see exactly what's missing.
func unimplementedHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("UNIMPLEMENTED: %s %s", r.Method, r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	_, _ = w.Write([]byte(`{"error":"unimplemented","message":"fakeaws does not yet model this endpoint; see logs for the method+path"}`))
}

func echoMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("echo: %s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
