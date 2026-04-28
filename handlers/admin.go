package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/redscaresu/fakeaws/models"
)

// /mock/state schema (versioned via the top-level "schema_version" key
// so topology_derive_aws can detect breaking changes). Documented
// inline so the contract is stable from S43 onwards.
//
//	{
//	  "schema_version": 1,
//	  "iam":            {"roles": [...], "policies": [...], ...},
//	  "s3":             {"buckets": [...]},
//	  "ec2":            {...},
//	  "rds":            {...},
//	  "dynamodb":       {...},
//	  "eks":            {...},
//	  "sqs":            {...},
//	  "secretsmanager": {...},
//	  "route53":        {...},
//	  "operations":     [...],   // bookkeeping; ignored by countOrphans
//	  "audit":          [...]    // request log; ignored by countOrphans
//	}
//
// Per concepts.md "Required surface" item 4 (S43-T4 acceptance): the
// schema is documented inline so topology_derive_aws has a stable
// contract. Per-service blocks land as services arrive (IAM in S43-T5,
// S3 in S43-T7, etc.).
const stateSchemaVersion = 1

// registerAdminRoutes wires the /mock/* admin endpoints. Per concepts.md
// § "Lessons we are explicitly carrying over" item 7: admin lifecycle
// in one file, no auth required (mockway and fakegcp follow the same
// convention — admin endpoints are unauthenticated by design).
func (app *Application) registerAdminRoutes(r chi.Router) {
	r.Route("/mock", func(mr chi.Router) {
		mr.Post("/reset", app.handleMockReset)
		mr.Post("/snapshot", app.handleMockSnapshot)
		mr.Post("/restore", app.handleMockRestore)
		mr.Get("/state", app.handleMockState)
		mr.Get("/state/{service}", app.handleMockStateService)
	})
}

func (app *Application) handleMockReset(w http.ResponseWriter, _ *http.Request) {
	if err := app.repo.Reset(); err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]any{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (app *Application) handleMockSnapshot(w http.ResponseWriter, _ *http.Request) {
	if err := app.repo.Snapshot(); err != nil {
		// Snapshot on :memory: returns ErrConflict — expose as 409.
		status := http.StatusInternalServerError
		if errors.Is(err, models.ErrConflict) {
			status = http.StatusConflict
		}
		writeJSONStatus(w, status, map[string]any{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (app *Application) handleMockRestore(w http.ResponseWriter, _ *http.Request) {
	if err := app.repo.Restore(); err != nil {
		// ErrNotFound = no snapshot baseline (404).
		// ErrConflict = :memory: db (409).
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, models.ErrNotFound):
			status = http.StatusNotFound
		case errors.Is(err, models.ErrConflict):
			status = http.StatusConflict
		}
		writeJSONStatus(w, status, map[string]any{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (app *Application) handleMockState(w http.ResponseWriter, _ *http.Request) {
	state := app.collectState("")
	writeJSONStatus(w, http.StatusOK, state)
}

func (app *Application) handleMockStateService(w http.ResponseWriter, r *http.Request) {
	service := chi.URLParam(r, "service")
	state := app.collectState(service)
	writeJSONStatus(w, http.StatusOK, state)
}

// collectState gathers the per-service state into the documented shape.
// service == "" returns the full state; otherwise just the named
// service's block (or an empty object if the service hasn't shipped
// handlers yet).
//
// Service-specific gather methods land per ticket: gatherIAMState in
// S43-T5/T6, gatherS3State in S43-T7/T8, etc. Each method returns the
// slice of resources for its service.
func (app *Application) collectState(service string) map[string]any {
	state := map[string]any{
		"schema_version": stateSchemaVersion,
		// Universal bookkeeping. countOrphans must continue to ignore
		// these on destroy assertions.
		"operations": []any{},
		"audit":      []any{},
	}

	// Per-service gather hooks. Each one returns either a populated
	// map for its service or an empty map. Adding a service is one
	// line here.
	state["iam"] = app.gatherIAMState()
	state["s3"] = app.gatherS3State()
	state["ec2"] = app.gatherEC2State()
	state["rds"] = app.gatherRDSStateReal()
	state["dynamodb"] = app.gatherDynamoDBStateReal()
	// eks/sqs/secretsmanager/route53 land per phase.

	if service == "" {
		return state
	}
	if val, ok := state[service]; ok {
		return map[string]any{
			"schema_version": stateSchemaVersion,
			service:          val,
		}
	}
	return map[string]any{
		"schema_version": stateSchemaVersion,
		service:          map[string]any{},
	}
}

// gatherIAMState returns the IAM block of /mock/state. Filled in by
// S43-T6 (handlers/iam.go::gatherIAMStateReal). Topology_derive_aws
// (S43-T9) keys off the documented shape.
func (app *Application) gatherIAMState() map[string]any {
	return app.gatherIAMStateReal()
}

// gatherS3State returns the S3 block, populated by S43-T8's real
// implementation in handlers/s3.go.
func (app *Application) gatherS3State() map[string]any {
	return app.gatherS3StateReal()
}

// gatherEC2State returns the EC2 block, populated by S44-T7's real
// implementation in handlers/ec2.go.
func (app *Application) gatherEC2State() map[string]any {
	return app.gatherEC2StateReal()
}

// writeJSONStatus is a small helper for the admin handlers; the
// awsproto package's response writers are designed for the
// AWS-shaped surface, but the /mock/* admin endpoints are
// fakeaws-internal JSON, not aws-shaped, so this helper avoids
// dragging in the protocol dispatch.
func writeJSONStatus(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	_, _ = w.Write(body)
	_, _ = w.Write([]byte("\n"))
}
