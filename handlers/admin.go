package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/redscaresu/fakeaws/handlers/awsproto"
	"github.com/redscaresu/fakeaws/models"
	"github.com/redscaresu/fakeaws/repository"
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
//	  "ssm":            {"parameters": [...]},  // name, type, version, region; no values
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
		mr.Post("/images", app.handleMockSeedImage)
	})
}

var (
	// An EC2 image id: ami- then 8 (legacy) or 17 lowercase hex digits.
	amiIDPattern  = regexp.MustCompile(`^ami-([0-9a-f]{8}|[0-9a-f]{17})$`)
	regionPattern = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d$`)
)

var errInvalidAMIID = errors.New("ami_id must be ami- followed by 8 or 17 lowercase hex digits")

// maxSeedImageBodyBytes caps the /mock/images body; one image is a few
// hundred bytes.
const maxSeedImageBodyBytes = 64 << 10

// seedImageRequest is the /mock/images body: the EC2AMI JSON shape
// (ami_id, name, owner_id, virtualization_type, root_device_name,
// region) plus the account it is seeded into.
type seedImageRequest struct {
	repository.EC2AMI
	AccountID string `json:"account_id"`
}

// handleMockSeedImage registers one AMI, so a caller can launch an
// image id it resolved elsewhere (real SSM). It writes through
// SeedAMI like the fixtures, so DescribeImages and RunInstances see
// it the same way; /mock/reset drops it. Re-seeding an id already in
// the region (a fixture included) is 200 when every field matches and
// 409 naming the fields when not, writing nothing either way.
func (app *Application) handleMockSeedImage(w http.ResponseWriter, r *http.Request) {
	var req seedImageRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSeedImageBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		writeAdminError(w, http.StatusBadRequest, "invalid body: one JSON object expected")
		return
	}
	if msg := validateSeedImage(&req); msg != "" {
		writeAdminError(w, http.StatusBadRequest, msg)
		return
	}
	// Fixtures land in a region lazily; seed them first so a fixture id
	// conflicts here instead of the fixture being dropped later.
	app.ensureAMIFixturesForRegion(req.AccountID, req.Region)
	stored, err := app.seedAMI(req.AccountID, &req.EC2AMI)
	if errors.Is(err, errInvalidAMIID) {
		writeAdminError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if diff := amiFieldDiff(stored, &req.EC2AMI); len(diff) > 0 {
		writeAdminError(w, http.StatusConflict, req.ID+" already exists in "+req.Region+" with a different "+strings.Join(diff, ", "))
		return
	}
	writeJSONStatus(w, http.StatusOK, map[string]any{"status": "ok", "image": seedImageRequest{*stored, req.AccountID}})
}

// seedAMI inserts ami unless its id already exists in the region and
// returns the stored row. A new id must match amiIDPattern
// (errInvalidAMIID otherwise); an existing one is looked up as is, since
// fixture ids such as AL2023AMIID do not match it.
func (app *Application) seedAMI(account string, ami *repository.EC2AMI) (*repository.EC2AMI, error) {
	stored, err := app.repo.GetAMI(account, ami.Region, ami.ID)
	if !errors.Is(err, models.ErrNotFound) {
		return stored, err
	}
	if !amiIDPattern.MatchString(ami.ID) {
		return nil, errInvalidAMIID
	}
	if err := app.repo.SeedAMI(account, ami); err != nil {
		return nil, err
	}
	// SeedAMI ignores a row a concurrent seed won; read back what stuck.
	return app.repo.GetAMI(account, ami.Region, ami.ID)
}

// amiFieldDiff names the JSON fields where want differs from stored.
func amiFieldDiff(stored, want *repository.EC2AMI) []string {
	var diff []string
	for _, f := range []struct{ name, stored, want string }{
		{"name", stored.Name, want.Name},
		{"owner_id", stored.OwnerID, want.OwnerID},
		{"virtualization_type", stored.VirtualizationType, want.VirtualizationType},
		{"root_device_name", stored.RootDeviceName, want.RootDeviceName},
	} {
		if f.stored != f.want {
			diff = append(diff, f.name)
		}
	}
	return diff
}

// validateSeedImage fills the AL2023 fixture's owner and
// virtualization type when absent and the fake account, and returns
// a message for the first missing or malformed field. The id is
// checked in seedAMI, which knows whether it already exists.
func validateSeedImage(req *seedImageRequest) string {
	switch {
	case !regionPattern.MatchString(req.Region):
		return "region must look like us-east-1"
	case req.RootDeviceName == "":
		return "root_device_name is required"
	case req.AccountID != "" && req.AccountID != awsproto.FakeAccountID:
		// The EC2 surface only ever reads the fake account.
		return "account_id must be " + awsproto.FakeAccountID
	}
	if req.OwnerID == "" {
		req.OwnerID = "amazon"
	}
	if req.VirtualizationType == "" {
		req.VirtualizationType = "hvm"
	}
	req.AccountID = awsproto.FakeAccountID
	return ""
}

func writeAdminError(w http.ResponseWriter, status int, msg string) {
	writeJSONStatus(w, status, map[string]any{"status": "error", "message": msg})
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
	state["eks"] = app.gatherEKSStateReal()
	state["sqs"] = app.gatherSQSStateReal()
	state["route53"] = app.gatherRoute53StateReal()
	state["secretsmanager"] = app.gatherSecretsManagerStateReal()
	state["ssm"] = app.gatherSSMStateReal()

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
