package handlers

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
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
//	  "kms":            {"keys": [...]},  // key_id, arn, state, region, account
//	  "operations":     [...],   // bookkeeping; ignored by countOrphans
//	  "audit":          [...]    // request log, {service, protocol, action, status, class}; ignored by countOrphans
//	}
//
// Per concepts.md "Required surface" item 4 (S43-T4 acceptance): the
// schema is documented inline so topology_derive_aws has a stable
// contract. Per-service blocks land as services arrive (IAM in S43-T5,
// S3 in S43-T7, etc.).
const stateSchemaVersion = 1

// registerAdminRoutes wires the /mock/* admin endpoints. Per concepts.md
// § "Lessons we are explicitly carrying over" item 7: admin lifecycle
// in one file. Without an admin token they are unauthenticated, as in
// mockway and fakegcp; with one, guardAdmin fronts every /mock path.
func (app *Application) registerAdminRoutes(r chi.Router) {
	r.Route("/mock", func(mr chi.Router) {
		if app.adminToken != "" {
			mr.Use(guardAdmin(app.adminToken))
		}
		mr.Post("/reset", app.handleMockReset)
		mr.Post("/snapshot", app.handleMockSnapshot)
		mr.Post("/restore", app.handleMockRestore)
		mr.With(app.holdIdentity).Get("/state", app.handleMockState)
		mr.With(app.holdIdentity).Get("/state/{service}", app.handleMockStateService)
		mr.With(app.holdIdentity).Post("/images", app.handleMockSeedImage)
		mr.Post("/identity", app.handleMockIdentity)
		if app.requests != nil {
			mr.Get("/requests", app.handleMockRequests)
			mr.Post("/requests/clear", app.handleMockRequestsClear)
		}
		if app.loadMaxBytes > 0 {
			mr.Post("/load", app.handleMockLoad)
		}
	})
}

// guardAdmin fronts every /mock path, unknown ones included, when an
// admin token is set.
//
// CRITICAL[mock-admin-origin-loopback-only]: a request whose Origin is
// present and not loopback is 403 before the token is read, so a page
// served from a non-loopback origin cannot drive /mock even when it holds
// the token. A loopback origin or an absent one (a non-browser client)
// passes on to the token, which is what stops a loopback-served page.
//
// CRITICAL[mock-admin-token-required]: anything but
// `Authorization: Bearer <token>` is 401, and neither refusal names the
// token. The compare is constant-time only for a token of the right
// length; subtle.ConstantTimeCompare refuses a wrong length at once.
func guardAdmin(token string) func(http.Handler) http.Handler {
	want := []byte(token)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if origin := r.Header.Get("Origin"); origin != "" && !isLoopbackOrigin(origin) {
				writeAdminError(w, http.StatusForbidden, "cross-origin request refused: /mock answers only pages served on loopback")
				return
			}
			scheme, got, _ := strings.Cut(r.Header.Get("Authorization"), " ")
			if !strings.EqualFold(scheme, "Bearer") || subtle.ConstantTimeCompare([]byte(got), want) != 1 {
				w.Header().Set("WWW-Authenticate", "Bearer")
				writeAdminError(w, http.StatusUnauthorized, "admin token required: Authorization: Bearer <token>")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// isLoopbackOrigin reports whether an Origin header names a loopback
// host: localhost or a loopback IP literal. Ported from infrafactory
// internal/api/origin_guard.go. It does not resolve names, which would
// let a DNS-rebound name through; `null` names no host and is refused.
func isLoopbackOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

var (
	// An EC2 image id: ami- then 8 (legacy) or 17 lowercase hex digits.
	amiIDPattern     = regexp.MustCompile(`^ami-([0-9a-f]{8}|[0-9a-f]{17})$`)
	regionPattern    = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d$`)
	accountIDPattern = regexp.MustCompile(`^[0-9]{12}$`)
)

var (
	errAccountID = errors.New("must be 12 digits")
	errRegion    = errors.New("must look like us-east-1")
)

// CheckAccountID returns an error unless id is an AWS account id: 12 digits.
func CheckAccountID(id string) error {
	if !accountIDPattern.MatchString(id) {
		return errAccountID
	}
	return nil
}

// CheckRegion returns an error unless region looks like us-east-1.
func CheckRegion(region string) error {
	if !regionPattern.MatchString(region) {
		return errRegion
	}
	return nil
}

var errInvalidAMIID = errors.New("ami_id must be ami- followed by 8 or 17 lowercase hex digits")

// maxAdminBodyBytes caps a /mock body; one image or identity is a few
// hundred bytes.
const maxAdminBodyBytes = 64 << 10

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
	account, err := app.AccountID()
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var req seedImageRequest
	if !decodeAdminBody(w, r, &req) {
		return
	}
	if msg := validateSeedImage(&req, account); msg != "" {
		writeAdminError(w, http.StatusBadRequest, msg)
		return
	}
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

// seedAMI inserts ami unless its id is already stored in the region or
// is a fixture, and returns the stored (or fixture) row. Fixtures land
// in a region lazily, so they are matched from ec2AMIFixtures without
// writing them, unless the database is loaded and has none. A new id
// must match amiIDPattern (errInvalidAMIID otherwise); fixture ids such
// as AL2023AMIID do not.
func (app *Application) seedAMI(account string, ami *repository.EC2AMI) (*repository.EC2AMI, error) {
	stored, err := app.repo.GetAMI(account, ami.Region, ami.ID)
	if !errors.Is(err, models.ErrNotFound) {
		return stored, err
	}
	loaded, err := app.repo.Loaded()
	if err != nil {
		return nil, err
	}
	for _, f := range ec2AMIFixtures {
		if f.ID == ami.ID && !loaded {
			f.Region = ami.Region
			return &f, nil
		}
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
// virtualization type when absent and the stored account, and returns
// a message for the first missing or malformed field. The id is
// checked in seedAMI, which knows whether it already exists.
func validateSeedImage(req *seedImageRequest, account string) string {
	switch {
	case CheckRegion(req.Region) != nil:
		return "region " + errRegion.Error()
	case req.Name == "":
		return "name is required"
	case req.RootDeviceName == "":
		return "root_device_name is required"
	case req.AccountID != "" && req.AccountID != account:
		return "account_id must be " + account
	}
	if req.OwnerID == "" {
		req.OwnerID = ec2AmazonOwner
	}
	if req.VirtualizationType == "" {
		req.VirtualizationType = "hvm"
	}
	req.AccountID = account
	return ""
}

// decodeAdminBody decodes one JSON object, with no unknown fields and at
// most maxAdminBodyBytes, from r's body into v. It writes the 400 and
// returns false when it cannot.
func decodeAdminBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := decodeStrict(http.MaxBytesReader(w, r.Body, maxAdminBodyBytes), v); err != nil {
		writeAdminError(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return false
	}
	return true
}

// decodeStrict decodes one JSON object, with no unknown fields, from
// body into v; an unknown field's error names it.
func decodeStrict(body io.Reader, v any) error {
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return errors.New("one JSON object expected")
	}
	return nil
}

// AccountID is the stored account id, or awsproto.FakeAccountID when
// none is stored. It reads the database on every call and never caches.
// Read it at a handler's entry, before any transaction: the database has
// one connection.
//
// CRITICAL[identity-stored-in-database]: the identity lives in the
// identity table, so a snapshot carries it, a restore brings it back, a
// restart on the same file keeps it, and /mock/reset deletes it, which
// returns AccountID to awsproto.FakeAccountID.
//
// MUST[responses-carry-the-stored-account]: a resource created under
// the stored identity is answered with that account, in its responses
// and in /mock/state, never with awsproto.FakeAccountID.
func (app *Application) AccountID() (string, error) {
	id, err := app.repo.GetIdentity()
	if errors.Is(err, sql.ErrNoRows) {
		return awsproto.FakeAccountID, nil
	}
	return id.AccountID, err
}

// readAccount is AccountID for an AWS handler's entry: on a read error
// it writes a 500 in the service's shape and returns false, so no
// handler ever answers the default in place of an unreadable identity.
func (app *Application) readAccount(w http.ResponseWriter, shape awsproto.WireShape) (string, bool) {
	account, err := app.AccountID()
	if err != nil {
		awsproto.WriteAWSError(w, shape, fmt.Errorf("read account id: %w", err))
		return "", false
	}
	return account, true
}

// setIdentity stores id unless the database holds rows under another
// account (models.ErrConflict naming both). It holds identityMu
// exclusively, so no request is between its account read and its write.
func (app *Application) setIdentity(id repository.Identity) error {
	app.identityMu.Lock()
	defer app.identityMu.Unlock()
	fixtures := make([]string, len(ec2AMIFixtures))
	for i, f := range ec2AMIFixtures {
		fixtures[i] = f.ID
	}
	return app.repo.SetIdentity(id, awsproto.FakeAccountID, fixtures)
}

// handleMockIdentity sets the stored identity from
// {"account_id", "region"}: a 12-digit account id and an optional region
// shaped like us-east-1, else 400 naming the field.
//
// CRITICAL[identity-change-refused-on-non-empty-db]: a different account
// on a database holding any row repository's isEmpty counts is 409
// naming both ids, and the stored account stays, so resources made
// under one account never read back under another. -account refuses the
// same way at boot.
func (app *Application) handleMockIdentity(w http.ResponseWriter, r *http.Request) {
	var id repository.Identity
	if !decodeAdminBody(w, r, &id) {
		return
	}
	if err := CheckAccountID(id.AccountID); err != nil {
		writeAdminError(w, http.StatusBadRequest, "account_id "+err.Error())
		return
	}
	if id.Region != "" {
		if err := CheckRegion(id.Region); err != nil {
			writeAdminError(w, http.StatusBadRequest, "region "+err.Error())
			return
		}
	}
	err := app.setIdentity(id)
	switch {
	case errors.Is(err, models.ErrConflict):
		writeAdminError(w, http.StatusConflict, err.Error())
	case err != nil:
		writeAdminError(w, http.StatusInternalServerError, err.Error())
	default:
		writeJSONStatus(w, http.StatusOK, map[string]any{"status": "ok"})
	}
}

func writeAdminError(w http.ResponseWriter, status int, msg string) {
	writeJSONStatus(w, status, map[string]any{"status": "error", "message": msg})
}

// handleMockReset deletes the identity with every row, so it holds
// identityMu exclusively, as setIdentity does.
func (app *Application) handleMockReset(w http.ResponseWriter, _ *http.Request) {
	app.identityMu.Lock()
	defer app.identityMu.Unlock()
	if err := app.repo.Reset(); err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]any{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}
	app.requests.clear()
	writeJSONStatus(w, http.StatusOK, map[string]any{"status": "ok"})
}

// handleMockSnapshot and handleMockRestore save and restore a
// file-backed db.
//
// CRITICAL[file-backed-db-owner-only]: the db fakeaws creates, its
// -wal and -shm, the .snapshot and a restored db it creates are each
// 0600, not 0644 under umask 022: they hold every secret a run wrote.
// An existing db keeps its mode.
//
// Snapshot holds identityMu exclusively: its VACUUM INTO must not catch
// half a request's writes, nor run on the handle a restore replaces.
func (app *Application) handleMockSnapshot(w http.ResponseWriter, _ *http.Request) {
	app.identityMu.Lock()
	defer app.identityMu.Unlock()
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

// handleMockRestore swaps in the snapshot's identity and db handle, so
// it holds identityMu exclusively, as setIdentity does. The copy of the
// snapshot that goes live first gets the default security group of each
// VPC stored without one (repository.BackfillDefaultGroups); if that
// fails, the live state is left as it was.
func (app *Application) handleMockRestore(w http.ResponseWriter, _ *http.Request) {
	app.identityMu.Lock()
	defer app.identityMu.Unlock()
	backfill := func(staged *repository.Repository) error { return staged.BackfillDefaultGroups(newDefaultGroup) }
	if err := app.repo.Restore(backfill); err != nil {
		// ErrNotFound = no snapshot baseline (404).
		// ErrConflict = :memory: db, or a snapshot at another db
		// schema version (409).
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
	app.writeState(w, "")
}

func (app *Application) handleMockStateService(w http.ResponseWriter, r *http.Request) {
	app.writeState(w, chi.URLParam(r, "service"))
}

func (app *Application) writeState(w http.ResponseWriter, service string) {
	state, err := app.collectState(service)
	if err != nil {
		writeAdminError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSONStatus(w, http.StatusOK, state)
}

// collectState gathers the per-service state into the documented shape.
// service == "" returns the full state; otherwise just the named
// service's block (or an empty object if the service hasn't shipped
// handlers yet).
//
// Each service's gather<Service>StateReal, in its own file, returns
// its block, or its first failed read, never a partial block: a table
// that fails to read must not look empty to an orphan check. A child
// table is read per parent row, so with no parent rows it is not read
// and adds nothing to the block. A parent a follow-up read no longer
// finds (models.ErrNotFound) was deleted since the list and is left
// out; any other error fails. collectState stops at the first error
// and returns only "<service> state could not be read", so /mock/state
// answers 500 and no state at all; the detail (SQL, table, decoder
// text) goes to the log, never the response.
//
// The account is read once, before any gather, and passed to every
// gather, so an unreadable identity is an error rather than a state no
// account can be vouched for, and no gather reads it a second time.
func (app *Application) collectState(service string) (map[string]any, error) {
	account, err := app.AccountID()
	if err != nil {
		log.Printf("GET /mock/state: read account: %v", err)
		return nil, errors.New("account identity could not be read")
	}
	state := map[string]any{
		"schema_version": stateSchemaVersion,
		// Universal bookkeeping. countOrphans must continue to ignore
		// these on destroy assertions.
		"operations": []any{},
		"audit":      app.requests.audit(),
	}

	// Per-service gather hooks. Adding a service is one line here.
	// A per-service request reads only its own service's tables.
	for _, g := range []struct {
		service string
		gather  func(account string) (map[string]any, error)
	}{
		{"iam", app.gatherIAMStateReal},
		{"s3", app.gatherS3StateReal},
		{"ec2", app.gatherEC2StateReal},
		{"rds", app.gatherRDSStateReal},
		{"dynamodb", app.gatherDynamoDBStateReal},
		{"eks", app.gatherEKSStateReal},
		{"sqs", app.gatherSQSStateReal},
		{"route53", app.gatherRoute53StateReal},
		{"secretsmanager", app.gatherSecretsManagerStateReal},
		{"ssm", app.gatherSSMStateReal},
		{"kms", app.gatherKMSStateReal},
	} {
		if service != "" && service != g.service {
			continue
		}
		block, err := g.gather(account)
		if err != nil {
			log.Printf("GET /mock/state: read %s state: %v", g.service, err)
			return nil, fmt.Errorf("%s state could not be read", g.service)
		}
		state[g.service] = block
	}

	if service == "" {
		return state, nil
	}
	if val, ok := state[service]; ok {
		return map[string]any{
			"schema_version": stateSchemaVersion,
			service:          val,
		}, nil
	}
	return map[string]any{
		"schema_version": stateSchemaVersion,
		service:          map[string]any{},
	}, nil
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
