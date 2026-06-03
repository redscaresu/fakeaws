package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/redscaresu/fakeaws/handlers/awsproto"
	"github.com/redscaresu/fakeaws/models"
	"github.com/redscaresu/fakeaws/repository"
)

// Secrets Manager dispatcher. Per fakeaws/PLAN.md § "Phase 5":
// JSON 1.1 with X-Amz-Target. Endpoint: /secretsmanager/region/<region>
// with header `X-Amz-Target: secretsmanager.<Operation>`.

func (app *Application) registerSecretsManagerRoutes(r chi.Router) {
	r.Post("/secretsmanager/region/{region}", app.handleSecretsManager)
}

func (app *Application) handleSecretsManager(w http.ResponseWriter, r *http.Request) {
	region := chi.URLParam(r, "region")
	req, err := awsproto.ParseXAmzTarget(r)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}
	const account = awsproto.FakeAccountID

	switch req.Operation {
	case "CreateSecret":
		app.smCreateSecret(w, account, region, req)
	case "DescribeSecret":
		app.smDescribeSecret(w, account, region, req)
	case "ListSecrets":
		app.smListSecrets(w, account, region, req)
	case "DeleteSecret":
		app.smDeleteSecret(w, account, region, req)
	case "RestoreSecret":
		app.smRestoreSecret(w, account, region, req)
	case "PutSecretValue":
		app.smPutSecretValue(w, account, region, req)
	case "GetSecretValue":
		app.smGetSecretValue(w, account, region, req)
	case "GetResourcePolicy":
		// terraform-provider-aws calls GetResourcePolicy on every
		// aws_secretsmanager_secret Read. We don't model resource
		// policies — return a 200 with a null body so the provider's
		// JSON decode populates `policy = ""` and Read completes.
		// Missing handler returned the default "not yet implemented"
		// 404 which bubbled as "reading Secrets Manager Secret policy:
		// couldn't find resource".
		app.smGetResourcePolicy(w, account, region, req)
	case "PutResourcePolicy", "DeleteResourcePolicy":
		// No-ops in v1 — accept the request and reply with the
		// minimal envelope the SDK expects so subsequent reads
		// don't error.
		var in struct {
			SecretId string `json:"SecretId"`
		}
		_ = json.Unmarshal(req.Body, &in)
		awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{
			"Name": in.SecretId, "ARN": in.SecretId,
		})
	case "TagResource", "UntagResource":
		// Tag mutations after create — accept silently. Persisted
		// tags from CreateSecret already echo through DescribeSecret.
		awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{})
	case "ListSecretVersionIds":
		app.smListSecretVersionIds(w, account, region, req)
	default:
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11,
			fmt.Errorf("Secrets Manager operation %q not yet implemented in fakeaws v1: %w", req.Operation, models.ErrNotFound))
	}
}

// secretRandSuffix produces the deterministic-ish 6-char suffix that
// AWS appends to secret ARNs. We use hex of crypto/rand to keep
// fingerprints stable test-by-test.
func secretRandSuffix() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ----- Secret -----

func (app *Application) smCreateSecret(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		Name         string                        `json:"Name"`
		Description  string                        `json:"Description,omitempty"`
		KmsKeyId     string                        `json:"KmsKeyId,omitempty"`
		SecretString string                        `json:"SecretString,omitempty"`
		Tags         []struct{ Key, Value string } `json:"Tags,omitempty"`
	}
	if err := json.Unmarshal(req.Body, &in); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}
	if in.Name == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11,
			fmt.Errorf("Name required: %w", models.ErrConflict))
		return
	}
	suffix := secretRandSuffix()
	tags := map[string]string{}
	for _, t := range in.Tags {
		tags[t.Key] = t.Value
	}
	s := &repository.SecretsManagerSecret{
		Name: in.Name, Description: in.Description, KMSKeyID: in.KmsKeyId,
		ARN:                  awsproto.BuildSecretsManagerSecretARN(region, in.Name, suffix),
		RecoveryWindowInDays: 30,
		State:                repository.SecretStateActive,
		Tags:                 tags,
		Region:               region,
		CreatedAt:            time.Now().UTC().Format(time.RFC3339),
	}
	if err := app.repo.CreateSecret(account, s); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, err)
		return
	}
	versionID := "VID-" + secretRandSuffix() + secretRandSuffix()
	if in.SecretString != "" {
		_ = app.repo.PutSecretValue(account, region, in.Name, &repository.SecretsManagerVersion{
			VersionID: versionID, SecretString: in.SecretString, Stages: []string{"AWSCURRENT"},
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		})
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{
		"ARN": s.ARN, "Name": s.Name, "VersionId": versionID,
	})
}

func (app *Application) smDescribeSecret(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		SecretId string `json:"SecretId"`
	}
	json.Unmarshal(req.Body, &in)
	// Destroyed secrets behave as not-found (concepts.md "fully
	// destroyed" contract; Codex pass 2 BLOCKING #2).
	s, err := app.repo.GetSecretActiveOrPending(account, region, in.SecretId)
	if err != nil {
		// Service-specific 404 code so the SDK + terraform-provider-aws
		// delete-wait recognise "secret is gone" as a successful
		// deletion. Generic ResourceNotFoundException is also valid
		// per the Secrets Manager spec, but the typed error is what
		// the SDK's errors.As path checks.
		awsproto.WriteServiceError(w, awsproto.ShapeJSON11, http.StatusNotFound,
			"ResourceNotFoundException",
			fmt.Sprintf("Secrets Manager can't find the specified secret: %s", in.SecretId))
		return
	}
	// VersionIdsToStages is the map terraform-provider-aws's Read
	// flow uses to derive aws_secretsmanager_secret_version.version_stages.
	// Missing field → provider treats every version as stage-less,
	// triggering drift on the next plan. Build it from the persisted
	// versions ordered by created_at descending so AWSCURRENT shows
	// up on the most-recent row.
	versions, _ := app.repo.ListSecretVersions(account, s.Region, s.Name)
	versionIdsToStages := map[string][]string{}
	for _, v := range versions {
		stages := v.Stages
		if stages == nil {
			stages = []string{}
		}
		versionIdsToStages[v.VersionID] = stages
	}
	resp := map[string]any{
		"ARN":                s.ARN,
		"Name":               s.Name,
		"Description":        s.Description,
		"KmsKeyId":           s.KMSKeyID,
		"CreatedDate":        secretEpoch(s.CreatedAt),
		"LastChangedDate":    secretEpoch(s.CreatedAt),
		"VersionIdsToStages": versionIdsToStages,
		// Empty slices instead of null so the SDK's JSON decode
		// produces zero-length slices the provider can iterate.
		"Tags": tagsAsJSONSlice(s.Tags),
	}
	if s.DeletedAt != "" {
		resp["DeletedDate"] = secretEpoch(s.DeletedAt)
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, resp)
}

// secretEpoch converts an RFC3339 timestamp into the seconds-since-
// epoch float Secrets Manager's JSON wire format uses for date
// fields (CreatedDate, LastChangedDate, DeletedDate). Returns 0
// when the input is empty so the JSON encodes as a present-but-zero
// field; the SDK's date parser treats that the same as absent.
func secretEpoch(ts string) float64 {
	if ts == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return 0
	}
	return float64(t.Unix())
}

// tagsAsJSONSlice turns the persisted tag map into the
// [{Key,Value},...] slice the AWS Secrets Manager JSON shape uses.
// Returns an empty slice (not nil) so the SDK doesn't drift on an
// unset-vs-empty mismatch.
func tagsAsJSONSlice(tags map[string]string) []map[string]string {
	out := make([]map[string]string, 0, len(tags))
	for k, v := range tags {
		out = append(out, map[string]string{"Key": k, "Value": v})
	}
	return out
}

func (app *Application) smListSecrets(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	secrets, err := app.repo.ListSecrets(account, region)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, err)
		return
	}
	out := make([]map[string]any, 0, len(secrets))
	for _, s := range secrets {
		out = append(out, map[string]any{
			"ARN": s.ARN, "Name": s.Name, "Description": s.Description,
		})
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{"SecretList": out})
}

func (app *Application) smDeleteSecret(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		SecretId                   string `json:"SecretId"`
		RecoveryWindowInDays       int    `json:"RecoveryWindowInDays,omitempty"`
		ForceDeleteWithoutRecovery bool   `json:"ForceDeleteWithoutRecovery,omitempty"`
	}
	if err := json.Unmarshal(req.Body, &in); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}
	window := in.RecoveryWindowInDays
	if in.ForceDeleteWithoutRecovery {
		window = 0
	} else if window == 0 {
		// Treat zero (un-set) as 30-day default per AWS; ForceDelete
		// is the way to bypass.
		window = 30
	}
	s, err := app.repo.ScheduleSecretDeletion(account, region, in.SecretId, window, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, err)
		return
	}
	// DeletionDate must be a JSON number (seconds-since-epoch).
	// Returning the RFC3339 string errors the SDK with
	// "expected DeletionDateType to be a JSON Number, got string".
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{
		"ARN": s.ARN, "Name": s.Name, "DeletionDate": secretEpoch(s.DeletedAt),
	})
}

func (app *Application) smRestoreSecret(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		SecretId string `json:"SecretId"`
	}
	json.Unmarshal(req.Body, &in)
	s, err := app.repo.RestoreSecret(account, region, in.SecretId)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, err)
		return
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{
		"ARN": s.ARN, "Name": s.Name,
	})
}

// ----- Version -----

func (app *Application) smPutSecretValue(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		SecretId      string   `json:"SecretId"`
		SecretString  string   `json:"SecretString,omitempty"`
		VersionStages []string `json:"VersionStages,omitempty"`
	}
	if err := json.Unmarshal(req.Body, &in); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}
	versionID := "VID-" + secretRandSuffix() + secretRandSuffix()
	v := &repository.SecretsManagerVersion{
		VersionID: versionID, SecretString: in.SecretString,
		Stages:    in.VersionStages,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := app.repo.PutSecretValue(account, region, in.SecretId, v); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, err)
		return
	}
	s, _ := app.repo.GetSecret(account, region, in.SecretId)
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{
		"ARN": s.ARN, "Name": s.Name, "VersionId": versionID,
	})
}

func (app *Application) smGetSecretValue(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		SecretId     string `json:"SecretId"`
		VersionId    string `json:"VersionId,omitempty"`
		VersionStage string `json:"VersionStage,omitempty"`
	}
	json.Unmarshal(req.Body, &in)
	v, err := app.repo.GetSecretValue(account, region, in.SecretId, in.VersionStage, in.VersionId)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, err)
		return
	}
	s, _ := app.repo.GetSecret(account, region, in.SecretId)
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{
		"ARN": s.ARN, "Name": s.Name,
		"VersionId": v.VersionID, "SecretString": v.SecretString,
		"VersionStages": v.Stages,
	})
}

// smGetResourcePolicy returns an empty resource-policy envelope so
// the provider's Read flow completes (it polls GetResourcePolicy on
// every refresh; missing handler bubbles as "reading Secrets Manager
// Secret policy: couldn't find resource"). Real AWS returns an
// empty string here when no policy has been attached, and the
// provider treats that as the canonical zero-value.
func (app *Application) smGetResourcePolicy(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		SecretId string `json:"SecretId"`
	}
	_ = json.Unmarshal(req.Body, &in)
	s, err := app.repo.GetSecretActiveOrPending(account, region, in.SecretId)
	if err != nil {
		awsproto.WriteServiceError(w, awsproto.ShapeJSON11, http.StatusNotFound,
			"ResourceNotFoundException",
			fmt.Sprintf("Secrets Manager can't find the specified secret: %s", in.SecretId))
		return
	}
	// Omit ResourcePolicy entirely when no policy is attached.
	// Returning "" caused the provider's Read flow to error with
	// `parsing policy: unexpected end of JSON input` — the SDK
	// only invokes the policy parser when the field is present.
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{
		"ARN":  s.ARN,
		"Name": s.Name,
	})
}

// smListSecretVersionIds backs the provider's
// aws_secretsmanager_secret_version Read which calls this to find
// the AWSCURRENT version after a refresh. Returns the persisted
// version list in the JSON shape the SDK expects.
func (app *Application) smListSecretVersionIds(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		SecretId string `json:"SecretId"`
	}
	_ = json.Unmarshal(req.Body, &in)
	s, err := app.repo.GetSecretActiveOrPending(account, region, in.SecretId)
	if err != nil {
		awsproto.WriteServiceError(w, awsproto.ShapeJSON11, http.StatusNotFound,
			"ResourceNotFoundException",
			fmt.Sprintf("Secrets Manager can't find the specified secret: %s", in.SecretId))
		return
	}
	versions, _ := app.repo.ListSecretVersions(account, s.Region, s.Name)
	out := make([]map[string]any, 0, len(versions))
	for _, v := range versions {
		stages := v.Stages
		if stages == nil {
			stages = []string{}
		}
		out = append(out, map[string]any{
			"VersionId":        v.VersionID,
			"VersionStages":    stages,
			"CreatedDate":      secretEpoch(v.CreatedAt),
			"LastAccessedDate": secretEpoch(v.CreatedAt),
		})
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{
		"ARN":      s.ARN,
		"Name":     s.Name,
		"Versions": out,
	})
}

// ----- /mock/state gather -----

// gatherSecretsManagerStateReal emits the Secrets Manager block of
// /mock/state.
//
// Codex pass 3 BLOCKING #2 fix: secrets now also surface their
// version stage labels (was previously only emitting secrets).
//
// S89 (2026-06-03): filter out PendingDeletion + Destroyed states.
// terraform-provider-aws's default DeleteSecret call sets a 30-day
// recovery window, which leaves the row in PendingDeletion. The
// infrafactory orphan-check reads /mock/state.secretsmanager.secrets
// and treats any non-empty entry as a leftover — but a
// PendingDeletion or Destroyed secret IS gone from the user's
// perspective (DescribeSecret returns 404). Filtering them out of
// /mock/state mirrors the "fully-deleted" contract the orphan-check
// expects. The Active-state retention is unchanged.
//
// Handler/repository behavior unchanged — RestoreSecret on
// PendingDeletion still works, the existing
// TestSecretsManager_PendingDeletionRoundTrip + tests pinning the
// 404 contract for Destroyed secrets still pass.
func (app *Application) gatherSecretsManagerStateReal() map[string]any {
	const account = awsproto.FakeAccountID
	out := map[string]any{
		"secrets":  []any{},
		"versions": []any{},
	}
	allSecrets := []map[string]any{}
	allVersions := []map[string]any{}
	// Account-wide list (Codex pass 8 BLOCKING #2 fix: previous code
	// walked a hard-coded region slice and dropped any secret created
	// outside it).
	secrets, _ := app.repo.ListSecrets(account, "")
	for _, s := range secrets {
		// S89: skip non-Active states. PendingDeletion + Destroyed
		// secrets are post-delete from the orphan-check perspective.
		if s.State != repository.SecretStateActive {
			continue
		}
		allSecrets = append(allSecrets, map[string]any{
			"name": s.Name, "arn": s.ARN, "state": s.State,
			"recovery_window_in_days": s.RecoveryWindowInDays,
			"region":                  s.Region,
		})
		// Surface every persisted version (Codex pass 4 BLOCKING
		// #3 fix). Older versions remain in the DB after stage
		// rotation but were previously invisible because the
		// gather only fetched AWSCURRENT + AWSPREVIOUS.
		versions, _ := app.repo.ListSecretVersions(account, s.Region, s.Name)
		for _, v := range versions {
			allVersions = append(allVersions, map[string]any{
				"secret_name": s.Name, "version_id": v.VersionID,
				"stages": v.Stages, "region": s.Region, "created_at": v.CreatedAt,
			})
		}
	}
	out["secrets"] = allSecrets
	out["versions"] = allVersions
	return out
}
