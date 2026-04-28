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
		Name         string            `json:"Name"`
		Description  string            `json:"Description,omitempty"`
		KmsKeyId     string            `json:"KmsKeyId,omitempty"`
		SecretString string            `json:"SecretString,omitempty"`
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
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, err)
		return
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{
		"ARN":         s.ARN,
		"Name":        s.Name,
		"Description": s.Description,
		"KmsKeyId":    s.KMSKeyID,
		"DeletedDate": s.DeletedAt,
	})
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
		SecretId                  string `json:"SecretId"`
		RecoveryWindowInDays      int    `json:"RecoveryWindowInDays,omitempty"`
		ForceDeleteWithoutRecovery bool  `json:"ForceDeleteWithoutRecovery,omitempty"`
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
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{
		"ARN": s.ARN, "Name": s.Name, "DeletionDate": s.DeletedAt,
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
		SecretId     string `json:"SecretId"`
		SecretString string `json:"SecretString,omitempty"`
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
		SecretId      string `json:"SecretId"`
		VersionId     string `json:"VersionId,omitempty"`
		VersionStage  string `json:"VersionStage,omitempty"`
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

// ----- /mock/state gather -----

// gatherSecretsManagerStateReal emits the Secrets Manager block of
// /mock/state.
//
// Codex pass 3 BLOCKING #2 fix: secrets now also surface their
// version stage labels (was previously only emitting secrets).
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
