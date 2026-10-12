package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/redscaresu/fakeaws/handlers/awsproto"
	"github.com/redscaresu/fakeaws/models"
	"github.com/redscaresu/fakeaws/repository"
)

// KMS dispatcher. JSON 1.1 with X-Amz-Target: TrentService.<Operation>.
// Endpoint: /kms/region/<region>. We don't model key material or
// rotation — just enough state for aws_kms_key + aws_kms_alias to
// round-trip through plan/apply/destroy. Keys are kms_keys rows
// (repository/kms.go), under the stored account and the request's
// region, so /mock/reset, snapshot, restore and the identity guard's
// empty check cover them like every other service's rows. A KeyId is a
// key id or a key ARN (kmsKeyRef); aliases are not stored.

func (app *Application) registerKMSRoutes(r chi.Router) {
	r.Post("/kms/region/{region}", app.handleKMS)
}

func (app *Application) handleKMS(w http.ResponseWriter, r *http.Request) {
	region := chi.URLParam(r, "region")
	req, err := awsproto.ParseXAmzTarget(r)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}
	account, ok := app.readAccount(w, awsproto.ShapeJSON11)
	if !ok {
		return
	}

	switch req.Operation {
	case "CreateKey":
		app.kmsCreateKey(w, account, region, req)
	case "DescribeKey":
		app.kmsDescribeKey(w, account, region, req)
	case "ListKeys":
		app.kmsListKeys(w, account, region)
	case "GetKeyPolicy":
		app.kmsGetKeyPolicy(w, account, region, req)
	case "PutKeyPolicy":
		awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{})
	case "GetKeyRotationStatus":
		app.kmsGetKeyRotationStatus(w, account, region, req)
	case "EnableKeyRotation":
		app.kmsSetKeyRotation(w, account, region, req, true)
	case "DisableKeyRotation":
		app.kmsSetKeyRotation(w, account, region, req, false)
	case "UpdateKeyDescription":
		app.kmsUpdateKeyDescription(w, account, region, req)
	case "ListResourceTags":
		app.kmsListResourceTags(w, account, region, req)
	case "TagResource":
		app.kmsTagResource(w, account, region, req)
	case "UntagResource":
		app.kmsUntagResource(w, account, region, req)
	case "ListAliases":
		awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{"Aliases": []any{}})
	case "CreateAlias", "UpdateAlias", "DeleteAlias":
		awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{})
	case "ScheduleKeyDeletion":
		app.kmsScheduleKeyDeletion(w, account, region, req)
	case "CancelKeyDeletion":
		awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{})
	case "EnableKey", "DisableKey":
		awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{})
	default:
		markClass(w, classNotModelled404)
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11,
			fmt.Errorf("KMS operation %q not yet implemented in fakeaws v1: %w", req.Operation, models.ErrNotFound))
	}
}

// kmsKeyRef resolves ref, a key id or the key's ARN in this region and
// account, to a key id. Any other ARN, an alias included, stays as given
// and matches no key.
func kmsKeyRef(account, region, ref string) string {
	return strings.TrimPrefix(ref, awsproto.BuildKMSKeyARN(region, account, ""))
}

// isKMSAlias reports whether ref names an alias, by name or by ARN.
func isKMSAlias(ref string) bool {
	return strings.HasPrefix(ref, "alias/") || strings.HasPrefix(ref, "arn:") && strings.Contains(ref, ":alias/")
}

// kmsKeyError answers err for ref: 404 NotFoundException, the code the
// provider reads as gone, when no key matches.
func kmsKeyError(w http.ResponseWriter, ref string, err error) {
	if errors.Is(err, models.ErrNotFound) {
		awsproto.WriteServiceError(w, awsproto.ShapeJSON11, http.StatusNotFound, "NotFoundException", "Key '"+ref+"' does not exist")
		return
	}
	awsproto.WriteAWSError(w, awsproto.ShapeJSON11, fmt.Errorf("key %q: %w", ref, err))
}

// kmsKey reads the key ref names, answering the error when it cannot.
func (app *Application) kmsKey(w http.ResponseWriter, account, region, ref string) (*repository.KMSKey, bool) {
	k, err := app.repo.GetKMSKey(account, region, kmsKeyRef(account, region, ref))
	if err != nil {
		kmsKeyError(w, ref, err)
		return nil, false
	}
	return k, true
}

// kmsUpdate applies mutate to the key ref names and answers {}.
func (app *Application) kmsUpdate(w http.ResponseWriter, account, region, ref string, mutate func(*repository.KMSKey)) {
	if err := app.repo.UpdateKMSKey(account, region, kmsKeyRef(account, region, ref), mutate); err != nil {
		kmsKeyError(w, ref, err)
		return
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{})
}

func (app *Application) kmsCreateKey(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		Description string `json:"Description"`
		Tags        []struct {
			TagKey   string `json:"TagKey"`
			TagValue string `json:"TagValue"`
		} `json:"Tags"`
	}
	_ = json.Unmarshal(req.Body, &in)

	b := make([]byte, 16)
	_, _ = rand.Read(b)
	keyID := hex.EncodeToString(b[:4]) + "-" + hex.EncodeToString(b[4:6]) + "-" + hex.EncodeToString(b[6:8]) + "-" + hex.EncodeToString(b[8:10]) + "-" + hex.EncodeToString(b[10:16])
	k := &repository.KMSKey{
		KeyID:       keyID,
		Region:      region,
		State:       repository.KMSKeyStateEnabled,
		Created:     time.Now().UTC(),
		Tags:        map[string]string{},
		Description: in.Description,
	}
	for _, t := range in.Tags {
		k.Tags[t.TagKey] = t.TagValue
	}
	if err := app.repo.CreateKMSKey(account, k); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, err)
		return
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{
		"KeyMetadata": kmsKeyMetadata(account, k),
	})
}

// kmsDescribeKey refuses an alias, which AWS accepts here, as not
// modelled: fakeaws stores no aliases, so a 404 would read as a key
// that does not exist.
func (app *Application) kmsDescribeKey(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		KeyId string `json:"KeyId"`
	}
	_ = json.Unmarshal(req.Body, &in)
	if isKMSAlias(in.KeyId) {
		writeUnimplemented(w, "POST /kms DescribeKey by alias")
		markClass(w, classFilterRefused)
		return
	}
	k, ok := app.kmsKey(w, account, region, in.KeyId)
	if !ok {
		return
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{
		"KeyMetadata": kmsKeyMetadata(account, k),
	})
}

// kmsListKeys lists every key in the region, PendingDeletion included
// as AWS does, in one page: Limit and Marker are ignored.
func (app *Application) kmsListKeys(w http.ResponseWriter, account, region string) {
	keys, err := app.repo.ListKMSKeys(account, region)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, err)
		return
	}
	out := []map[string]string{}
	for _, k := range keys {
		out = append(out, map[string]string{"KeyId": k.KeyID, "KeyArn": awsproto.BuildKMSKeyARN(region, account, k.KeyID)})
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{"Keys": out, "Truncated": false})
}

// kmsGetKeyPolicy answers the default key policy of a stored key —
// terraform-provider-aws decodes this on every Read and just stores it.
// Real AWS returns the resource policy JSON; we hand back the canonical
// default-allow shape, whose root principal is the key's account.
func (app *Application) kmsGetKeyPolicy(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		KeyId string `json:"KeyId"`
	}
	_ = json.Unmarshal(req.Body, &in)
	if _, ok := app.kmsKey(w, account, region, in.KeyId); !ok {
		return
	}
	policy := `{"Version":"2012-10-17","Statement":[{"Sid":"Enable IAM User Permissions","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::` + account + `:root"},"Action":"kms:*","Resource":"*"}]}`
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{
		"Policy":     policy,
		"PolicyName": "default",
	})
}

// CRITICAL[kms-soft-delete-state-pending-deletion]: ScheduleKeyDeletion
// MUST flip the key's state to "PendingDeletion" without removing the
// row — real AWS retains the key for the configured PendingWindowInDays
// (7–30 days). The provider's destroy reads DescribeKey AFTER calling
// ScheduleKeyDeletion and expects 200 with KeyMetadata.KeyState ==
// "PendingDeletion". A hard delete here makes DescribeKey 404 and
// breaks the provider's destroy contract. Locked in by
// TestContract_kms_soft_delete_state_pending_deletion (S106 fix).
func (app *Application) kmsScheduleKeyDeletion(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		KeyId               string `json:"KeyId"`
		PendingWindowInDays int    `json:"PendingWindowInDays"`
	}
	_ = json.Unmarshal(req.Body, &in)
	deletionDate := time.Now().UTC().Add(time.Duration(in.PendingWindowInDays) * 24 * time.Hour)
	if in.PendingWindowInDays == 0 {
		deletionDate = time.Now().UTC().Add(7 * 24 * time.Hour)
	}
	// Soft-delete: real AWS keeps the key visible in PendingDeletion
	// state for 7-30 days. terraform-provider-aws's destroy wait
	// polls DescribeKey expecting KeyState="PendingDeletion" — if
	// we hard-delete and return 404, the wait-loop errors with
	// ResourceNotFoundException. Persist the state transition so
	// DescribeKey can report it; /mock/reset deletes the row, and the
	// identity guard does not count it.
	err := app.repo.UpdateKMSKey(account, region, kmsKeyRef(account, region, in.KeyId), func(k *repository.KMSKey) {
		k.State = repository.KMSKeyStatePendingDeletion
		k.DeletionDate = &deletionDate
	})
	if err != nil {
		kmsKeyError(w, in.KeyId, err)
		return
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{
		"KeyId":        in.KeyId,
		"DeletionDate": float64(deletionDate.Unix()),
	})
}

// kmsGetKeyRotationStatus returns the persisted RotationEnabled flag
// for the requested key. The terraform-provider-aws Update wait-loop
// polls this endpoint waiting for the value to flip after an
// Enable/Disable call; before this handler was state-aware the polled
// value was hard-coded to false and apply timed out after 10m.
//
// Returns NotFoundException for unknown key ids — matches AWS KMS.
func (app *Application) kmsGetKeyRotationStatus(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		KeyId string `json:"KeyId"`
	}
	_ = json.Unmarshal(req.Body, &in)
	k, ok := app.kmsKey(w, account, region, in.KeyId)
	if !ok {
		return
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{
		"KeyRotationEnabled": k.RotationEnabled,
	})
}

// kmsSetKeyRotation handles both EnableKeyRotation (enable=true) and
// DisableKeyRotation (enable=false). Persists the change so the next
// GetKeyRotationStatus reflects it.
func (app *Application) kmsSetKeyRotation(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest, enable bool) {
	var in struct {
		KeyId string `json:"KeyId"`
	}
	_ = json.Unmarshal(req.Body, &in)
	app.kmsUpdate(w, account, region, in.KeyId, func(k *repository.KMSKey) { k.RotationEnabled = enable })
}

// kmsUpdateKeyDescription replaces the key's description. The provider
// polls DescribeKey after this call until the description matches.
func (app *Application) kmsUpdateKeyDescription(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		KeyId       string `json:"KeyId"`
		Description string `json:"Description"`
	}
	_ = json.Unmarshal(req.Body, &in)
	app.kmsUpdate(w, account, region, in.KeyId, func(k *repository.KMSKey) { k.Description = in.Description })
}

// kmsListResourceTags returns the persisted tag set for the requested
// key. Real AWS pairs each tag as {TagKey, TagValue}; the
// terraform-provider-aws Read flow rebuilds the resource Tags map
// from this shape. Before this handler was state-aware the response
// was a hard-coded empty list and aws_kms_key.tags Update wait-loops
// timed out after a few minutes.
//
// Returns NotFoundException for unknown key ids — matches AWS KMS.
func (app *Application) kmsListResourceTags(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		KeyId string `json:"KeyId"`
	}
	_ = json.Unmarshal(req.Body, &in)
	k, ok := app.kmsKey(w, account, region, in.KeyId)
	if !ok {
		return
	}
	tags := []map[string]string{}
	for kk, vv := range k.Tags {
		tags = append(tags, map[string]string{"TagKey": kk, "TagValue": vv})
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{
		"Tags": tags,
	})
}

// kmsTagResource adds or overwrites tags on the requested key.
// AWS allows the same TagKey to appear multiple times in a single
// request (last write wins); we mirror that by iterating in order.
func (app *Application) kmsTagResource(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		KeyId string `json:"KeyId"`
		Tags  []struct {
			TagKey   string `json:"TagKey"`
			TagValue string `json:"TagValue"`
		} `json:"Tags"`
	}
	_ = json.Unmarshal(req.Body, &in)
	app.kmsUpdate(w, account, region, in.KeyId, func(k *repository.KMSKey) {
		if k.Tags == nil {
			k.Tags = map[string]string{}
		}
		for _, t := range in.Tags {
			k.Tags[t.TagKey] = t.TagValue
		}
	})
}

// kmsUntagResource removes the listed tag keys. Real AWS silently
// ignores unknown keys; we mirror that.
func (app *Application) kmsUntagResource(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		KeyId   string   `json:"KeyId"`
		TagKeys []string `json:"TagKeys"`
	}
	_ = json.Unmarshal(req.Body, &in)
	app.kmsUpdate(w, account, region, in.KeyId, func(k *repository.KMSKey) {
		for _, kk := range in.TagKeys {
			delete(k.Tags, kk)
		}
	})
}

func kmsKeyMetadata(account string, k *repository.KMSKey) map[string]any {
	// CreationDate is `DateType` in the KMS smithy spec which the AWS
	// SDK decodes as a Unix epoch number (seconds + fractional). The
	// terraform-provider-aws kms.CreateKey wait-loop deserializes the
	// response with that strict numeric expectation; returning an
	// RFC3339 string surfaces as "expected DateType to be a JSON
	// Number, got string instead" and apply fails on aws-full-stack.
	md := map[string]any{
		"AWSAccountId":          account,
		"KeyId":                 k.KeyID,
		"Arn":                   awsproto.BuildKMSKeyARN(k.Region, account, k.KeyID),
		"CreationDate":          float64(k.Created.Unix()),
		"Enabled":               k.State == repository.KMSKeyStateEnabled,
		"Description":           k.Description,
		"KeyUsage":              "ENCRYPT_DECRYPT",
		"KeyState":              k.State,
		"Origin":                "AWS_KMS",
		"KeyManager":            "CUSTOMER",
		"CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
		"KeySpec":               "SYMMETRIC_DEFAULT",
		"MultiRegion":           false,
		"EncryptionAlgorithms":  []string{"SYMMETRIC_DEFAULT"},
	}
	if k.DeletionDate != nil {
		md["DeletionDate"] = float64(k.DeletionDate.Unix())
	}
	return md
}

// gatherKMSStateReal lists every key under account, in every region,
// PendingDeletion included, so an operator sees each key's state.
func (app *Application) gatherKMSStateReal(account string) (map[string]any, error) {
	keys, err := app.repo.ListKMSKeys(account, "")
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for _, k := range keys {
		out = append(out, map[string]any{
			"key_id": k.KeyID, "arn": awsproto.BuildKMSKeyARN(k.Region, account, k.KeyID),
			"state": k.State, "region": k.Region, "account": account,
		})
	}
	return map[string]any{"keys": out}, nil
}
