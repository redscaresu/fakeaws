package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/redscaresu/fakeaws/handlers/awsproto"
	"github.com/redscaresu/fakeaws/models"
)

// KMS dispatcher. JSON 1.1 with X-Amz-Target: TrentService.<Operation>.
// Endpoint: /kms/region/<region>. We don't model key material or
// rotation — just enough state for aws_kms_key + aws_kms_alias to
// round-trip through plan/apply/destroy.

type kmsKey struct {
	KeyID   string
	ARN     string
	State   string
	Created time.Time
	Deleted *time.Time
	// RotationEnabled mirrors the AWS KMS GetKeyRotationStatus field.
	// terraform-provider-aws calls EnableKeyRotation / DisableKeyRotation
	// then polls GetKeyRotationStatus waiting for the state to flip; the
	// resource Update wait-loop times out after 10m otherwise. Persisting
	// this field across the Update/Get cycle closes the gap.
	RotationEnabled bool
	// Tags mirrors the AWS KMS resource tag set. terraform-provider-aws
	// calls TagResource / UntagResource on Update and polls
	// ListResourceTags waiting for the set to converge; without
	// persistence the resource Update wait-loop diverges and apply
	// times out. Same fix shape as RotationEnabled (S77).
	Tags map[string]string
}

type kmsState struct {
	mu   sync.Mutex
	keys map[string]*kmsKey
}

// kmsStore holds in-process key state for the dispatcher. A single
// app instance shares one map across all KMS requests.
var kmsStore = &kmsState{keys: make(map[string]*kmsKey)}

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
	const account = awsproto.FakeAccountID

	switch req.Operation {
	case "CreateKey":
		app.kmsCreateKey(w, account, region, req)
	case "DescribeKey":
		app.kmsDescribeKey(w, account, region, req)
	case "GetKeyPolicy":
		app.kmsGetKeyPolicy(w, account, region, req)
	case "PutKeyPolicy":
		awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{})
	case "GetKeyRotationStatus":
		app.kmsGetKeyRotationStatus(w, req)
	case "EnableKeyRotation":
		app.kmsSetKeyRotation(w, req, true)
	case "DisableKeyRotation":
		app.kmsSetKeyRotation(w, req, false)
	case "ListResourceTags":
		app.kmsListResourceTags(w, req)
	case "TagResource":
		app.kmsTagResource(w, req)
	case "UntagResource":
		app.kmsUntagResource(w, req)
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
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11,
			fmt.Errorf("KMS operation %q not yet implemented in fakeaws v1: %w", req.Operation, models.ErrNotFound))
	}
}

func (app *Application) kmsCreateKey(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		Tags []struct {
			TagKey   string `json:"TagKey"`
			TagValue string `json:"TagValue"`
		} `json:"Tags"`
	}
	_ = json.Unmarshal(req.Body, &in)

	b := make([]byte, 16)
	_, _ = rand.Read(b)
	keyID := hex.EncodeToString(b[:4]) + "-" + hex.EncodeToString(b[4:6]) + "-" + hex.EncodeToString(b[6:8]) + "-" + hex.EncodeToString(b[8:10]) + "-" + hex.EncodeToString(b[10:16])
	arn := fmt.Sprintf("arn:aws:kms:%s:%s:key/%s", region, awsproto.FakeAccountID, keyID)
	k := &kmsKey{
		KeyID:   keyID,
		ARN:     arn,
		State:   "Enabled",
		Created: time.Now().UTC(),
		Tags:    map[string]string{},
	}
	for _, t := range in.Tags {
		k.Tags[t.TagKey] = t.TagValue
	}
	kmsStore.mu.Lock()
	kmsStore.keys[keyID] = k
	kmsStore.mu.Unlock()

	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{
		"KeyMetadata": kmsKeyMetadata(k),
	})
}

func (app *Application) kmsDescribeKey(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		KeyId string `json:"KeyId"`
	}
	_ = json.Unmarshal(req.Body, &in)
	kmsStore.mu.Lock()
	k, ok := kmsStore.keys[in.KeyId]
	kmsStore.mu.Unlock()
	if !ok {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11,
			fmt.Errorf("key %q: %w", in.KeyId, models.ErrNotFound))
		return
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{
		"KeyMetadata": kmsKeyMetadata(k),
	})
}

func (app *Application) kmsGetKeyPolicy(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	// Default key policy — terraform-provider-aws decodes this on
	// every Read and just stores it. Real AWS returns the resource
	// policy JSON; we hand back the canonical default-allow shape.
	policy := `{"Version":"2012-10-17","Statement":[{"Sid":"Enable IAM User Permissions","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"kms:*","Resource":"*"}]}`
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{
		"Policy":     policy,
		"PolicyName": "default",
	})
}

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
	kmsStore.mu.Lock()
	k, ok := kmsStore.keys[in.KeyId]
	if ok {
		// Soft-delete: real AWS keeps the key visible in PendingDeletion
		// state for 7-30 days. terraform-provider-aws's destroy wait
		// polls DescribeKey expecting KeyState="PendingDeletion" — if
		// we hard-delete and return 404, the wait-loop errors with
		// ResourceNotFoundException. Persist the state transition so
		// DescribeKey can report it. /mock/reset purges everything for
		// clean re-runs.
		k.State = "PendingDeletion"
		k.Deleted = &deletionDate
	}
	kmsStore.mu.Unlock()
	if !ok {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11,
			fmt.Errorf("key %q: %w", in.KeyId, models.ErrNotFound))
		return
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{
		"KeyId":        k.KeyID,
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
func (app *Application) kmsGetKeyRotationStatus(w http.ResponseWriter, req awsproto.XAmzTargetRequest) {
	var in struct {
		KeyId string `json:"KeyId"`
	}
	_ = json.Unmarshal(req.Body, &in)
	kmsStore.mu.Lock()
	k, ok := kmsStore.keys[in.KeyId]
	enabled := false
	if ok {
		enabled = k.RotationEnabled
	}
	kmsStore.mu.Unlock()
	if !ok {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11,
			fmt.Errorf("key %q: %w", in.KeyId, models.ErrNotFound))
		return
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{
		"KeyRotationEnabled": enabled,
	})
}

// kmsSetKeyRotation handles both EnableKeyRotation (enable=true) and
// DisableKeyRotation (enable=false). Persists the change so the next
// GetKeyRotationStatus reflects it.
func (app *Application) kmsSetKeyRotation(w http.ResponseWriter, req awsproto.XAmzTargetRequest, enable bool) {
	var in struct {
		KeyId string `json:"KeyId"`
	}
	_ = json.Unmarshal(req.Body, &in)
	kmsStore.mu.Lock()
	k, ok := kmsStore.keys[in.KeyId]
	if ok {
		k.RotationEnabled = enable
	}
	kmsStore.mu.Unlock()
	if !ok {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11,
			fmt.Errorf("key %q: %w", in.KeyId, models.ErrNotFound))
		return
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{})
}

// kmsListResourceTags returns the persisted tag set for the requested
// key. Real AWS pairs each tag as {TagKey, TagValue}; the
// terraform-provider-aws Read flow rebuilds the resource Tags map
// from this shape. Before this handler was state-aware the response
// was a hard-coded empty list and aws_kms_key.tags Update wait-loops
// timed out after a few minutes.
//
// Returns NotFoundException for unknown key ids — matches AWS KMS.
func (app *Application) kmsListResourceTags(w http.ResponseWriter, req awsproto.XAmzTargetRequest) {
	var in struct {
		KeyId string `json:"KeyId"`
	}
	_ = json.Unmarshal(req.Body, &in)
	kmsStore.mu.Lock()
	k, ok := kmsStore.keys[in.KeyId]
	var tags []map[string]string
	if ok {
		for kk, vv := range k.Tags {
			tags = append(tags, map[string]string{"TagKey": kk, "TagValue": vv})
		}
	}
	kmsStore.mu.Unlock()
	if !ok {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11,
			fmt.Errorf("key %q: %w", in.KeyId, models.ErrNotFound))
		return
	}
	if tags == nil {
		tags = []map[string]string{}
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{
		"Tags": tags,
	})
}

// kmsTagResource adds or overwrites tags on the requested key.
// AWS allows the same TagKey to appear multiple times in a single
// request (last write wins); we mirror that by iterating in order.
func (app *Application) kmsTagResource(w http.ResponseWriter, req awsproto.XAmzTargetRequest) {
	var in struct {
		KeyId string `json:"KeyId"`
		Tags  []struct {
			TagKey   string `json:"TagKey"`
			TagValue string `json:"TagValue"`
		} `json:"Tags"`
	}
	_ = json.Unmarshal(req.Body, &in)
	kmsStore.mu.Lock()
	k, ok := kmsStore.keys[in.KeyId]
	if ok {
		if k.Tags == nil {
			k.Tags = map[string]string{}
		}
		for _, t := range in.Tags {
			k.Tags[t.TagKey] = t.TagValue
		}
	}
	kmsStore.mu.Unlock()
	if !ok {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11,
			fmt.Errorf("key %q: %w", in.KeyId, models.ErrNotFound))
		return
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{})
}

// kmsUntagResource removes the listed tag keys. Real AWS silently
// ignores unknown keys; we mirror that.
func (app *Application) kmsUntagResource(w http.ResponseWriter, req awsproto.XAmzTargetRequest) {
	var in struct {
		KeyId   string   `json:"KeyId"`
		TagKeys []string `json:"TagKeys"`
	}
	_ = json.Unmarshal(req.Body, &in)
	kmsStore.mu.Lock()
	k, ok := kmsStore.keys[in.KeyId]
	if ok {
		for _, kk := range in.TagKeys {
			delete(k.Tags, kk)
		}
	}
	kmsStore.mu.Unlock()
	if !ok {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11,
			fmt.Errorf("key %q: %w", in.KeyId, models.ErrNotFound))
		return
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{})
}

func kmsKeyMetadata(k *kmsKey) map[string]any {
	// CreationDate is `DateType` in the KMS smithy spec which the AWS
	// SDK decodes as a Unix epoch number (seconds + fractional). The
	// terraform-provider-aws kms.CreateKey wait-loop deserializes the
	// response with that strict numeric expectation; returning an
	// RFC3339 string surfaces as "expected DateType to be a JSON
	// Number, got string instead" and apply fails on aws-full-stack.
	md := map[string]any{
		"AWSAccountId":          awsproto.FakeAccountID,
		"KeyId":                 k.KeyID,
		"Arn":                   k.ARN,
		"CreationDate":          float64(k.Created.Unix()),
		"Enabled":               k.State == "Enabled",
		"Description":           "",
		"KeyUsage":              "ENCRYPT_DECRYPT",
		"KeyState":              k.State,
		"Origin":                "AWS_KMS",
		"KeyManager":            "CUSTOMER",
		"CustomerMasterKeySpec": "SYMMETRIC_DEFAULT",
		"KeySpec":               "SYMMETRIC_DEFAULT",
		"MultiRegion":           false,
		"EncryptionAlgorithms":  []string{"SYMMETRIC_DEFAULT"},
	}
	if k.Deleted != nil {
		md["DeletionDate"] = float64(k.Deleted.Unix())
	}
	return md
}
