package handlers

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/redscaresu/fakeaws/handlers/awsproto"
	"github.com/redscaresu/fakeaws/models"
	"github.com/redscaresu/fakeaws/repository"
)

// registerS3Routes wires the S3 path-style endpoints. terraform-
// provider-aws's `s3_use_path_style = true` directs requests to
// /<bucket>/<key>; we expose them under /s3/<bucket>/<key> so chi can
// dispatch alongside other services on the same router.
//
// Per concepts.md § "Service surface § S3": bucket-level CRUD only;
// object endpoints accept PUT (discard body) and return 404 on GET
// since we don't model object payloads at v1.
func (app *Application) registerS3Routes(r chi.Router) {
	r.Route("/s3", func(s3r chi.Router) {
		s3r.Get("/", app.s3ListBuckets)
		s3r.Route("/{bucket}", func(br chi.Router) {
			br.Put("/", app.s3PutBucket)
			br.Head("/", app.s3HeadBucket)
			br.Get("/", app.s3GetBucketOrListObjects)
			br.Delete("/", app.s3DeleteBucket)

			br.Route("/{key:.*}", func(or chi.Router) {
				or.Put("/", app.s3PutObject)
				or.Head("/", app.s3HeadObject)
				or.Get("/", app.s3GetObject)
				or.Delete("/", app.s3DeleteObject)
			})
		})
	})
}

// gatherS3StateReal returns the S3 block of /mock/state.
func (app *Application) gatherS3StateReal() map[string]any {
	const account = awsproto.FakeAccountID
	out := map[string]any{
		"buckets": []any{},
	}
	buckets, _ := app.repo.ListBuckets(account)
	bs := make([]map[string]any, 0, len(buckets))
	for _, b := range buckets {
		entry := map[string]any{
			"name":       b.Name,
			"region":     b.Region,
			"arn":        b.ARN,
			"created_at": b.CreatedAt,
		}
		configs, _ := app.repo.ListBucketConfigs(account, b.Name)
		if len(configs) > 0 {
			confMap := make(map[string]any, len(configs))
			for k, v := range configs {
				var raw any
				_ = json.Unmarshal(v, &raw)
				confMap[k] = raw
			}
			entry["configs"] = confMap
		}
		bs = append(bs, entry)
	}
	out["buckets"] = bs
	return out
}

// ----- Bucket CRUD -----

// s3PutBucket multiplexes on subresource query params. PUT /<bucket>
// with ?versioning etc. is a config write; without subresource it's
// CreateBucket.
func (app *Application) s3PutBucket(w http.ResponseWriter, r *http.Request) {
	const account = awsproto.FakeAccountID
	bucket := chi.URLParam(r, "bucket")
	q := r.URL.Query()
	switch {
	case q.Has("versioning"):
		app.s3PutVersioning(w, r, account, bucket)
		return
	case q.Has("encryption"):
		app.s3PutEncryption(w, r, account, bucket)
		return
	case q.Has("policy"):
		app.s3PutPolicy(w, r, account, bucket)
		return
	case q.Has("publicAccessBlock"):
		app.s3PutPublicAccessBlock(w, r, account, bucket)
		return
	case q.Has("ownershipControls"):
		app.s3PutOwnershipControls(w, r, account, bucket)
		return
	case q.Has("tagging"):
		app.s3PutTagging(w, r, account, bucket)
		return
	}

	if bucket == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeXML,
			fmt.Errorf("bucket name required: %w", models.ErrConflict))
		return
	}
	region := bucketRegionFromRequest(r)
	b := &repository.S3Bucket{
		Name:      bucket,
		Region:    region,
		ARN:       awsproto.BuildS3BucketARN(bucket),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := app.repo.CreateBucket(account, b); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeXML, err)
		return
	}
	w.Header().Set("Location", "/"+bucket)
	w.WriteHeader(http.StatusOK)
}

func (app *Application) s3HeadBucket(w http.ResponseWriter, r *http.Request) {
	const account = awsproto.FakeAccountID
	if _, err := app.repo.GetBucket(account, chi.URLParam(r, "bucket")); err != nil {
		// HeadBucket returns 404 with no body when the bucket doesn't exist.
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// s3GetBucketOrListObjects multiplexes on query params. GET on a bucket
// with `?versioning` etc. returns the config; with no subresource it's
// ListObjectsV2 (which returns an empty list at v1 since we don't
// store objects).
func (app *Application) s3GetBucketOrListObjects(w http.ResponseWriter, r *http.Request) {
	const account = awsproto.FakeAccountID
	bucket := chi.URLParam(r, "bucket")
	if _, err := app.repo.GetBucket(account, bucket); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeXML, err)
		return
	}
	q := r.URL.Query()
	switch {
	case q.Has("versioning"):
		app.s3GetVersioning(w, account, bucket)
	case q.Has("encryption"):
		app.s3GetEncryption(w, account, bucket)
	case q.Has("policy"):
		app.s3GetPolicy(w, account, bucket)
	case q.Has("publicAccessBlock"):
		app.s3GetPublicAccessBlock(w, account, bucket)
	case q.Has("ownershipControls"):
		app.s3GetOwnershipControls(w, account, bucket)
	case q.Has("tagging"):
		app.s3GetTagging(w, account, bucket)
	case q.Has("location"):
		app.s3GetLocation(w, account, bucket)
	default:
		app.s3ListObjects(w, account, bucket)
	}
}

func (app *Application) s3DeleteBucket(w http.ResponseWriter, r *http.Request) {
	const account = awsproto.FakeAccountID
	bucket := chi.URLParam(r, "bucket")
	q := r.URL.Query()

	// DELETE /<bucket>?policy etc. → delete that config row.
	switch {
	case q.Has("policy"):
		if err := app.repo.DeleteBucketConfig(account, bucket, repository.S3ConfigPolicy); err != nil {
			awsproto.WriteAWSError(w, awsproto.ShapeXML, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	case q.Has("publicAccessBlock"):
		_ = app.repo.DeleteBucketConfig(account, bucket, repository.S3ConfigPublicAccessBlock)
		w.WriteHeader(http.StatusNoContent)
		return
	case q.Has("tagging"):
		_ = app.repo.DeleteBucketConfig(account, bucket, repository.S3ConfigTagging)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if err := app.repo.DeleteBucket(account, bucket); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeXML, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (app *Application) s3ListBuckets(w http.ResponseWriter, r *http.Request) {
	const account = awsproto.FakeAccountID
	buckets, err := app.repo.ListBuckets(account)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeXML, err)
		return
	}
	type bucketXML struct {
		Name         string `xml:"Name"`
		CreationDate string `xml:"CreationDate"`
	}
	type ownerXML struct {
		ID          string `xml:"ID"`
		DisplayName string `xml:"DisplayName"`
	}
	type result struct {
		XMLName xml.Name    `xml:"ListAllMyBucketsResult"`
		Owner   ownerXML    `xml:"Owner"`
		Buckets []bucketXML `xml:"Buckets>Bucket"`
	}
	out := result{
		Owner: ownerXML{ID: awsproto.FakeAccountID, DisplayName: "fakeaws"},
	}
	for _, b := range buckets {
		out.Buckets = append(out.Buckets, bucketXML{Name: b.Name, CreationDate: b.CreatedAt})
	}
	awsproto.WriteXMLResponse(w, http.StatusOK, &out)
}

// ----- Bucket config GET/PUT (path: PUT goes through s3PutBucket
//       with subresource detection; GET goes through s3GetBucket...) -----

// ----- Per-config helpers -----

func (app *Application) s3GetVersioning(w http.ResponseWriter, account, bucket string) {
	type versioning struct {
		XMLName xml.Name `xml:"VersioningConfiguration"`
		Status  string   `xml:"Status,omitempty"`
	}
	raw, err := app.repo.GetBucketConfig(account, bucket, repository.S3ConfigVersioning)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			// Real S3 returns 200 with an empty <VersioningConfiguration/>.
			awsproto.WriteXMLResponse(w, http.StatusOK, &versioning{})
			return
		}
		awsproto.WriteAWSError(w, awsproto.ShapeXML, err)
		return
	}
	var v versioning
	_ = json.Unmarshal(raw, &v)
	awsproto.WriteXMLResponse(w, http.StatusOK, &v)
}

func (app *Application) s3PutVersioning(w http.ResponseWriter, r *http.Request, account, bucket string) {
	body, _ := io.ReadAll(r.Body)
	type versioning struct {
		XMLName xml.Name `xml:"VersioningConfiguration"`
		Status  string   `xml:"Status,omitempty"`
	}
	var v versioning
	if err := xml.Unmarshal(body, &v); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeXML,
			fmt.Errorf("malformed body: %w: %v", models.ErrConflict, err))
		return
	}
	if err := app.repo.PutBucketConfig(account, bucket, repository.S3ConfigVersioning, v); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeXML, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// Generic "store the body, return 200" + "load and emit" pattern for the
// remaining configs. Each one keeps its own typed XML root so the wire
// shape matches real S3.

func (app *Application) s3GetEncryption(w http.ResponseWriter, account, bucket string) {
	app.s3GetGenericConfig(w, account, bucket, repository.S3ConfigEncryption,
		"ServerSideEncryptionConfiguration")
}
func (app *Application) s3PutEncryption(w http.ResponseWriter, r *http.Request, account, bucket string) {
	app.s3PutGenericConfig(w, r, account, bucket, repository.S3ConfigEncryption)
}

func (app *Application) s3GetPolicy(w http.ResponseWriter, account, bucket string) {
	raw, err := app.repo.GetBucketConfig(account, bucket, repository.S3ConfigPolicy)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeXML, err)
		return
	}
	// Bucket policy is a JSON document, not XML; emit application/json.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}
func (app *Application) s3PutPolicy(w http.ResponseWriter, r *http.Request, account, bucket string) {
	body, _ := io.ReadAll(r.Body)
	if !json.Valid(body) {
		awsproto.WriteAWSError(w, awsproto.ShapeXML,
			fmt.Errorf("policy must be JSON: %w", models.ErrConflict))
		return
	}
	if err := app.repo.PutBucketConfig(account, bucket, repository.S3ConfigPolicy, json.RawMessage(body)); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeXML, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (app *Application) s3GetPublicAccessBlock(w http.ResponseWriter, account, bucket string) {
	app.s3GetGenericConfig(w, account, bucket, repository.S3ConfigPublicAccessBlock,
		"PublicAccessBlockConfiguration")
}
func (app *Application) s3PutPublicAccessBlock(w http.ResponseWriter, r *http.Request, account, bucket string) {
	app.s3PutGenericConfig(w, r, account, bucket, repository.S3ConfigPublicAccessBlock)
}

func (app *Application) s3GetOwnershipControls(w http.ResponseWriter, account, bucket string) {
	app.s3GetGenericConfig(w, account, bucket, repository.S3ConfigOwnershipControls,
		"OwnershipControls")
}
func (app *Application) s3PutOwnershipControls(w http.ResponseWriter, r *http.Request, account, bucket string) {
	app.s3PutGenericConfig(w, r, account, bucket, repository.S3ConfigOwnershipControls)
}

func (app *Application) s3GetTagging(w http.ResponseWriter, account, bucket string) {
	app.s3GetGenericConfig(w, account, bucket, repository.S3ConfigTagging, "Tagging")
}
func (app *Application) s3PutTagging(w http.ResponseWriter, r *http.Request, account, bucket string) {
	app.s3PutGenericConfig(w, r, account, bucket, repository.S3ConfigTagging)
}

// s3GetGenericConfig reads the stored config blob, decodes it as JSON
// (which is how we serialised the XML structure), and writes it back as
// XML. Implementation passes through the raw stored XML.
func (app *Application) s3GetGenericConfig(w http.ResponseWriter, account, bucket, kind, rootElement string) {
	raw, err := app.repo.GetBucketConfig(account, bucket, kind)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeXML, err)
		return
	}
	// We stored the body as a JSON-encoded string (the original XML).
	// Unmarshal back to string and emit.
	var stored string
	if err := json.Unmarshal(raw, &stored); err == nil && stored != "" {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(xml.Header))
		_, _ = w.Write([]byte(stored))
		return
	}
	// Fallback: empty wrapper.
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xml.Header))
	fmt.Fprintf(w, "<%s/>\n", rootElement)
}

func (app *Application) s3PutGenericConfig(w http.ResponseWriter, r *http.Request, account, bucket, kind string) {
	body, _ := io.ReadAll(r.Body)
	// Store the raw XML body as a JSON-encoded string so the GET path
	// can replay it verbatim. Real S3 normalises and re-emits its own
	// canonical form; for fidelity at v1 we round-trip what the caller
	// sent.
	if err := app.repo.PutBucketConfig(account, bucket, kind, string(body)); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeXML, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (app *Application) s3GetLocation(w http.ResponseWriter, account, bucket string) {
	b, err := app.repo.GetBucket(account, bucket)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeXML, err)
		return
	}
	type loc struct {
		XMLName            xml.Name `xml:"LocationConstraint"`
		LocationConstraint string   `xml:",chardata"`
	}
	awsproto.WriteXMLResponse(w, http.StatusOK, &loc{LocationConstraint: b.Region})
}

func (app *Application) s3ListObjects(w http.ResponseWriter, account, bucket string) {
	type result struct {
		XMLName     xml.Name `xml:"ListBucketResult"`
		Name        string   `xml:"Name"`
		KeyCount    int      `xml:"KeyCount"`
		MaxKeys     int      `xml:"MaxKeys"`
		IsTruncated bool     `xml:"IsTruncated"`
	}
	awsproto.WriteXMLResponse(w, http.StatusOK, &result{
		Name: bucket, KeyCount: 0, MaxKeys: 1000, IsTruncated: false,
	})
}

// ----- Object endpoints (payload discarded) -----

func (app *Application) s3PutObject(w http.ResponseWriter, r *http.Request) {
	const account = awsproto.FakeAccountID
	bucket := chi.URLParam(r, "bucket")
	if _, err := app.repo.GetBucket(account, bucket); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeXML, err)
		return
	}
	body, _ := io.ReadAll(r.Body)
	hash := md5.Sum(body)
	w.Header().Set("ETag", `"`+hex.EncodeToString(hash[:])+`"`)
	w.WriteHeader(http.StatusOK)
}

func (app *Application) s3HeadObject(w http.ResponseWriter, r *http.Request) {
	// v1: we don't store objects, so HEAD always 404s.
	w.WriteHeader(http.StatusNotFound)
}

func (app *Application) s3GetObject(w http.ResponseWriter, r *http.Request) {
	awsproto.WriteAWSError(w, awsproto.ShapeXML, models.ErrNotFound)
}

func (app *Application) s3DeleteObject(w http.ResponseWriter, r *http.Request) {
	// v1: object delete is a no-op + 204.
	w.WriteHeader(http.StatusNoContent)
}

// ----- helpers -----

// bucketRegionFromRequest reads the LocationConstraint from a
// CreateBucketConfiguration body; defaults to "us-east-1" if the body
// is absent or doesn't include one.
func bucketRegionFromRequest(r *http.Request) string {
	if r.Body == nil {
		return "us-east-1"
	}
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		return "us-east-1"
	}
	type cfg struct {
		XMLName            xml.Name `xml:"CreateBucketConfiguration"`
		LocationConstraint string   `xml:"LocationConstraint"`
	}
	var c cfg
	if err := xml.Unmarshal(body, &c); err != nil || c.LocationConstraint == "" {
		return "us-east-1"
	}
	// Real S3 quirk: LocationConstraint can be empty for us-east-1.
	loc := strings.TrimSpace(c.LocationConstraint)
	if loc == "" {
		return "us-east-1"
	}
	return loc
}
