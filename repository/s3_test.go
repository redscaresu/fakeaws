package repository

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/redscaresu/fakeaws/models"
)

func TestBucketCRUD(t *testing.T) {
	r := setupRepo(t)
	b := &S3Bucket{
		Name: "my-bucket", Region: "us-east-1",
		ARN: "arn:aws:s3:::my-bucket", CreatedAt: "2026-04-27T12:00:00Z",
	}
	if err := r.CreateBucket(testAccount, b); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}

	got, err := r.GetBucket(testAccount, "my-bucket")
	if err != nil {
		t.Fatalf("GetBucket: %v", err)
	}
	if got.Region != "us-east-1" {
		t.Errorf("Region: got %q want us-east-1", got.Region)
	}

	if _, err := r.GetBucket(testAccount, "missing"); !errors.Is(err, models.ErrNotFound) {
		t.Errorf("GetBucket(missing): want ErrNotFound, got %v", err)
	}

	buckets, err := r.ListBuckets(testAccount)
	if err != nil {
		t.Fatalf("ListBuckets: %v", err)
	}
	if len(buckets) != 1 {
		t.Errorf("ListBuckets: got %d want 1", len(buckets))
	}

	if err := r.DeleteBucket(testAccount, "my-bucket"); err != nil {
		t.Fatalf("DeleteBucket: %v", err)
	}
	if _, err := r.GetBucket(testAccount, "my-bucket"); !errors.Is(err, models.ErrNotFound) {
		t.Errorf("after Delete: want ErrNotFound, got %v", err)
	}
}

func TestBucketDuplicateConflict(t *testing.T) {
	r := setupRepo(t)
	b := &S3Bucket{Name: "x", Region: "us-east-1", ARN: "arn", CreatedAt: "t"}
	if err := r.CreateBucket(testAccount, b); err != nil {
		t.Fatal(err)
	}
	if err := r.CreateBucket(testAccount, b); !errors.Is(err, models.ErrConflict) {
		t.Errorf("duplicate CreateBucket: want ErrConflict, got %v", err)
	}
}

func TestBucketConfigPutGetDelete(t *testing.T) {
	r := setupRepo(t)
	b := &S3Bucket{Name: "b", Region: "us-east-1", ARN: "arn", CreatedAt: "t"}
	if err := r.CreateBucket(testAccount, b); err != nil {
		t.Fatal(err)
	}

	versioning := map[string]string{"Status": "Enabled"}
	if err := r.PutBucketConfig(testAccount, "b", S3ConfigVersioning, versioning); err != nil {
		t.Fatalf("PutBucketConfig: %v", err)
	}

	got, err := r.GetBucketConfig(testAccount, "b", S3ConfigVersioning)
	if err != nil {
		t.Fatalf("GetBucketConfig: %v", err)
	}
	var unmarshaled map[string]string
	if err := json.Unmarshal(got, &unmarshaled); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	if unmarshaled["Status"] != "Enabled" {
		t.Errorf("Status: got %q want Enabled", unmarshaled["Status"])
	}

	// Upsert: flip to Suspended.
	versioning["Status"] = "Suspended"
	if err := r.PutBucketConfig(testAccount, "b", S3ConfigVersioning, versioning); err != nil {
		t.Fatalf("PutBucketConfig (upsert): %v", err)
	}
	got, _ = r.GetBucketConfig(testAccount, "b", S3ConfigVersioning)
	json.Unmarshal(got, &unmarshaled)
	if unmarshaled["Status"] != "Suspended" {
		t.Errorf("after upsert: got %q want Suspended", unmarshaled["Status"])
	}

	if err := r.DeleteBucketConfig(testAccount, "b", S3ConfigVersioning); err != nil {
		t.Fatalf("DeleteBucketConfig: %v", err)
	}
	if _, err := r.GetBucketConfig(testAccount, "b", S3ConfigVersioning); !errors.Is(err, models.ErrNotFound) {
		t.Errorf("after Delete: want ErrNotFound, got %v", err)
	}
}

func TestBucketConfigForMissingBucketIs404(t *testing.T) {
	r := setupRepo(t)
	err := r.PutBucketConfig(testAccount, "ghost", S3ConfigVersioning, map[string]string{"Status": "Enabled"})
	if !errors.Is(err, models.ErrNotFound) {
		t.Errorf("PutBucketConfig for missing bucket: want ErrNotFound, got %v", err)
	}
	_, err = r.GetBucketConfig(testAccount, "ghost", S3ConfigVersioning)
	if !errors.Is(err, models.ErrNotFound) {
		t.Errorf("GetBucketConfig for missing bucket: want ErrNotFound, got %v", err)
	}
}

func TestDeleteBucketCascadesConfigs(t *testing.T) {
	r := setupRepo(t)
	b := &S3Bucket{Name: "c", Region: "us-east-1", ARN: "arn", CreatedAt: "t"}
	if err := r.CreateBucket(testAccount, b); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{S3ConfigVersioning, S3ConfigEncryption, S3ConfigTagging} {
		if err := r.PutBucketConfig(testAccount, "c", kind, map[string]string{"k": "v"}); err != nil {
			t.Fatal(err)
		}
	}

	configs, _ := r.ListBucketConfigs(testAccount, "c")
	if len(configs) != 3 {
		t.Errorf("expected 3 configs before DeleteBucket, got %d", len(configs))
	}

	if err := r.DeleteBucket(testAccount, "c"); err != nil {
		t.Fatal(err)
	}

	// CASCADE: all configs gone (the bucket itself is gone too, so
	// ListBucketConfigs would return ErrNotFound via GetBucket; check
	// directly via DB to confirm rows are deleted).
	var n int
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM s3_bucket_configs WHERE bucket_name = ?`, "c").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("CASCADE: expected 0 config rows, got %d", n)
	}
}
