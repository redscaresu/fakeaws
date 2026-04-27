package handlers_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// S3 handler tests. v1 surface: bucket-level CRUD + 6 sub-resources;
// object endpoints accept PUT (return ETag) and 404 on GET.

func s3Do(t *testing.T, srv *httptest.Server, method, path string, body string, contentType string) (*http.Response, []byte) {
	t.Helper()
	url := srv.URL + path
	var bodyReader *bytes.Reader
	if body != "" {
		bodyReader = bytes.NewReader([]byte(body))
	}
	var req *http.Request
	var err error
	if bodyReader != nil {
		req, err = http.NewRequest(method, url, bodyReader)
	} else {
		req, err = http.NewRequest(method, url, nil)
	}
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	respBody := readAll(t, resp)
	return resp, respBody
}

func readAll(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return buf.Bytes()
}

func TestS3_CreateHeadGetDeleteBucket(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	// PUT /s3/<bucket> → 200
	resp, body := s3Do(t, srv, http.MethodPut, "/s3/my-bucket/", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PutBucket: got %d body=%s", resp.StatusCode, body)
	}

	// HEAD /s3/<bucket>/ → 200
	resp, _ = s3Do(t, srv, http.MethodHead, "/s3/my-bucket/", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("HeadBucket existing: %d", resp.StatusCode)
	}

	// GET /s3/<bucket>/ → ListObjectsV2 returns empty list
	resp, body = s3Do(t, srv, http.MethodGet, "/s3/my-bucket/", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("ListObjects: %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "<KeyCount>0</KeyCount>") {
		t.Errorf("ListObjects body: %s", body)
	}

	// DELETE → 204
	resp, _ = s3Do(t, srv, http.MethodDelete, "/s3/my-bucket/", "", "")
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("DeleteBucket: %d", resp.StatusCode)
	}

	// HEAD after delete → 404
	resp, _ = s3Do(t, srv, http.MethodHead, "/s3/my-bucket/", "", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("HeadBucket after delete: %d want 404", resp.StatusCode)
	}
}

func TestS3_CreateBucketDuplicateIs409(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/dup/", "", "")
	resp, body := s3Do(t, srv, http.MethodPut, "/s3/dup/", "", "")
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("duplicate PutBucket: %d body=%s", resp.StatusCode, body)
	}
}

func TestS3_GetBucketMissingIs404(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, body := s3Do(t, srv, http.MethodGet, "/s3/ghost/", "", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GetBucket missing: %d body=%s", resp.StatusCode, body)
	}
}

func TestS3_ListBuckets(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/a/", "", "")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/b/", "", "")

	resp, body := s3Do(t, srv, http.MethodGet, "/s3/", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("ListBuckets: %d", resp.StatusCode)
	}
	for _, want := range []string{"<Name>a</Name>", "<Name>b</Name>"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("ListBuckets missing %s: %s", want, body)
		}
	}
}

func TestS3_VersioningRoundTrip(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/v/", "", "")

	// PUT versioning Enabled.
	versioningXML := `<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`
	resp, _ := s3Do(t, srv, http.MethodPut, "/s3/v/?versioning", versioningXML, "application/xml")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("PutVersioning: %d", resp.StatusCode)
	}

	// GET versioning.
	resp, body := s3Do(t, srv, http.MethodGet, "/s3/v/?versioning", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GetVersioning: %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "<Status>Enabled</Status>") {
		t.Errorf("GetVersioning body missing Enabled: %s", body)
	}
}

func TestS3_VersioningDefaultsToEmptyOn404(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/x/", "", "")

	// No versioning ever set → 200 with empty config (real S3 behaviour).
	resp, body := s3Do(t, srv, http.MethodGet, "/s3/x/?versioning", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GetVersioning empty: %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "<VersioningConfiguration") {
		t.Errorf("expected empty VersioningConfiguration: %s", body)
	}
}

func TestS3_PolicyRoundTripJSON(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/p/", "", "")

	policy := `{"Version":"2012-10-17","Statement":[]}`
	resp, _ := s3Do(t, srv, http.MethodPut, "/s3/p/?policy", policy, "application/json")
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("PutPolicy: %d", resp.StatusCode)
	}

	resp, body := s3Do(t, srv, http.MethodGet, "/s3/p/?policy", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GetPolicy: %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), `"Version":"2012-10-17"`) {
		t.Errorf("GetPolicy body lost JSON: %s", body)
	}
}

func TestS3_PolicyRejectsInvalidJSON(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/p2/", "", "")
	resp, _ := s3Do(t, srv, http.MethodPut, "/s3/p2/?policy", "not json", "application/json")
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("PutPolicy with bad JSON: %d want 409", resp.StatusCode)
	}
}

func TestS3_TaggingRoundTrip(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/t/", "", "")

	tagging := `<Tagging><TagSet><Tag><Key>Env</Key><Value>prod</Value></Tag></TagSet></Tagging>`
	resp, _ := s3Do(t, srv, http.MethodPut, "/s3/t/?tagging", tagging, "application/xml")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("PutTagging: %d", resp.StatusCode)
	}
	resp, body := s3Do(t, srv, http.MethodGet, "/s3/t/?tagging", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GetTagging: %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "<Key>Env</Key>") {
		t.Errorf("GetTagging body: %s", body)
	}
}

func TestS3_PublicAccessBlockRoundTrip(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/pab/", "", "")

	pab := `<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls></PublicAccessBlockConfiguration>`
	resp, _ := s3Do(t, srv, http.MethodPut, "/s3/pab/?publicAccessBlock", pab, "application/xml")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("PutPublicAccessBlock: %d", resp.StatusCode)
	}
	resp, body := s3Do(t, srv, http.MethodGet, "/s3/pab/?publicAccessBlock", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GetPublicAccessBlock: %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "<BlockPublicAcls>true</BlockPublicAcls>") {
		t.Errorf("GetPublicAccessBlock body: %s", body)
	}
}

func TestS3_GetLocation(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	body := `<CreateBucketConfiguration><LocationConstraint>eu-west-1</LocationConstraint></CreateBucketConfiguration>`
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/loc/", body, "application/xml")

	resp, respBody := s3Do(t, srv, http.MethodGet, "/s3/loc/?location", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GetLocation: %d", resp.StatusCode)
	}
	if !strings.Contains(string(respBody), "eu-west-1") {
		t.Errorf("GetLocation body: %s", respBody)
	}
}

func TestS3_PutObjectReturnsETag(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/o/", "", "")

	resp, _ := s3Do(t, srv, http.MethodPut, "/s3/o/key.txt", "hello", "text/plain")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("PutObject: %d", resp.StatusCode)
	}
	if etag := resp.Header.Get("ETag"); etag == "" {
		t.Errorf("PutObject missing ETag header")
	}
}

func TestS3_GetObjectAlways404(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/g/", "", "")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/g/key.txt", "hello", "text/plain")

	// v1: object payloads not stored, GET always 404.
	resp, body := s3Do(t, srv, http.MethodGet, "/s3/g/key.txt", "", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GetObject (v1, no payload store): %d want 404, body=%s", resp.StatusCode, body)
	}
}

func TestS3_DeleteObjectIs204(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/d/", "", "")

	resp, _ := s3Do(t, srv, http.MethodDelete, "/s3/d/anything.txt", "", "")
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("DeleteObject: %d want 204", resp.StatusCode)
	}
}

func TestS3_PutVersioningOnMissingBucketIs404(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	versioningXML := `<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`
	resp, body := s3Do(t, srv, http.MethodPut, "/s3/missing/?versioning", versioningXML, "application/xml")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("PutVersioning on missing bucket: %d body=%s", resp.StatusCode, body)
	}
}

func TestS3_DeleteBucketCascadesConfigs(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/c/", "", "")

	tagging := `<Tagging><TagSet/></Tagging>`
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/c/?tagging", tagging, "application/xml")

	// Delete bucket — should CASCADE the tagging config.
	resp, _ := s3Do(t, srv, http.MethodDelete, "/s3/c/", "", "")
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("DeleteBucket: %d", resp.StatusCode)
	}

	// Recreate, then GET tagging — should be empty (config is gone).
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/c/", "", "")
	resp, body := s3Do(t, srv, http.MethodGet, "/s3/c/?tagging", "", "")
	// Tagging on a bucket with no config returns 404 in real S3 (we
	// surface ErrNotFound → 404).
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GetTagging after CASCADE delete + recreate: %d body=%s", resp.StatusCode, body)
	}
}

func TestS3_MockStateReflectsBuckets(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/state-test/", "", "")

	resp, body := doGet(t, srv, "/mock/state/s3")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/mock/state/s3: %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), `"state-test"`) {
		t.Errorf("/mock/state/s3 missing bucket: %s", body)
	}
}
