package handlers_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.NoError(t, err, "new request")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := srv.Client().Do(req)
	require.NoError(t, err, "%s %s", method, path)
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
	require.Equal(t, http.StatusOK, resp.StatusCode, "PutBucket body=%s", body)

	// HEAD /s3/<bucket>/ → 200
	resp, _ = s3Do(t, srv, http.MethodHead, "/s3/my-bucket/", "", "")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "HeadBucket existing")

	// GET /s3/<bucket>/ → ListObjectsV2 returns empty list
	resp, body = s3Do(t, srv, http.MethodGet, "/s3/my-bucket/", "", "")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "ListObjects")
	assert.Contains(t, string(body), "<KeyCount>0</KeyCount>", "ListObjects body: %s", body)

	// DELETE → 204
	resp, _ = s3Do(t, srv, http.MethodDelete, "/s3/my-bucket/", "", "")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode, "DeleteBucket")

	// HEAD after delete → 404
	resp, _ = s3Do(t, srv, http.MethodHead, "/s3/my-bucket/", "", "")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "HeadBucket after delete")
}

func TestS3_CreateBucketDuplicateIs409(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/dup/", "", "")
	resp, body := s3Do(t, srv, http.MethodPut, "/s3/dup/", "", "")
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "duplicate PutBucket body=%s", body)
}

func TestS3_GetBucketMissingIs404(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, body := s3Do(t, srv, http.MethodGet, "/s3/ghost/", "", "")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "GetBucket missing body=%s", body)
}

func TestS3_ListBuckets(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/a/", "", "")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/b/", "", "")

	resp, body := s3Do(t, srv, http.MethodGet, "/s3/", "", "")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "ListBuckets")
	for _, want := range []string{"<Name>a</Name>", "<Name>b</Name>"} {
		assert.Contains(t, string(body), want, "ListBuckets missing %s: %s", want, body)
	}
}

func TestS3_VersioningRoundTrip(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/v/", "", "")

	// PUT versioning Enabled.
	versioningXML := `<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`
	resp, _ := s3Do(t, srv, http.MethodPut, "/s3/v/?versioning", versioningXML, "application/xml")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "PutVersioning")

	// GET versioning.
	resp, body := s3Do(t, srv, http.MethodGet, "/s3/v/?versioning", "", "")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "GetVersioning")
	assert.Contains(t, string(body), "<Status>Enabled</Status>", "GetVersioning body missing Enabled: %s", body)
}

func TestS3_VersioningDefaultsToEmptyOn404(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/x/", "", "")

	// No versioning ever set → 200 with empty config (real S3 behaviour).
	resp, body := s3Do(t, srv, http.MethodGet, "/s3/x/?versioning", "", "")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "GetVersioning empty body=%s", body)
	assert.Contains(t, string(body), "<VersioningConfiguration", "expected empty VersioningConfiguration: %s", body)
}

func TestS3_PolicyRoundTripJSON(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/p/", "", "")

	policy := `{"Version":"2012-10-17","Statement":[]}`
	resp, _ := s3Do(t, srv, http.MethodPut, "/s3/p/?policy", policy, "application/json")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode, "PutPolicy")

	resp, body := s3Do(t, srv, http.MethodGet, "/s3/p/?policy", "", "")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "GetPolicy")
	assert.Contains(t, string(body), `"Version":"2012-10-17"`, "GetPolicy body lost JSON: %s", body)
}

func TestS3_PolicyRejectsInvalidJSON(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/p2/", "", "")
	resp, _ := s3Do(t, srv, http.MethodPut, "/s3/p2/?policy", "not json", "application/json")
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "PutPolicy with bad JSON")
}

func TestS3_TaggingRoundTrip(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/t/", "", "")

	tagging := `<Tagging><TagSet><Tag><Key>Env</Key><Value>prod</Value></Tag></TagSet></Tagging>`
	resp, _ := s3Do(t, srv, http.MethodPut, "/s3/t/?tagging", tagging, "application/xml")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "PutTagging")
	resp, body := s3Do(t, srv, http.MethodGet, "/s3/t/?tagging", "", "")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "GetTagging")
	assert.Contains(t, string(body), "<Key>Env</Key>", "GetTagging body: %s", body)
}

func TestS3_PublicAccessBlockRoundTrip(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/pab/", "", "")

	pab := `<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls></PublicAccessBlockConfiguration>`
	resp, _ := s3Do(t, srv, http.MethodPut, "/s3/pab/?publicAccessBlock", pab, "application/xml")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "PutPublicAccessBlock")
	resp, body := s3Do(t, srv, http.MethodGet, "/s3/pab/?publicAccessBlock", "", "")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "GetPublicAccessBlock")
	assert.Contains(t, string(body), "<BlockPublicAcls>true</BlockPublicAcls>", "GetPublicAccessBlock body: %s", body)
}

func TestS3_GetLocation(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	body := `<CreateBucketConfiguration><LocationConstraint>eu-west-1</LocationConstraint></CreateBucketConfiguration>`
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/loc/", body, "application/xml")

	resp, respBody := s3Do(t, srv, http.MethodGet, "/s3/loc/?location", "", "")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "GetLocation")
	assert.Contains(t, string(respBody), "eu-west-1", "GetLocation body: %s", respBody)
}

func TestS3_PutObjectReturnsETag(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/o/", "", "")

	resp, _ := s3Do(t, srv, http.MethodPut, "/s3/o/key.txt", "hello", "text/plain")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "PutObject")
	assert.NotEmpty(t, resp.Header.Get("ETag"), "PutObject missing ETag header")
}

func TestS3_GetObjectAlways404(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/g/", "", "")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/g/key.txt", "hello", "text/plain")

	// v1: object payloads not stored, GET always 404.
	resp, body := s3Do(t, srv, http.MethodGet, "/s3/g/key.txt", "", "")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "GetObject (v1, no payload store): body=%s", body)
}

func TestS3_DeleteObjectIs204(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/d/", "", "")

	resp, _ := s3Do(t, srv, http.MethodDelete, "/s3/d/anything.txt", "", "")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode, "DeleteObject")
}

func TestS3_PutVersioningOnMissingBucketIs404(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	versioningXML := `<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`
	resp, body := s3Do(t, srv, http.MethodPut, "/s3/missing/?versioning", versioningXML, "application/xml")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "PutVersioning on missing bucket body=%s", body)
}

func TestS3_DeleteBucketCascadesConfigs(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/c/", "", "")

	tagging := `<Tagging><TagSet/></Tagging>`
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/c/?tagging", tagging, "application/xml")

	// Delete bucket — should CASCADE the tagging config.
	resp, _ := s3Do(t, srv, http.MethodDelete, "/s3/c/", "", "")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode, "DeleteBucket")

	// Recreate, then GET tagging — should be empty (config is gone).
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/c/", "", "")
	resp, body := s3Do(t, srv, http.MethodGet, "/s3/c/?tagging", "", "")
	// Tagging on a bucket with no config returns 404 in real S3 (we
	// surface ErrNotFound → 404).
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "GetTagging after CASCADE delete + recreate body=%s", body)
}

func TestS3_MockStateReflectsBuckets(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, _ = s3Do(t, srv, http.MethodPut, "/s3/state-test/", "", "")

	resp, body := doGet(t, srv, "/mock/state/s3")
	require.Equal(t, http.StatusOK, resp.StatusCode, "/mock/state/s3")
	assert.Contains(t, string(body), `"state-test"`, "/mock/state/s3 missing bucket: %s", body)
}
