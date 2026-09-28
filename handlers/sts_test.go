package handlers_test

import (
	"bytes"
	"encoding/xml"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redscaresu/fakeaws/handlers/awsproto"
)

// stsCall POSTs a Query-RPC body to /sts/, the path terraform-provider-aws
// posts to, and returns the response and body.
func stsCall(t *testing.T, srv *httptest.Server, action string) (*http.Response, []byte) {
	t.Helper()
	params := url.Values{"Action": {action}, "Version": {"2011-06-15"}}
	resp, err := srv.Client().Post(srv.URL+"/sts/", "application/x-www-form-urlencoded", strings.NewReader(params.Encode()))
	require.NoError(t, err, "POST /sts %s", action)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, body
}

func TestContract_sts_caller_identity_fake_account(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	resp, body := stsCall(t, srv, "GetCallerIdentity")
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", body)
	var got struct {
		Arn     string `xml:"GetCallerIdentityResult>Arn"`
		UserId  string `xml:"GetCallerIdentityResult>UserId"`
		Account string `xml:"GetCallerIdentityResult>Account"`
	}
	require.NoError(t, xml.Unmarshal(body, &got), "body=%s", body)
	assert.Equal(t, awsproto.FakeAccountID, got.Account)
	assert.NotEmpty(t, got.UserId)
	assert.Contains(t, got.Arn, ":000000000000:")
}

func TestSTS_AssumeRoleUnimplemented(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	resp, body := stsCall(t, srv, "AssumeRole")
	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "body=%s", body)
	assert.Contains(t, logs.String(), "UNIMPLEMENTED: POST /sts Action=AssumeRole")
}
