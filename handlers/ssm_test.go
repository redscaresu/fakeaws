package handlers_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redscaresu/fakeaws/handlers"
)

const al2023Parameter = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"

// ssmDo POSTs one AmazonSSM.<op> call. It never touches t, so the
// concurrent-put test can call it off the test goroutine.
func ssmDo(srv *httptest.Server, op, body string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/ssm/region/us-east-1", strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "AmazonSSM."+op)
	return srv.Client().Do(req)
}

func ssmCall(t *testing.T, srv *httptest.Server, op, body string) (*http.Response, []byte) {
	t.Helper()
	resp, err := ssmDo(srv, op, body)
	require.NoError(t, err, "POST /ssm %s", op)
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp, out
}

// ssmGetValue returns GetParameter's status and Parameter.Value for name.
func ssmGetValue(t *testing.T, srv *httptest.Server, name string) (int, string, []byte) {
	t.Helper()
	resp, body := ssmCall(t, srv, "GetParameter", fmt.Sprintf(`{"Name":%q,"WithDecryption":true}`, name))
	var got struct{ Parameter struct{ Value string } }
	_ = json.Unmarshal(body, &got)
	return resp.StatusCode, got.Parameter.Value, body
}

func TestContract_ssm_put_parameter_no_overwrite_cas(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	resp, body := ssmCall(t, srv, "PutParameter", `{"Name":"/app/x","Type":"String","Value":"one","Overwrite":false}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", body)
	assert.JSONEq(t, `{"Version":1}`, string(body))

	resp, body = ssmCall(t, srv, "PutParameter", `{"Name":"/app/x","Type":"String","Value":"two","Overwrite":false}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "body=%s", body)
	assert.Contains(t, string(body), "ParameterAlreadyExists")
	status, value, body := ssmGetValue(t, srv, "/app/x")
	require.Equal(t, http.StatusOK, status, "body=%s", body)
	assert.Equal(t, "one", value)

	resp, body = ssmCall(t, srv, "PutParameter", `{"Name":"/app/x","Type":"String","Value":"three","Overwrite":true}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", body)
	assert.JSONEq(t, `{"Version":2}`, string(body))

	const racers = 20
	codes := make(chan int, racers)
	var wg sync.WaitGroup
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := ssmDo(srv, "PutParameter", fmt.Sprintf(`{"Name":"/app/race","Type":"String","Value":"v%d"}`, i))
			if err != nil {
				codes <- 0
				return
			}
			resp.Body.Close()
			codes <- resp.StatusCode
		}()
	}
	wg.Wait()
	close(codes)
	count := map[int]int{}
	for c := range codes {
		count[c]++
	}
	assert.Equal(t, map[int]int{http.StatusOK: 1, http.StatusBadRequest: racers - 1}, count)

	resp, body = ssmCall(t, srv, "DeleteParameter", `{"Name":"/app/x"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", body)
	status, _, body = ssmGetValue(t, srv, "/app/x")
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, string(body), "ParameterNotFound")
	resp, body = ssmCall(t, srv, "DeleteParameter", `{"Name":"/app/x"}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "ParameterNotFound")
}

// TestSSM_ParameterLifecycle walks what aws_ssm_parameter calls at
// hashicorp/aws 5.100.0: PutParameter, GetParameter, DescribeParameters
// (Name Equals), the three tag operations, an overwrite that omits
// Description, and DeleteParameter; Get and the tag operations also
// take the parameter's ARN, as after an import by ARN.
func TestSSM_ParameterLifecycle(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	resp, body := ssmCall(t, srv, "PutParameter", `{"Name":"/app/db","Type":"SecureString","Value":"s3cret",
		"AllowedPattern":"","Description":"db password","Overwrite":false,"Tags":[{"Key":"env","Value":"dev"}]}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", body)

	resp, body = ssmCall(t, srv, "GetParameter", `{"Name":"/app/db","WithDecryption":true}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", body)
	var got struct {
		Parameter struct {
			ARN, Name, Type, DataType, Value string
			Version                          int
			LastModifiedDate                 float64
		}
	}
	require.NoError(t, json.Unmarshal(body, &got))
	assert.Equal(t, "arn:aws:ssm:us-east-1:000000000000:parameter/app/db", got.Parameter.ARN)
	assert.Equal(t, "SecureString", got.Parameter.Type)
	assert.Equal(t, "text", got.Parameter.DataType)
	assert.Equal(t, "s3cret", got.Parameter.Value)
	assert.Equal(t, 1, got.Parameter.Version)
	assert.Positive(t, got.Parameter.LastModifiedDate, "epoch number, not a string")

	status, value, body := ssmGetValue(t, srv, "arn:aws:ssm:us-east-1:000000000000:parameter/app/db")
	assert.Equal(t, http.StatusOK, status, "GetParameter by ARN: %s", body)
	assert.Equal(t, "s3cret", value)
	for _, arn := range []string{
		"arn:aws:ssm:eu-west-1:000000000000:parameter/app/db",
		"arn:aws:ssm:us-east-1:111111111111:parameter/app/db",
	} {
		status, _, body = ssmGetValue(t, srv, arn)
		assert.Equal(t, http.StatusBadRequest, status, "%s: %s", arn, body)
	}

	resp, body = ssmCall(t, srv, "PutParameter", `{"Name":"/app/other","Type":"String","Value":"v"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", body)
	resp, body = ssmCall(t, srv, "PutParameter", `{"Name":"/app/db","Type":"SecureString","Value":"rotated","AllowedPattern":"","Tier":"Standard","Overwrite":true}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", body)

	resp, body = ssmCall(t, srv, "DescribeParameters", `{"ParameterFilters":[{"Key":"Name","Option":"Equals","Values":["/app/db"]}]}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", body)
	var described struct {
		Parameters []struct {
			Name, Description, KeyId, Tier, DataType string
			Version                                  int
		}
	}
	require.NoError(t, json.Unmarshal(body, &described))
	require.Len(t, described.Parameters, 1, "body=%s", body)
	p := described.Parameters[0]
	assert.Equal(t, "/app/db", p.Name)
	assert.Equal(t, "db password", p.Description, "overwrite without Description keeps it")
	assert.Equal(t, "alias/aws/ssm", p.KeyId)
	assert.Equal(t, "Standard", p.Tier)
	assert.Equal(t, 2, p.Version)

	resp, body = ssmCall(t, srv, "ListTagsForResource", `{"ResourceType":"Parameter","ResourceId":"/app/db"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", body)
	assert.JSONEq(t, `{"TagList":[{"Key":"env","Value":"dev"}]}`, string(body))
	resp, body = ssmCall(t, srv, "ListTagsForResource", `{"ResourceType":"Parameter","ResourceId":"/app/none"}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "InvalidResourceId")

	resp, body = ssmCall(t, srv, "AddTagsToResource", `{"ResourceType":"Parameter","ResourceId":"/app/db","Tags":[{"Key":"team","Value":"core"}]}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", body)
	resp, body = ssmCall(t, srv, "RemoveTagsFromResource", `{"ResourceType":"Parameter","ResourceId":"arn:aws:ssm:us-east-1:000000000000:parameter/app/db","TagKeys":["env"]}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", body)
	resp, body = ssmCall(t, srv, "ListTagsForResource", `{"ResourceType":"Parameter","ResourceId":"/app/db"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", body)
	assert.JSONEq(t, `{"TagList":[{"Key":"team","Value":"core"}]}`, string(body))
	resp, body = ssmCall(t, srv, "AddTagsToResource", `{"ResourceType":"Parameter","ResourceId":"/app/none","Tags":[{"Key":"k","Value":"v"}]}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "InvalidResourceId")

	resp, body = ssmCall(t, srv, "DeleteParameter", `{"Name":"/app/db"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", body)
	resp, body = ssmCall(t, srv, "DescribeParameters", `{}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", body)
	assert.Contains(t, string(body), `"/app/other"`)
	assert.NotContains(t, string(body), `"/app/db"`)
}

func TestSSM_PutParameterValidation(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	for _, body := range []string{
		`{"Name":"/aws/service/mine","Type":"String","Value":"v"}`,
		`{"Name":"ssm-thing","Type":"String","Value":"v"}`,
		`{"Name":"x","Type":"Bogus","Value":"v"}`,
		`{"Name":"x","Type":"String","Value":"v","Overwrite":true,"Tags":[{"Key":"k","Value":"v"}]}`,
	} {
		resp, out := ssmCall(t, srv, "PutParameter", body)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "%s: %s", body, out)
		assert.Contains(t, string(out), "ValidationException", body)
	}
}

func TestSSM_UnmodelledOperationsAre501(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	for op, body := range map[string]string{
		"GetParametersByPath": `{"Path":"/app"}`,
		"AddTagsToResource":   `{"ResourceType":"Document","ResourceId":"x","Tags":[]}`,
		"DescribeParameters":  `{"ParameterFilters":[{"Key":"Path","Values":["/app"]}]}`,
	} {
		resp, out := ssmCall(t, srv, op, body)
		assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "%s: %s", op, out)
	}
}

func TestSSM_AL2023PublicParameterIsAKnownImage(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	status, ami, body := ssmGetValue(t, srv, al2023Parameter)
	require.Equal(t, http.StatusOK, status, "body=%s", body)
	assert.Equal(t, handlers.AL2023AMIID, ami)
	assert.Contains(t, string(body), `"ARN":"arn:aws:ssm:us-east-1::parameter/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"`)

	resp, body := ec2PostRegression(t, srv, "us-east-1", "DescribeImages", url.Values{"ImageId.1": {ami}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", body)
	assert.Regexp(t, `<imageId>`+ami+`</imageId>\s*<name>al2023-ami-`, string(body))

	resp, body = ssmCall(t, srv, "DeleteParameter", fmt.Sprintf(`{"Name":%q}`, al2023Parameter))
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "ParameterNotFound")
}

func TestSSM_MockStateListsUserParametersOnly(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, body := ssmCall(t, srv, "PutParameter", `{"Name":"/app/x","Type":"String","Value":"hidden-value"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", body)
	status, _, body := ssmGetValue(t, srv, al2023Parameter)
	require.Equal(t, http.StatusOK, status, "body=%s", body)

	resp, body = doGet(t, srv, "/mock/state/ssm")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.JSONEq(t, `{"schema_version":1,"ssm":{"parameters":[
		{"name":"/app/x","type":"String","version":1,"region":"us-east-1"}]}}`, string(body))
}

func TestSSM_ResetAndSnapshotRestore(t *testing.T) {
	srv := newTestServer(t, filepath.Join(t.TempDir(), "test.db"))
	put := func(name string) {
		resp, body := ssmCall(t, srv, "PutParameter", fmt.Sprintf(`{"Name":%q,"Type":"String","Value":"v"}`, name))
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", body)
	}

	put("kept")
	resp, body := doPost(t, srv, "/mock/snapshot")
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", body)
	put("later")
	resp, body = doPost(t, srv, "/mock/restore")
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", body)

	status, value, _ := ssmGetValue(t, srv, "kept")
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "v", value)
	status, _, _ = ssmGetValue(t, srv, "later")
	assert.Equal(t, http.StatusBadRequest, status, "restore drops the post-snapshot parameter")

	resp, body = doPost(t, srv, "/mock/reset")
	require.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", body)
	status, _, body = ssmGetValue(t, srv, "kept")
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, string(body), "ParameterNotFound")
}
