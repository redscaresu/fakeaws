package handlers_test

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redscaresu/fakeaws/handlers"
	"github.com/redscaresu/fakeaws/handlers/awsproto"
	"github.com/redscaresu/fakeaws/repository"
)

const al2023Parameter = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"

// ssmDo POSTs one AmazonSSM.<op> call in us-east-1, ssmDoIn in region.
// Neither touches t, so the concurrent-put test can call it off the
// test goroutine.
func ssmDo(srv *httptest.Server, op, body string) (*http.Response, error) {
	return ssmDoIn(srv, "us-east-1", op, body)
}

func ssmDoIn(srv *httptest.Server, region, op, body string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/ssm/region/"+region, strings.NewReader(body))
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

// smithy-go 1.28.2 sends /ssm/region/<region>/ for a path-style
// BaseEndpoint; it must route like the slash-less endpoint.
func TestSSM_RegionRootTrailingSlashRoutes(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/ssm/region/us-east-1/", strings.NewReader(fmt.Sprintf(`{"Name":%q}`, al2023Parameter)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "AmazonSSM.GetParameter")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "body=%s", body)
	assert.Contains(t, string(body), "ami-")
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
	status, byARN, body := ssmGetValue(t, srv, "arn:aws:ssm:us-east-1::parameter"+al2023Parameter)
	require.Equal(t, http.StatusOK, status, "GetParameter by the account-less ARN: %s", body)
	assert.Equal(t, ami, byARN)
	assert.Contains(t, string(body), `"Name":"`+al2023Parameter+`"`)

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

// A public parameter the fixture does not answer, and a private twin
// whose name differs only in its prefix.
const (
	publicParameter = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
	privateTwin     = "/twin/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
)

// newSSMPublicApp stores publicParameter and privateTwin as the loader
// would, through the repository (PutParameter refuses aws-prefixed names).
func newSSMPublicApp(t *testing.T) (*handlers.Application, *httptest.Server) {
	t.Helper()
	app, srv := newTestApp(t, ":memory:")
	for _, name := range []string{publicParameter, privateTwin} {
		_, err := app.Repository().PutSSMParameter(awsproto.FakeAccountID, &repository.SSMParameterPut{
			Name: name, Type: "String", Value: "ami-0123456789abcdef0", Region: "us-east-1",
			Tags: map[string]string{"k": "v"}, Now: "1791763200",
		}, false)
		require.NoError(t, err)
	}
	return app, srv
}

func TestSSM_PublicParameterRow(t *testing.T) {
	app, srv := newSSMPublicApp(t)
	publicARN := "arn:aws:ssm:us-east-1::parameter" + publicParameter
	accountARN := "arn:aws:ssm:us-east-1:" + awsproto.FakeAccountID + ":parameter" + publicParameter

	for _, ref := range []string{publicParameter, publicARN} {
		resp, body := ssmCall(t, srv, "GetParameter", fmt.Sprintf(`{"Name":%q}`, ref))
		require.Equal(t, http.StatusOK, resp.StatusCode, "GetParameter %s: %s", ref, body)
		var got struct {
			Parameter struct{ ARN, Name, Value string }
		}
		require.NoError(t, json.Unmarshal(body, &got))
		assert.Equal(t, publicARN, got.Parameter.ARN, ref)
		assert.Equal(t, publicParameter, got.Parameter.Name, ref)
		assert.Equal(t, "ami-0123456789abcdef0", got.Parameter.Value, ref)
	}
	status, _, body := ssmGetValue(t, srv, accountARN)
	assert.Equal(t, http.StatusBadRequest, status, "GetParameter by the account-scoped ARN: %s", body)
	assert.Contains(t, string(body), "ParameterNotFound")

	resp, body := ssmCall(t, srv, "DescribeParameters", `{}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeParameters: %s", body)
	assert.Contains(t, string(body), privateTwin)
	assert.NotContains(t, string(body), publicParameter, "DescribeParameters lists the public parameter")
	resp, body = doGet(t, srv, "/mock/state/ssm")
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET /mock/state/ssm: %s", body)
	assert.Contains(t, string(body), privateTwin)
	assert.NotContains(t, string(body), publicParameter, "/mock/state lists the public parameter")

	refused := map[string]string{
		"DeleteParameter": fmt.Sprintf(`{"Name":%q}`, publicParameter),
		"PutParameter":    fmt.Sprintf(`{"Name":%q,"Type":"String","Value":"x","Overwrite":true}`, publicParameter),
	}
	for _, ref := range []string{publicParameter, publicARN, accountARN} {
		refused["ListTagsForResource "+ref] = fmt.Sprintf(`{"ResourceType":"Parameter","ResourceId":%q}`, ref)
		refused["AddTagsToResource "+ref] = fmt.Sprintf(`{"ResourceType":"Parameter","ResourceId":%q,"Tags":[{"Key":"a","Value":"b"}]}`, ref)
		refused["RemoveTagsFromResource "+ref] = fmt.Sprintf(`{"ResourceType":"Parameter","ResourceId":%q,"TagKeys":["k"]}`, ref)
	}
	codes := map[string]string{
		"DeleteParameter": "ParameterNotFound", "PutParameter": "ValidationException",
		"ListTagsForResource": "InvalidResourceId", "AddTagsToResource": "InvalidResourceId", "RemoveTagsFromResource": "InvalidResourceId",
	}
	for call, reqBody := range refused {
		op, _, _ := strings.Cut(call, " ")
		resp, body := ssmCall(t, srv, op, reqBody)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "%s: %s", call, body)
		assert.Contains(t, string(body), codes[op], call)
	}
	got, err := app.Repository().GetSSMParameter(awsproto.FakeAccountID, "us-east-1", publicParameter)
	require.NoError(t, err, "the refusals left the public parameter")
	assert.Equal(t, "ami-0123456789abcdef0", got.Value, "a refused call changed the value")
	assert.Equal(t, int64(1), got.Version, "a refused call changed the version")
	assert.Equal(t, map[string]string{"k": "v"}, got.Tags, "a refused call changed the tags")
}

// An ARN matches only in the form awsproto.BuildSSMParameterARN builds:
// a doubled slash or an empty path names no stored parameter.
func TestSSM_NonCanonicalARNMatchesNothing(t *testing.T) {
	_, srv := newSSMPublicApp(t)
	for _, ref := range []string{
		"arn:aws:ssm:us-east-1:" + awsproto.FakeAccountID + ":parameter/" + privateTwin,
		"arn:aws:ssm:us-east-1::parameter/" + publicParameter,
		"arn:aws:ssm:us-east-1:" + awsproto.FakeAccountID + ":parameter/",
	} {
		status, _, body := ssmGetValue(t, srv, ref)
		assert.Equal(t, http.StatusBadRequest, status, "GetParameter %s: %s", ref, body)
		assert.Contains(t, string(body), "ParameterNotFound", ref)
		for op, reqBody := range map[string]string{
			"ListTagsForResource":    `{"ResourceType":"Parameter","ResourceId":%q}`,
			"AddTagsToResource":      `{"ResourceType":"Parameter","ResourceId":%q,"Tags":[{"Key":"a","Value":"b"}]}`,
			"RemoveTagsFromResource": `{"ResourceType":"Parameter","ResourceId":%q,"TagKeys":["k"]}`,
		} {
			resp, body := ssmCall(t, srv, op, fmt.Sprintf(reqBody, ref))
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "%s %s: %s", op, ref, body)
			assert.Contains(t, string(body), "InvalidResourceId", "%s %s", op, ref)
		}
	}
}

func TestSSM_PrivateParameterTagOpsByARN(t *testing.T) {
	_, srv := newSSMPublicApp(t)
	arn := "arn:aws:ssm:us-east-1:" + awsproto.FakeAccountID + ":parameter" + privateTwin
	tagged := func(ref string) []byte {
		t.Helper()
		resp, body := ssmCall(t, srv, "ListTagsForResource", fmt.Sprintf(`{"ResourceType":"Parameter","ResourceId":%q}`, ref))
		require.Equal(t, http.StatusOK, resp.StatusCode, "ListTagsForResource %s: %s", ref, body)
		return body
	}

	resp, body := ssmCall(t, srv, "AddTagsToResource", fmt.Sprintf(`{"ResourceType":"Parameter","ResourceId":%q,"Tags":[{"Key":"a","Value":"b"}]}`, arn))
	require.Equal(t, http.StatusOK, resp.StatusCode, "AddTagsToResource: %s", body)
	resp, body = ssmCall(t, srv, "RemoveTagsFromResource", fmt.Sprintf(`{"ResourceType":"Parameter","ResourceId":%q,"TagKeys":["k"]}`, arn))
	require.Equal(t, http.StatusOK, resp.StatusCode, "RemoveTagsFromResource: %s", body)
	assert.JSONEq(t, `{"TagList":[{"Key":"a","Value":"b"}]}`, string(tagged(arn)))
	assert.JSONEq(t, `{"TagList":[{"Key":"a","Value":"b"}]}`, string(tagged(privateTwin)))

	accountless := "arn:aws:ssm:us-east-1::parameter" + privateTwin
	resp, body = ssmCall(t, srv, "ListTagsForResource", fmt.Sprintf(`{"ResourceType":"Parameter","ResourceId":%q}`, accountless))
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "a private parameter's account-less ARN: %s", body)
	assert.Contains(t, string(body), "InvalidResourceId")
}

// Every operation handleSSM dispatches, sent to a public parameter,
// answers exactly as a public parameter must: its pinned status and
// error code, or body. And renamed to its private twin's, the answer
// must not equal the twin's.
func TestContract_ssm_public_parameter_one_predicate(t *testing.T) {
	refused := func(code string) string { return `{"__type":"` + code + `"}` }
	type call struct {
		body, want string // want: the public answer's body, message aside
		status     int
	}
	calls := map[string]call{
		"PutParameter": {`{"Name":%q,"Type":"String","Value":"x","Overwrite":true}`, refused("ValidationException"), http.StatusBadRequest},
		"GetParameter": {`{"Name":%q}`, fmt.Sprintf(`{"Parameter":{"ARN":"arn:aws:ssm:us-east-1::parameter%s","Name":%q,
			"Type":"String","DataType":"text","Value":"ami-0123456789abcdef0","Version":1,"LastModifiedDate":%d}}`,
			publicParameter, publicParameter, time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC).Unix()), http.StatusOK},
		"DescribeParameters":     {`{"ParameterFilters":[{"Key":"Name","Option":"Equals","Values":[%q]}]}`, `{"Parameters":[]}`, http.StatusOK},
		"DeleteParameter":        {`{"Name":%q}`, refused("ParameterNotFound"), http.StatusBadRequest},
		"ListTagsForResource":    {`{"ResourceType":"Parameter","ResourceId":%q}`, refused("InvalidResourceId"), http.StatusBadRequest},
		"AddTagsToResource":      {`{"ResourceType":"Parameter","ResourceId":%q,"Tags":[{"Key":"a","Value":"b"}]}`, refused("InvalidResourceId"), http.StatusBadRequest},
		"RemoveTagsFromResource": {`{"ResourceType":"Parameter","ResourceId":%q,"TagKeys":["k"]}`, refused("InvalidResourceId"), http.StatusBadRequest},
	}
	require.ElementsMatch(t, slices.Collect(maps.Keys(handlers.SSMOperations)), slices.Collect(maps.Keys(calls)),
		"every dispatched SSM operation has a call here")

	for op, c := range calls {
		t.Run(op, func(t *testing.T) {
			_, srv := newSSMPublicApp(t)
			resp, out := ssmCall(t, srv, op, fmt.Sprintf(c.body, publicParameter))
			assert.Equal(t, c.status, resp.StatusCode, "%s: %s", op, out)
			var got map[string]any
			require.NoError(t, json.Unmarshal(out, &got), "%s: %s", op, out)
			delete(got, "message")
			gotJSON, err := json.Marshal(got)
			require.NoError(t, err)
			assert.JSONEq(t, c.want, string(gotJSON), op)

			public := fmt.Sprintf("%d %s", resp.StatusCode, strings.ReplaceAll(string(out), "aws/service/", "twin/"))
			resp, private := ssmCall(t, srv, op, fmt.Sprintf(c.body, privateTwin))
			assert.NotEqual(t, fmt.Sprintf("%d %s", resp.StatusCode, private), public,
				"%s answers the public parameter as a private one", op)
		})
	}
}

// DescribeParameters never lists a public parameter, but its metadata
// derives the ARN account as GetParameter does: none for a public one.
func TestSSM_ParameterMetadataARN(t *testing.T) {
	for name, want := range map[string]string{
		publicParameter: "arn:aws:ssm:us-east-1::parameter" + publicParameter,
		privateTwin:     "arn:aws:ssm:us-east-1:" + awsproto.FakeAccountID + ":parameter" + privateTwin,
	} {
		got := handlers.SSMParameterMetadata(awsproto.FakeAccountID, repository.SSMParameter{Name: name, Type: "String", Region: "us-east-1"})
		assert.Equal(t, want, got["ARN"], name)
	}
}
