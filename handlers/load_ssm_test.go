package handlers_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redscaresu/fakeaws/handlers"
)

const (
	ssmFixtureARN = "arn:aws:ssm:us-east-1::parameter" + al2023Parameter
	ssmFixtureAMI = "ami-0abcdef1234567890"
)

var ssmGetParameterKey = handlers.LoadKey{Service: "ssm", Action: "GetParameter"}

// ssmFixture is testdata/ssm/GetParameter.json: the al2023 public
// parameter's GetParameter answer.
func ssmFixture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../testdata/ssm/GetParameter.json")
	require.NoError(t, err)
	return string(b)
}

// ssmGetParameterExchange is a recorded GetParameter of the al2023
// parameter answering status and body.
func ssmGetParameterExchange(status int, body string) string {
	b, _ := json.Marshal(map[string]any{
		"service": "ssm", "protocol": "json", "action": "GetParameter",
		"params": map[string]any{"Name": al2023Parameter}, "status": status, "body": body,
	})
	return string(b)
}

// loadSSM loads exchanges into loadAccount in us-east-1, the region
// ssmCall answers in, and returns the status and body.
func loadSSM(t *testing.T, srv *httptest.Server, exchanges ...string) (int, string) {
	t.Helper()
	return postLoad(t, srv, loadEnvelope(loadAccount, "us-east-1", exchanges...))
}

// loadSSMBody is a server with body loaded as the al2023 GetParameter.
func loadSSMBody(t *testing.T, body string) (*handlers.Application, *httptest.Server, string) {
	t.Helper()
	app, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	status, answer := loadSSM(t, srv, ssmGetParameterExchange(http.StatusOK, body))
	require.Equal(t, http.StatusOK, status, answer)
	return app, srv, answer
}

// ssmGetEqual asserts GetParameter of ref answers a body equal to want
// by the load diff, in both directions.
func ssmGetEqual(t *testing.T, srv *httptest.Server, ref, want string) {
	t.Helper()
	resp, body := ssmCall(t, srv, "GetParameter", fmt.Sprintf(`{"Name":%q}`, ref))
	require.Equal(t, http.StatusOK, resp.StatusCode, "GetParameter %s: %s", ref, body)
	rec, ren := handlers.Diff(ssmGetParameterKey, mustParseJSON(t, want), mustParseJSON(t, string(body)))
	assert.Empty(t, rec, "GetParameter %s lacks recorded paths", ref)
	assert.Empty(t, ren, "GetParameter %s adds paths", ref)
}

func mustParseJSON(t *testing.T, body string) *handlers.Tree {
	t.Helper()
	tree, err := handlers.ParseJSON([]byte(body))
	require.NoError(t, err, body)
	return tree
}

// ssmNotFoundAnswer is op's answer to body as its status and error code.
func ssmNotFoundAnswer(t *testing.T, srv *httptest.Server, op, body string) string {
	t.Helper()
	resp, out := ssmCall(t, srv, op, body)
	var got struct {
		Type string `json:"__type"`
	}
	require.NoError(t, json.Unmarshal(out, &got), "%s: %s", op, out)
	return fmt.Sprintf("%d %s", resp.StatusCode, got.Type)
}

func TestLoadSSM_PublicParameterLoadsByteExact(t *testing.T) {
	fixture := ssmFixture(t)
	_, srv, answer := loadSSMBody(t, fixture)
	assert.JSONEq(t, `{"loaded":{"ssm-parameter":1},"absent":{},"unresolved":{"image":["`+ssmFixtureAMI+`"]}}`, answer,
		"the AMI the value names is answered under unresolved")

	for _, ref := range []string{al2023Parameter, ssmFixtureARN} {
		ssmGetEqual(t, srv, ref, fixture)
	}
	resp, body := ssmCall(t, srv, "GetParameter", fmt.Sprintf(`{"Name":%q}`, al2023Parameter))
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	var got struct{ Parameter struct{ ARN string } }
	require.NoError(t, json.Unmarshal(body, &got))
	assert.Equal(t, ssmFixtureARN, got.Parameter.ARN)
	assert.NotContains(t, got.Parameter.ARN, loadAccount, "the ARN holds the loaded account")
}

func TestLoadSSM_NotFoundLoadsNothing(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	status, answer := loadSSM(t, srv, ssmGetParameterExchange(http.StatusBadRequest, `{"__type":"ParameterNotFound","message":"x"}`))
	require.Equal(t, http.StatusOK, status, answer)
	assert.JSONEq(t, `{"loaded":{},"absent":{"ssm-parameter":1},"unresolved":{}}`, answer)
}

// The ARN is stored, not derived: a recording whose ARN's region is not
// the load's answers that ARN, and only it finds the row.
func TestLoadSSM_ARNIsStoredNotDerived(t *testing.T) {
	recordedARN := "arn:aws:ssm:eu-west-1::parameter" + al2023Parameter
	fixture := strings.Replace(ssmFixture(t), ssmFixtureARN, recordedARN, 1)
	require.Contains(t, fixture, recordedARN)
	_, srv, _ := loadSSMBody(t, fixture)

	ssmGetEqual(t, srv, al2023Parameter, fixture)
	ssmGetEqual(t, srv, recordedARN, fixture)
	assert.Equal(t, "400 ParameterNotFound", ssmNotFoundAnswer(t, srv, "GetParameter", fmt.Sprintf(`{"Name":%q}`, ssmFixtureARN)),
		"the derived ARN finds a row whose recorded ARN differs")
}

func TestLoadSSM_AccountScopedARNMatchesNothing(t *testing.T) {
	_, srv, _ := loadSSMBody(t, ssmFixture(t))
	accountARN := "arn:aws:ssm:us-east-1:" + loadAccount + ":parameter" + al2023Parameter
	assert.Equal(t, "400 ParameterNotFound", ssmNotFoundAnswer(t, srv, "GetParameter", fmt.Sprintf(`{"Name":%q}`, accountARN)))

	tags := `{"ResourceType":"Parameter","ResourceId":%q}`
	absent := ssmNotFoundAnswer(t, srv, "ListTagsForResource", fmt.Sprintf(tags, "/aws/service/no-such-parameter"))
	assert.Equal(t, "400 InvalidResourceId", absent)
	assert.Equal(t, absent, ssmNotFoundAnswer(t, srv, "ListTagsForResource", fmt.Sprintf(tags, accountARN)),
		"ListTagsForResource on the account-scoped ARN answers as for an absent parameter")
}

func TestLoadSSM_ValueReadsBackByteExact(t *testing.T) {
	const value = "café\n"
	fixture := strings.Replace(ssmFixture(t), `"`+ssmFixtureAMI+`"`, `"café\n"`, 1)
	_, srv, answer := loadSSMBody(t, fixture)
	assert.JSONEq(t, `{"loaded":{"ssm-parameter":1},"absent":{},"unresolved":{}}`, answer, "a value that is no AMI id references nothing")

	status, got, body := ssmGetValue(t, srv, al2023Parameter)
	require.Equal(t, http.StatusOK, status, string(body))
	assert.Equal(t, []byte(value), []byte(got))
}

// On a loaded db the public parameter is not the account's: it is never
// listed, and it is the only SSM row.
func TestLoadSSM_PublicParameterIsNotListed(t *testing.T) {
	app, srv, _ := loadSSMBody(t, ssmFixture(t))
	resp, body := ssmCall(t, srv, "DescribeParameters", `{}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	assert.JSONEq(t, `{"Parameters":[]}`, string(body))
	resp, body = ssmCall(t, srv, "DescribeParameters", fmt.Sprintf(`{"ParameterFilters":[{"Key":"Name","Option":"Equals","Values":[%q]}]}`, al2023Parameter))
	require.Equal(t, http.StatusOK, resp.StatusCode, string(body))
	assert.JSONEq(t, `{"Parameters":[]}`, string(body))
	state := mockOK(t, srv, http.MethodGet, "/mock/state", "")
	assert.NotContains(t, state, "/aws/service/", "/mock/state lists the public parameter")

	var rows int
	require.NoError(t, app.Repository().DB().QueryRow(`SELECT COUNT(*) FROM ssm_parameters`).Scan(&rows))
	assert.Equal(t, 1, rows, "another SSM row exists beside the loaded one")
}

func TestLoadSSM_PutParameterOnTheLoadedParameterIsRefused(t *testing.T) {
	fixture := ssmFixture(t)
	_, srv, _ := loadSSMBody(t, fixture)
	for _, overwrite := range []bool{false, true} {
		resp, body := ssmCall(t, srv, "PutParameter", fmt.Sprintf(`{"Name":%q,"Type":"String","Value":"ami-0fffffffffffffff0","Overwrite":%v}`, al2023Parameter, overwrite))
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "Overwrite=%v: %s", overwrite, body)
		assert.Contains(t, string(body), "ValidationException", "Overwrite=%v", overwrite)
	}
	ssmGetEqual(t, srv, al2023Parameter, fixture)
}

func TestLoadSSM_UnmodelledFieldRefusesTheLoad(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	fixture := strings.Replace(ssmFixture(t), `"Version": 61`, `"Version": 61, "Foo": "bar"`, 1)
	status, body := loadSSM(t, srv, ssmGetParameterExchange(http.StatusOK, fixture))
	require.Equal(t, http.StatusBadRequest, status, body)
	assert.Equal(t, []string{"exchange 0: ssm GetParameter: ssm-parameter: the model cannot hold recorded Parameter/Foo"}, loadRefusals(t, body))
}

func TestLoadSSM_NonPublicParameterIsRefused(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	fixture := strings.ReplaceAll(ssmFixture(t), al2023Parameter, "/myapp/db-host")
	status, body := loadSSM(t, srv, ssmGetParameterExchange(http.StatusOK, fixture))
	require.Equal(t, http.StatusBadRequest, status, body)
	refusals := loadRefusals(t, body)
	require.Len(t, refusals, 1, body)
	assert.Contains(t, refusals[0], "exchange 0: ssm GetParameter: parameter /myapp/db-host is not public")
	for _, field := range []string{"description", "tier", "allowed_pattern", "key_id", "tags"} {
		assert.Contains(t, refusals[0], field)
	}
}
