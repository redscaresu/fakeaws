package handlers_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redscaresu/fakeaws/handlers"
)

const requestDeadline = 10 * time.Second

type loggedRequest struct {
	Method         string `json:"method"`
	Path           string `json:"path"`
	Status         int    `json:"status"`
	Classification string `json:"classification"`
}

// newRecordingApp is newOptionsApp with RecordRequests and the admin
// token it needs, and a deadline on every request the server's client
// sends.
func newRecordingApp(t *testing.T, opts handlers.Options) (*handlers.Application, *httptest.Server) {
	t.Helper()
	opts.RecordRequests, opts.AdminToken = true, adminToken
	app, srv := newOptionsApp(t, opts)
	srv.Client().Timeout = requestDeadline
	return app, srv
}

// readSet is a logged request's ADR-0041 read-set fields and status.
type readSet struct {
	Service  string         `json:"service"`
	Protocol string         `json:"protocol"`
	Action   string         `json:"action"`
	Params   map[string]any `json:"params"`
	Status   int            `json:"status"`
}

// mockRequests is GET /mock/requests, each entry decoded as T.
func mockRequests[T any](t *testing.T, srv *httptest.Server) []T {
	t.Helper()
	status, body := doAdmin(t, srv, http.MethodGet, "/mock/requests", bearer(adminToken))
	require.Equal(t, http.StatusOK, status, body)
	var got struct {
		Requests []T `json:"requests"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &got), body)
	require.NotNil(t, got.Requests, "requests is [], never null: %s", body)
	return got.Requests
}

func loggedRequests(t *testing.T, srv *httptest.Server) []loggedRequest {
	t.Helper()
	return mockRequests[loggedRequest](t, srv)
}

// stateAudit is /mock/state's audit block, read with header.
func stateAudit(t *testing.T, srv *httptest.Server, header http.Header) []map[string]any {
	t.Helper()
	status, body := doAdmin(t, srv, http.MethodGet, "/mock/state", header)
	require.Equal(t, http.StatusOK, status, body)
	var state struct {
		Audit []map[string]any `json:"audit"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &state), body)
	require.NotNil(t, state.Audit, "audit is [], never null: %s", body)
	return state.Audit
}

// testRoutes adds /test routes to app's router: one that panics, one
// that writes 200 and then panics, one that answers 503 unmarked, one that marks unimplemented-501 and
// answers 200, and one that marks unimplemented-501 then filter-refused.
func testRoutes(app *handlers.Application) *chi.Mux {
	mux := app.Router().(*chi.Mux)
	mux.Get("/test/panic", func(http.ResponseWriter, *http.Request) { panic("test route") })
	mux.Get("/test/panic-after-200", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		panic("test route after 200")
	})
	mux.Get("/test/503", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	mux.Get("/test/marked-200", func(w http.ResponseWriter, _ *http.Request) {
		handlers.MarkClass(w, handlers.ClassUnimplemented)
		w.WriteHeader(http.StatusOK)
	})
	mux.Get("/test/remarked", func(w http.ResponseWriter, _ *http.Request) {
		handlers.MarkClass(w, handlers.ClassUnimplemented)
		handlers.MarkClass(w, handlers.RequestClass("filter-refused"))
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

// providerTraffic sends an STS request answered from rows, an
// unmodelled STS action and a path no service owns.
func providerTraffic(t *testing.T, srv *httptest.Server) {
	t.Helper()
	resp, body := stsCall(t, srv, "GetCallerIdentity")
	require.Equal(t, http.StatusOK, resp.StatusCode, "%s", body)
	resp, body = stsCall(t, srv, "AssumeRole")
	require.Equal(t, http.StatusNotImplemented, resp.StatusCode, "%s", body)
	resp, body = doGet(t, srv, "/secret-bucket-name/key")
	require.Equal(t, http.StatusNotImplemented, resp.StatusCode, "%s", body)
}

func TestContract_request_log_off_by_default(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	providerTraffic(t, srv)

	wantStatus, wantBody := doAdmin(t, srv, http.MethodGet, "/mock/x", http.Header{})
	require.Equal(t, http.StatusNotImplemented, wantStatus, "the router's 501")
	for _, rt := range []adminRoute{{http.MethodGet, "/mock/requests"}, {http.MethodPost, "/mock/requests/clear"}} {
		status, body := doAdmin(t, srv, rt.method, rt.path, http.Header{})
		assert.Equal(t, wantStatus, status, "%s %s", rt.method, rt.path)
		assert.Equal(t, wantBody, body, "%s %s", rt.method, rt.path)
	}
	assert.Empty(t, stateAudit(t, srv, http.Header{}), "nothing is recorded")
}

func TestContract_request_log_needs_admin_token(t *testing.T) {
	app, err := handlers.NewApplication(handlers.Options{DBPath: ":memory:", RecordRequests: true})
	assert.ErrorIs(t, err, handlers.ErrRecordRequestsNeedsAdminToken)
	assert.ErrorContains(t, err, "admin token")
	assert.Nil(t, app)
}

func TestRequestLog_CompletionOrderSkipsAdminAndHealthz(t *testing.T) {
	app, srv := newRecordingApp(t, handlers.Options{DBPath: ":memory:"})
	entered, release := make(chan struct{}), make(chan struct{})
	testRoutes(app).Get("/test/slow", func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusAccepted)
	})
	unblock := sync.OnceFunc(func() { close(release) })
	t.Cleanup(unblock) // runs before srv.Close, which waits on /test/slow

	slow := make(chan int, 1)
	go func() {
		status := 0
		if resp, err := srv.Client().Get(srv.URL + "/test/slow"); err == nil {
			resp.Body.Close()
			status = resp.StatusCode
		}
		slow <- status
	}()
	select {
	case <-entered:
	case <-time.After(requestDeadline):
		t.Fatal("/test/slow never reached its handler")
	}

	resp, body := stsCall(t, srv, "GetCallerIdentity")
	require.Equal(t, http.StatusOK, resp.StatusCode, "%s", body)
	for _, rt := range []adminRoute{{http.MethodGet, "/healthz"}, {http.MethodGet, "/mock/state"}, {http.MethodGet, "/mock/x"}, {http.MethodGet, "/mock"}} {
		doAdmin(t, srv, rt.method, rt.path, http.Header{})
	}
	unblock()
	select {
	case status := <-slow:
		require.Equal(t, http.StatusAccepted, status)
	case <-time.After(requestDeadline):
		t.Fatal("/test/slow never answered")
	}

	assert.Equal(t, []loggedRequest{
		{http.MethodPost, "/sts/", http.StatusOK, "answered-from-rows"},
		{http.MethodGet, "/test/slow", http.StatusAccepted, "answered-from-rows"},
	}, loggedRequests(t, srv), "completion order; /mock and /healthz are not recorded")
}

func TestRequestLog_ClearResetSnapshotRestoreRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "fakeaws.db")
	app, srv := newRecordingApp(t, handlers.Options{DBPath: dbPath})
	sts := loggedRequest{http.MethodPost, "/sts/", http.StatusOK, "answered-from-rows"}
	getCallerIdentity := func() {
		resp, body := stsCall(t, srv, "GetCallerIdentity")
		require.Equal(t, http.StatusOK, resp.StatusCode, "%s", body)
	}
	admin := func(path string) {
		status, body := doAdmin(t, srv, http.MethodPost, path, bearer(adminToken))
		require.Equal(t, http.StatusOK, status, "%s: %s", path, body)
	}

	getCallerIdentity()
	admin("/mock/requests/clear")
	assert.Empty(t, loggedRequests(t, srv), "clear empties the log")

	getCallerIdentity()
	admin("/mock/reset")
	assert.Empty(t, loggedRequests(t, srv), "/mock/reset empties the log")

	getCallerIdentity()
	admin("/mock/snapshot")
	assert.Equal(t, []loggedRequest{sts}, loggedRequests(t, srv), "snapshot leaves the log")
	getCallerIdentity()
	admin("/mock/restore")
	assert.Equal(t, []loggedRequest{sts, sts}, loggedRequests(t, srv), "restore leaves the log")

	require.NoError(t, app.Close())
	_, restarted := newRecordingApp(t, handlers.Options{DBPath: dbPath})
	assert.Empty(t, loggedRequests(t, restarted), "a restart on the same db starts empty")
}

func TestContract_request_log_unimplemented_501(t *testing.T) {
	app, srv := newRecordingApp(t, handlers.Options{DBPath: ":memory:"})
	testRoutes(app)

	resp, body := doGet(t, srv, "/no/such/path")
	require.Equal(t, http.StatusNotImplemented, resp.StatusCode, "NotFound: %s", body)
	resp, body = doGet(t, srv, "/ec2/region/us-east-1")
	require.Equal(t, http.StatusNotImplemented, resp.StatusCode, "MethodNotAllowed: %s", body)
	resp, body = stsCall(t, srv, "AssumeRole")
	require.Equal(t, http.StatusNotImplemented, resp.StatusCode, "%s", body)
	resp, body = ssmCall(t, srv, "GetParametersByPath", `{"Path":"/app"}`)
	require.Equal(t, http.StatusNotImplemented, resp.StatusCode, "%s", body)
	resp, body = iamCall(t, srv, "GetRole", url.Values{"RoleName": {"missing"}})
	require.Equal(t, http.StatusNotFound, resp.StatusCode, "%s", body)
	for _, path := range []string{"/test/503", "/test/marked-200", "/test/remarked"} {
		doGet(t, srv, path)
	}

	assert.Equal(t, []loggedRequest{
		{http.MethodGet, "/no/such/path", http.StatusNotImplemented, "unimplemented-501"},
		{http.MethodGet, "/ec2/region/us-east-1", http.StatusNotImplemented, "unimplemented-501"},
		{http.MethodPost, "/sts/", http.StatusNotImplemented, "unimplemented-501"},
		{http.MethodPost, "/ssm/region/us-east-1", http.StatusNotImplemented, "unimplemented-501"},
		{http.MethodPost, "/iam", http.StatusNotFound, "answered-from-rows"},
		{http.MethodGet, "/test/503", http.StatusServiceUnavailable, "unimplemented-501"},
		{http.MethodGet, "/test/marked-200", http.StatusOK, "unimplemented-501"},
		{http.MethodGet, "/test/remarked", http.StatusOK, "filter-refused"},
	}, loggedRequests(t, srv))
}

func TestContract_request_log_panic_recorded(t *testing.T) {
	app, srv := newRecordingApp(t, handlers.Options{DBPath: ":memory:"})
	testRoutes(app)

	resp, body := doGet(t, srv, "/test/panic")
	require.Equal(t, http.StatusInternalServerError, resp.StatusCode, "%s", body)
	resp, body = doGet(t, srv, "/test/panic-after-200")
	require.Equal(t, http.StatusOK, resp.StatusCode, "the 200 went out before the panic: %s", body)
	assert.Equal(t, []loggedRequest{
		{http.MethodGet, "/test/panic", http.StatusInternalServerError, "unimplemented-501"},
		{http.MethodGet, "/test/panic-after-200", http.StatusInternalServerError, "unimplemented-501"},
	}, loggedRequests(t, srv))
}

func TestContract_state_audit_no_values(t *testing.T) {
	_, srv := newRecordingApp(t, handlers.Options{DBPath: ":memory:"})
	providerTraffic(t, srv)
	const queryAction, jsonOp = "secret-value/with spaces", "secret value"
	resp, body := ec2Call(t, srv, "us-east-1", queryAction, nil)
	require.Equal(t, http.StatusNotFound, resp.StatusCode, "%s", body)
	resp, body = ssmCall(t, srv, jsonOp, `{}`)
	require.Equal(t, http.StatusNotImplemented, resp.StatusCode, "%s", body)

	_, requests := doAdmin(t, srv, http.MethodGet, "/mock/requests", bearer(adminToken))
	_, state := doAdmin(t, srv, http.MethodGet, "/mock/state", bearer(adminToken))
	for _, v := range []string{"secret-bucket-name", queryAction, jsonOp} {
		assert.Contains(t, requests, v, "the request log keeps it")
		assert.NotContains(t, state, v, "it never reaches /mock/state")
	}
	audit := stateAudit(t, srv, bearer(adminToken))
	for _, e := range audit {
		var keys []string
		for k := range e {
			keys = append(keys, k)
		}
		assert.ElementsMatch(t, []string{"service", "protocol", "action", "status", "class"}, keys, "%v", e)
	}
	assert.Equal(t, []map[string]any{
		{"service": "sts", "protocol": "query", "action": "GetCallerIdentity", "status": float64(http.StatusOK), "class": "answered-from-rows"},
		{"service": "sts", "protocol": "query", "action": "AssumeRole", "status": float64(http.StatusNotImplemented), "class": "unimplemented-501"},
		{"service": "", "protocol": "", "action": "", "status": float64(http.StatusNotImplemented), "class": "unimplemented-501"},
		{"service": "ec2", "protocol": "query", "action": "", "status": float64(http.StatusNotFound), "class": "not-modelled-404"},
		{"service": "ssm", "protocol": "json", "action": "", "status": float64(http.StatusNotImplemented), "class": "unimplemented-501"},
	}, audit)
}

func TestRequestLog_ConcurrentRequestsAllRecorded(t *testing.T) {
	_, srv := newRecordingApp(t, handlers.Options{DBPath: ":memory:"})
	const n = 50
	ctx, cancel := context.WithTimeout(context.Background(), requestDeadline)
	defer cancel()

	statuses := make(chan int, n)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			form := url.Values{"Action": {"GetCallerIdentity"}, "Version": {"2011-06-15"}}.Encode()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/sts/", strings.NewReader(form))
			if err != nil {
				statuses <- 0
				return
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := srv.Client().Do(req)
			if err != nil {
				statuses <- 0
				return
			}
			resp.Body.Close()
			statuses <- resp.StatusCode
		})
	}
	wg.Wait()
	close(statuses)
	for status := range statuses {
		require.Equal(t, http.StatusOK, status)
	}

	got := loggedRequests(t, srv)
	assert.Len(t, got, n)
	for _, e := range got {
		assert.Equal(t, loggedRequest{http.MethodPost, "/sts/", http.StatusOK, "answered-from-rows"}, e)
	}
}

func TestRequestLog_AdminTokenGatesIt(t *testing.T) {
	_, srv := newRecordingApp(t, handlers.Options{DBPath: ":memory:"})
	providerTraffic(t, srv)

	for _, rt := range []adminRoute{{http.MethodGet, "/mock/requests"}, {http.MethodPost, "/mock/requests/clear"}} {
		status, body := doAdmin(t, srv, rt.method, rt.path, http.Header{})
		assert.Equal(t, http.StatusUnauthorized, status, "%s %s: %s", rt.method, rt.path, body)
		assert.NotContains(t, body, "secret-bucket-name", "%s %s", rt.method, rt.path)
	}
	status, body := doAdmin(t, srv, http.MethodGet, "/mock/requests", bearer(adminToken))
	assert.Equal(t, http.StatusOK, status, body)
	assert.Contains(t, body, "secret-bucket-name", "the bearer reads the log")
}

// lastClass is the classification of the last request srv recorded.
func lastClass(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	got := loggedRequests(t, srv)
	require.NotEmpty(t, got)
	return got[len(got)-1].Classification
}

func TestContract_request_log_not_modelled_404(t *testing.T) {
	_, srv := newRecordingApp(t, handlers.Options{DBPath: ":memory:"})
	const region = "us-east-1"
	for name, call := range map[string]func() (*http.Response, []byte){
		"EC2 CreateNatGateway":         func() (*http.Response, []byte) { return ec2Call(t, srv, region, "CreateNatGateway", nil) },
		"IAM CreateGroup":              func() (*http.Response, []byte) { return iamCall(t, srv, "CreateGroup", nil) },
		"RDS CreateEventSubscription":  func() (*http.Response, []byte) { return rdsCall(t, srv, region, "CreateEventSubscription", nil) },
		"DynamoDB CreateBackup":        func() (*http.Response, []byte) { return ddbCall(t, srv, region, "CreateBackup", `{}`) },
		"SQS SendMessageBatch":         func() (*http.Response, []byte) { return sqsCall(t, srv, "SendMessageBatch", `{}`) },
		"Secrets Manager RotateSecret": func() (*http.Response, []byte) { return smCall(t, srv, "RotateSecret", `{}`) },
		"KMS Encrypt":                  func() (*http.Response, []byte) { return kmsCall(t, srv, region, "Encrypt", `{}`) },
	} {
		resp, body := call()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, "%s: %s", name, body)
		assert.Contains(t, string(body), "ResourceNotFoundException", name)
		assert.Equal(t, "not-modelled-404", lastClass(t, srv), name)
	}

	_, unknown := ddbCall(t, srv, region, "CreateBackup", `{}`)
	resp, missing := ddbCall(t, srv, region, "DescribeTable", `{"TableName":"missing"}`)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "%s", missing)
	assert.Equal(t, string(unknown), string(missing), "a missing table is wire-identical to the default arm")
	assert.Equal(t, "answered-from-rows", lastClass(t, srv), "DescribeTable on a missing table")
}

func TestContract_request_log_filter_refused(t *testing.T) {
	_, srv := newRecordingApp(t, handlers.Options{DBPath: ":memory:"})
	const region = "us-east-1"
	for _, action := range []string{"DescribeSecurityGroups", "DescribeVolumes", "DescribeRouteTables", "DescribeAddresses", "DescribeNetworkInterfaces", "DescribeTags"} {
		resp, body := ec2Call(t, srv, region, action, url.Values{"Filter.1.Name": {"foo"}, "Filter.1.Value.1": {"bar"}})
		assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "%s: %s", action, body)
		assert.Equal(t, action+": not modelled by fakeaws: foo", extractEC2Tag(body, "Message"), action)
		assert.Equal(t, "filter-refused", lastClass(t, srv), action)
	}

	instNet := newInstanceNet(t, srv, region, "10.0.0.0/16", "10.0.1.0/24")
	instance := runInstance(t, srv, region, topLevelParams(instNet.subnet, instNet.sgs))
	resp, body := ec2Call(t, srv, region, "AllocateAddress", url.Values{"Domain": {"vpc"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "AllocateAddress: %s", body)
	resp, body = ec2Call(t, srv, region, "AssociateAddress", url.Values{
		"AllocationId": {extractEC2Tag(body, "allocationId")}, "InstanceId": {instance}, "AllowReassociation": {"true"},
	})
	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "AllowReassociation: %s", body)
	assert.Equal(t, "filter-refused", lastClass(t, srv), "AllowReassociation")

	ami, nic := "ami-0abcd1234", "NetworkInterface.1."
	for _, c := range []struct {
		action string
		params url.Values
	}{
		{"AllocateAddress", url.Values{"Domain": {"standard"}}},
		{"RunInstances", url.Values{"ImageId": {ami}, "InstanceType": {"t3.micro"}, nic + "DeviceIndex": {"0"}, nic + "NetworkInterfaceId": {"eni-x"}}},
		{"RunInstances", url.Values{"ImageId": {ami}, "InstanceType": {"t3.micro"}}},
		{"RunInstances", url.Values{"SubnetId": {"subnet-x"}, "ImageId": {ami}, "InstanceType": {"t3.micro"},
			"TagSpecification.1.ResourceType": {"spot-instances-request"}, "TagSpecification.1.Tag.1.Key": {"k"}}},
		{"ModifyNetworkInterfaceAttribute", url.Values{"NetworkInterfaceId": {"eni-x"}, "SourceDestCheck.Value": {"false"}}},
		{"CreateVpc", url.Values{"Ipv4IpamPoolId": {"ipam-pool-x"}, "Ipv4NetmaskLength": {"16"}}},
		{"CreateSubnet", url.Values{"VpcId": {"vpc-x"}, "Ipv6Native": {"true"}}},
		{"AssociateRouteTable", url.Values{"RouteTableId": {"rtb-x"}, "GatewayId": {"igw-x"}}},
		{"CreateRoute", url.Values{"RouteTableId": {"rtb-x"}, "DestinationIpv6CidrBlock": {"::/0"}, "GatewayId": {"igw-x"}}},
		{"CreateSecurityGroup", url.Values{"GroupName": {"g"}, "GroupDescription": {"g"}}},
		{"DeleteSecurityGroup", url.Values{"GroupName": {"web"}}},
		{"AuthorizeSecurityGroupIngress", url.Values{"GroupName": {"web"}, "IpPermissions.1.IpProtocol": {"tcp"}}},
		{"AuthorizeSecurityGroupIngress", url.Values{"GroupId": {"sg-x"}, "IpProtocol": {"tcp"}, "FromPort": {"22"}, "ToPort": {"22"}, "CidrIp": {"0.0.0.0/0"}}},
		{"RevokeSecurityGroupIngress", url.Values{"GroupName": {"web"}}},
		{"CreateTags", url.Values{"ResourceId.1": {"vol-x"}, "Tag.1.Key": {"k"}}},
	} {
		resp, body := ec2Call(t, srv, region, c.action, c.params)
		assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "%v: %s", c.params, body)
		assert.Contains(t, extractEC2Tag(body, "Message"), c.action+": not modelled by fakeaws: ", "%v", c.params)
		assert.Equal(t, "filter-refused", lastClass(t, srv), "%v", c.params)
	}
	resp, body = rdsCall(t, srv, region, "ListTagsForResource", url.Values{"ResourceName": {"arn:aws:rds:us-east-1:000000000000:snapshot:x"}})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "RDS tags on a snapshot: %s", body)
	assert.Equal(t, "filter-refused", lastClass(t, srv), "RDS tags on a snapshot")
	resp, body = r53Request(t, srv, http.MethodGet, "/route53/2013-04-01/tags/healthcheck/x", "")
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "Route53 tags on a health check: %s", body)
	assert.Equal(t, "filter-refused", lastClass(t, srv), "Route53 tags on a health check")

	for _, c := range []struct{ name, op, body string }{
		{"Filters", "DescribeParameters", `{"Filters":[{"Key":"Name","Values":["x"]}]}`},
		{"non-Name ParameterFilter", "DescribeParameters", `{"ParameterFilters":[{"Key":"Type","Values":["String"]}]}`},
		{"ListTagsForResource", "ListTagsForResource", `{"ResourceType":"Document","ResourceId":"x"}`},
		{"AddTagsToResource", "AddTagsToResource", `{"ResourceType":"Document","ResourceId":"x","Tags":[{"Key":"k","Value":"v"}]}`},
		{"RemoveTagsFromResource", "RemoveTagsFromResource", `{"ResourceType":"Document","ResourceId":"x","TagKeys":["k"]}`},
	} {
		resp, body := ssmCall(t, srv, c.op, c.body)
		assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "%s: %s", c.name, body)
		assert.Equal(t, "filter-refused", lastClass(t, srv), c.name)
	}
	resp, body = kmsCall(t, srv, region, "DescribeKey", `{"KeyId":"alias/app"}`)
	assert.Equal(t, http.StatusNotImplemented, resp.StatusCode, "KMS DescribeKey by alias: %s", body)
	assert.Equal(t, "filter-refused", lastClass(t, srv), "KMS DescribeKey by alias")

	_, body = ec2Call(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.1.0.0/16"}})
	dup := url.Values{"GroupName": {"dup"}, "GroupDescription": {"dup"}, "VpcId": {extractEC2Tag(body, "vpcId")}}
	resp, body = ec2Call(t, srv, region, "CreateSecurityGroup", dup)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%s", body)
	resp, body = ec2Call(t, srv, region, "CreateSecurityGroup", dup)
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "a duplicate group name in one VPC: %s", body)
	assert.Equal(t, "answered-from-rows", lastClass(t, srv), "a modelled 409")

	resp, body = ec2Call(t, srv, region, "CreateVpc", url.Values{
		"CidrBlock": {"10.2.0.0/16"}, "TagSpecification.1.ResourceType": {"subnet"}, "TagSpecification.1.Tag.1.Key": {"k"},
	})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "CreateVpc with a subnet TagSpecification: %s", body)
	assert.Equal(t, "answered-from-rows", lastClass(t, srv), "a TagSpecification type EC2 refuses too")
}

func TestContract_request_log_empty_collection(t *testing.T) {
	_, srv := newRecordingApp(t, handlers.Options{DBPath: ":memory:"})
	const region = "us-east-1"
	for _, action := range []string{"DescribeVolumes", "DescribeNatGateways", "DescribeSnapshots", "DescribeLaunchTemplates"} {
		resp, body := ec2Call(t, srv, region, action, nil)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "%s: %s", action, body)
		assert.Equal(t, "empty-collection", lastClass(t, srv), action)
	}

	resp, body := ec2Call(t, srv, region, "DescribeVpcs", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "%s", body)
	require.Empty(t, extractEC2Tag(body, "vpcId"), "an empty account: %s", body)
	assert.Equal(t, "answered-from-rows", lastClass(t, srv), "DescribeVpcs on an empty account")
}

func TestContract_request_log_read_set_entry(t *testing.T) {
	_, srv := newRecordingApp(t, handlers.Options{DBPath: ":memory:"})
	const region = "us-east-1"
	type call = func() (*http.Response, []byte)
	for _, c := range []struct {
		name string
		call call
		want readSet
	}{
		{"EC2 DescribeSubnets", func() (*http.Response, []byte) {
			return ec2Call(t, srv, region, "DescribeSubnets", url.Values{"Filter.1.Name": {"vpc-id"}, "Filter.1.Value.1": {"vpc-1"}})
		}, readSet{"ec2", "query", "DescribeSubnets", map[string]any{"Filter.1.Name": "vpc-id", "Filter.1.Value.1": "vpc-1"}, http.StatusOK}},
		{"IAM GetRole", func() (*http.Response, []byte) {
			return iamCall(t, srv, "GetRole", url.Values{"RoleName": {"app"}})
		}, readSet{"iam", "query", "GetRole", map[string]any{"RoleName": "app"}, http.StatusNotFound}},
		{"STS GetCallerIdentity", func() (*http.Response, []byte) {
			return stsCall(t, srv, "GetCallerIdentity")
		}, readSet{"sts", "query", "GetCallerIdentity", map[string]any{}, http.StatusOK}},
		{"RDS DescribeDBInstances", func() (*http.Response, []byte) {
			return rdsCall(t, srv, region, "DescribeDBInstances", url.Values{"DBInstanceIdentifier": {"app-db"}})
		}, readSet{"rds", "query", "DescribeDBInstances", map[string]any{"DBInstanceIdentifier": "app-db"}, http.StatusNotFound}},
		{"SSM GetParameter", func() (*http.Response, []byte) {
			return ssmCall(t, srv, "GetParameter", `{"Name":"/app/db/host","WithDecryption":true}`)
		}, readSet{"ssm", "json", "GetParameter", map[string]any{"Name": "/app/db/host", "WithDecryption": true}, http.StatusBadRequest}},
		{"DynamoDB DescribeTable", func() (*http.Response, []byte) {
			return ddbCall(t, srv, region, "DescribeTable", `{"TableName":"app"}`)
		}, readSet{"dynamodb", "json", "DescribeTable", map[string]any{"TableName": "app"}, http.StatusNotFound}},
		{"KMS DescribeKey", func() (*http.Response, []byte) {
			return kmsCall(t, srv, region, "DescribeKey", `{"KeyId":"alias/app"}`)
		}, readSet{"kms", "json", "DescribeKey", map[string]any{"KeyId": "alias/app"}, http.StatusNotImplemented}},
		{"Secrets Manager DescribeSecret", func() (*http.Response, []byte) {
			return smCall(t, srv, "DescribeSecret", `{"SecretId":"app/db"}`)
		}, readSet{"secretsmanager", "json", "DescribeSecret", map[string]any{"SecretId": "app/db"}, http.StatusNotFound}},
		{"SQS GetQueueUrl", func() (*http.Response, []byte) {
			return sqsCall(t, srv, "GetQueueUrl", `{"QueueName":"app"}`)
		}, readSet{"sqs", "json", "GetQueueUrl", map[string]any{"QueueName": "app"}, http.StatusNotFound}},
		{"a repeated query key", func() (*http.Response, []byte) {
			return ec2Call(t, srv, region, "DescribeVpcs", url.Values{"VpcId.1": {"vpc-a", "vpc-b"}})
		}, readSet{"ec2", "query", "DescribeVpcs", nil, http.StatusBadRequest}},
		{"a json body that is not an object", func() (*http.Response, []byte) {
			return ssmCall(t, srv, "GetParameter", `not json`)
		}, readSet{"ssm", "json", "GetParameter", nil, http.StatusBadRequest}},
		{"a path no service owns", func() (*http.Response, []byte) {
			return doGet(t, srv, "/nowhere")
		}, readSet{"", "", "", nil, http.StatusNotImplemented}},
		{"an unrouted EKS path", func() (*http.Response, []byte) {
			return eksRequest(t, srv, http.MethodGet, "/eks/region/us-east-1/nope", "")
		}, readSet{"eks", "rest", "", map[string]any{"path": "/eks/region/us-east-1/nope", "query": ""}, http.StatusNotImplemented}},
		{"an unrouted S3 path", func() (*http.Response, []byte) {
			return s3Do(t, srv, http.MethodPut, "/s3/b/dir/key.txt?acl", "", "")
		}, readSet{"s3", "rest", "", map[string]any{"path": "/s3/b/dir/key.txt", "query": "acl"}, http.StatusNotImplemented}},
		{"a method no S3 route takes", func() (*http.Response, []byte) {
			return s3Do(t, srv, http.MethodPatch, "/s3/b", "", "")
		}, readSet{"s3", "rest", "", map[string]any{"path": "/s3/b", "query": ""}, http.StatusNotImplemented}},
	} {
		resp, body := c.call()
		assert.Equal(t, c.want.Status, resp.StatusCode, "%s: %s", c.name, body)
		got := mockRequests[readSet](t, srv)
		require.NotEmpty(t, got, c.name)
		assert.Equal(t, c.want, got[len(got)-1], c.name)
	}
}

func TestRequestLog_RESTEntries(t *testing.T) {
	_, srv := newRecordingApp(t, handlers.Options{DBPath: ":memory:"})
	resp, body := s3Do(t, srv, http.MethodPut, "/s3/web-assets/", "", "")
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateBucket: %s", body)
	for _, sub := range []string{"tagging", "policy"} {
		resp, body = s3Do(t, srv, http.MethodGet, "/s3/web-assets/?"+sub, "", "")
		require.Equal(t, http.StatusNotFound, resp.StatusCode, "%s: %s", sub, body)
	}
	resp, body = eksRequest(t, srv, http.MethodGet, "/eks/region/us-east-1/clusters/demo", "")
	require.Equal(t, http.StatusNotFound, resp.StatusCode, "DescribeCluster: %s", body)
	resp, body = r53Request(t, srv, http.MethodGet, "/route53/2013-04-01/hostedzone/Z1", "")
	require.Equal(t, http.StatusNotFound, resp.StatusCode, "GetHostedZone: %s", body)

	bucket := func(method, query string, status int) readSet {
		return readSet{"s3", "rest", method + " /s3/{bucket}/", map[string]any{"path": "/s3/web-assets/", "query": query}, status}
	}
	assert.Equal(t, []readSet{
		bucket(http.MethodPut, "", http.StatusOK),
		bucket(http.MethodGet, "tagging", http.StatusNotFound),
		bucket(http.MethodGet, "policy", http.StatusNotFound),
		{"eks", "rest", "GET /eks/region/{region}/clusters/{name}", map[string]any{"path": "/eks/region/us-east-1/clusters/demo", "query": ""}, http.StatusNotFound},
		{"route53", "rest", "GET /route53/2013-04-01/hostedzone/{id}", map[string]any{"path": "/route53/2013-04-01/hostedzone/Z1", "query": ""}, http.StatusNotFound},
	}, mockRequests[readSet](t, srv), "two subresources on one bucket differ only in params.query")
}

func TestRequestLog_BodyRestored(t *testing.T) {
	_, srv := newRecordingApp(t, handlers.Options{DBPath: ":memory:"})
	t.Run("query", func(t *testing.T) {
		const region = "us-east-1"
		resp, body := ec2Call(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
		require.Equal(t, http.StatusOK, resp.StatusCode, "CreateVpc: %s", body)
		vpc := extractEC2Tag(body, "vpcId")
		resp, body = ec2Call(t, srv, region, "DescribeVpcs", url.Values{"VpcId.1": {vpc}})
		assert.Equal(t, http.StatusOK, resp.StatusCode, "DescribeVpcs: %s", body)
		assert.Equal(t, vpc, extractEC2Tag(body, "vpcId"), "%s", body)

		trust := `{"Version":"2012-10-17","Statement":[]}`
		resp, body = iamCall(t, srv, "CreateRole", url.Values{"RoleName": {"restored"}, "AssumeRolePolicyDocument": {trust}})
		require.Equal(t, http.StatusOK, resp.StatusCode, "CreateRole: %s", body)
		resp, body = iamCall(t, srv, "GetRole", url.Values{"RoleName": {"restored"}})
		assert.Equal(t, http.StatusOK, resp.StatusCode, "GetRole: %s", body)
		assert.Contains(t, string(body), "<RoleName>restored</RoleName>")
	})
	t.Run("json", func(t *testing.T) {
		const value = `a&b=c "quoted" \ é ✓`
		put, err := json.Marshal(map[string]string{"Name": "/restored", "Value": value, "Type": "String"})
		require.NoError(t, err)
		resp, body := ssmCall(t, srv, "PutParameter", string(put))
		require.Equal(t, http.StatusOK, resp.StatusCode, "PutParameter: %s", body)
		status, got, body := ssmGetValue(t, srv, "/restored")
		assert.Equal(t, http.StatusOK, status, "GetParameter: %s", body)
		assert.Equal(t, value, got, "byte-exact")
	})
}

func TestRequestLog_ParamsStayInMemory(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "fakeaws.db")
	_, srv := newRecordingApp(t, handlers.Options{DBPath: dbPath})
	const stored, value, missing = "stored-control-4b1d", "logged-only-value-7f3a", "/logged-only/missing-9c1e"

	put := func(v string) (*http.Response, []byte) {
		return ssmCall(t, srv, "PutParameter", `{"Name":"/in-memory","Value":"`+v+`","Type":"String"}`)
	}
	resp, body := put(stored)
	require.Equal(t, http.StatusOK, resp.StatusCode, "PutParameter: %s", body)
	resp, body = put(value)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "PutParameter without Overwrite stores nothing: %s", body)
	resp, body = ssmCall(t, srv, "GetParameter", `{"Name":"`+missing+`"}`)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "GetParameter: %s", body)
	status, snap := doAdmin(t, srv, http.MethodPost, "/mock/snapshot", bearer(adminToken))
	require.Equal(t, http.StatusOK, status, snap)

	_, requests := doAdmin(t, srv, http.MethodGet, "/mock/requests", bearer(adminToken))
	_, state := doAdmin(t, srv, http.MethodGet, "/mock/state", bearer(adminToken))
	files := map[string]string{"/mock/requests": requests, "/mock/state": state}
	for _, name := range []string{dbPath, dbPath + "-wal", dbPath + ".snapshot"} {
		b, err := os.ReadFile(name)
		if !errors.Is(err, os.ErrNotExist) {
			require.NoError(t, err, name)
		}
		files[name] = string(b)
	}
	assert.Contains(t, files[dbPath]+files[dbPath+"-wal"], stored, "the db holds the stored parameter")
	assert.Contains(t, files[dbPath+".snapshot"], stored, "the snapshot holds the stored parameter")
	for _, s := range []string{value, missing} {
		assert.Contains(t, requests, s, "the request log holds the params")
		for name, content := range files {
			if name != "/mock/requests" {
				assert.NotContains(t, content, s, name)
			}
		}
	}
}

func TestRequestLog_EveryLandedServiceHasAProtocol(t *testing.T) {
	var services []string
	for s := range handlers.ServiceProtocols {
		services = append(services, s)
	}
	assert.ElementsMatch(t, handlers.LandedServices, services)
}
