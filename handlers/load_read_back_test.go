package handlers_test

// load_read_back_test.go — TestLoadReadBack loads each recorded read
// into an in-process fakeaws and re-sends every exchange's request,
// diffing each answer against its recorded body. Its report names the
// read, the exchange, its action and a path, never a body or a value:
// the read may be a real account's raw read (FAKEAWS_LOAD_READ).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redscaresu/fakeaws/handlers"
)

// loadReadEnv, when set, names the one recorded read TestLoadReadBack
// runs on (a relative path is from handlers/) in place of
// testdata/load/*.json. Set to an empty or unreadable path, it fails.
const loadReadEnv = "FAKEAWS_LOAD_READ"

// readBackTimeout bounds each request a read-back sends.
const readBackTimeout = 30 * time.Second

func TestLoadReadBack(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "testdata", "load", "*.json"))
	require.NoError(t, err)
	if path, ok := os.LookupEnv(loadReadEnv); ok {
		paths = []string{path}
	}
	require.NotEmpty(t, paths, "no recorded read under testdata/load")
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			read, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Empty(t, readBack(t, filepath.Base(path), read))
		})
	}
}

// readBackExchange is a recorded exchange, as a read-back re-sends it.
type readBackExchange struct {
	Service, Protocol, Action string
	Params                    json.RawMessage
	Status                    int
	Body                      string
}

// readBacker reads back one loaded read, named name.
type readBacker struct {
	t         *testing.T
	srv       *httptest.Server
	name      string
	read      []byte
	region    string
	exchanges []readBackExchange
}

// readBack POSTs read to /mock/load of a fresh in-process fakeaws
// (:memory:, the admin token, -load-max-bytes the read's size). Loaded,
// it re-sends each entry's first request and diffs the answer, in both
// directions, against the union of the entry's pages. It returns
// every difference and refusal, each naming name, and an exchange, its
// action and a path where it can; nothing of a body.
func readBack(t *testing.T, name string, read []byte) []string {
	t.Helper()
	var env struct {
		Region    string
		Exchanges []readBackExchange
	}
	if err := json.Unmarshal(read, &env); err != nil {
		return []string{name + ": not a recorded read"}
	}
	if len(env.Exchanges) == 0 {
		return []string{name + ": no exchange to read back"}
	}
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:", LoadMaxBytes: int64(len(read))})
	srv.Client().Timeout = readBackTimeout
	r := &readBacker{t: t, srv: srv, name: name, read: read, region: env.Region, exchanges: env.Exchanges}
	status, body := postLoad(t, srv, string(read))
	if status != http.StatusOK {
		return r.refused(status, []byte(body))
	}
	r.logCounts([]byte(body))
	var report []string
	for _, entry := range r.entries() {
		report = append(report, r.compare(entry)...)
	}
	return report
}

// logCounts logs a load answer's per-type counts: the unresolved ids
// are values, so only how many.
func (r *readBacker) logCounts(answer []byte) {
	var a struct {
		Loaded, Absent map[string]int
		Unresolved     map[string][]string
	}
	require.NoError(r.t, json.Unmarshal(answer, &a))
	unresolved := map[string]int{}
	for typ, ids := range a.Unresolved {
		unresolved[typ] = len(ids)
	}
	r.t.Logf("%s: loaded %v, absent %v, unresolved %v", r.name, a.Loaded, a.Absent, unresolved)
}

var (
	// readBackShown is a service or action a line shows: any other is
	// shown as {name}.
	readBackShown = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
	// readBackPath is a path load_diff.go's Diff names (diffLabel).
	readBackPath = regexp.MustCompile(`^[A-Za-z0-9@{}\[\]./]+$`)
	// readBackRefusal is a load refusal of one exchange.
	readBackRefusal = regexp.MustCompile(`^exchange (\d+): `)
	// readBackRefusedPaths are the refusals of the load's rendering diff,
	// each ending in the path it names.
	readBackRefusedPaths = map[string]*regexp.Regexp{
		"recorded only": refusedPathRE(handlers.LoadRecordedOnly),
		"rendered only": refusedPathRE(handlers.LoadRenderedOnly),
	}
)

// refusedPathRE matches a refusal ending in format, capturing its path.
func refusedPathRE(format string) *regexp.Regexp {
	before, after, _ := strings.Cut(format, "%s")
	return regexp.MustCompile(": " + regexp.QuoteMeta(before) + `(\S+)` + regexp.QuoteMeta(after) + "$")
}

// line is a report line about exchange i.
func (r *readBacker) line(i int, format string, args ...any) string {
	shown := func(s string) string {
		if readBackShown.MatchString(s) {
			return s
		}
		return "{name}"
	}
	ex := r.exchanges[i]
	return fmt.Sprintf("%s: exchange %d: %s %s: ", r.name, i, shown(ex.Service), shown(ex.Action)) + fmt.Sprintf(format, args...)
}

// refused reports a load that answered status and body, not 200: each
// refusal's exchange and, for a rendering diff's, its path. The rest of
// a refusal can quote the read, so it is withheld.
func (r *readBacker) refused(status int, body []byte) []string {
	var answer struct{ Refusals []string }
	if status != http.StatusBadRequest || json.Unmarshal(body, &answer) != nil || len(answer.Refusals) == 0 {
		return []string{fmt.Sprintf("%s: the load answered %d", r.name, status)}
	}
	out := make([]string, len(answer.Refusals))
	for k, refusal := range answer.Refusals {
		out[k] = r.refusal(refusal)
	}
	return out
}

func (r *readBacker) refusal(refusal string) string {
	const withheld = "(its text withheld: it can quote the read)"
	m := readBackRefusal.FindStringSubmatch(refusal)
	if m == nil {
		return r.name + ": the load refused the read " + withheld
	}
	i, err := strconv.Atoi(m[1])
	if err != nil || i >= len(r.exchanges) {
		return r.name + ": the load refused the read " + withheld
	}
	for what, re := range readBackRefusedPaths {
		if p := re.FindStringSubmatch(refusal); p != nil && readBackPath.MatchString(p[1]) {
			return r.line(i, "the load refused it: %s %s", what, p[1])
		}
	}
	return r.line(i, "the load refused it "+withheld)
}

// entries are the read's exchanges by the request that made them: each
// page chain the load linked (handlers.LoadChains), and each other
// exchange alone, a NotFound or a 2xx page no chain holds, in recorded
// order.
func (r *readBacker) entries() [][]int {
	chains, err := handlers.LoadChains(r.read)
	require.NoError(r.t, err)
	byFirst, chained := map[int][]int{}, map[int]bool{}
	for _, c := range chains {
		byFirst[c[0]] = c
		for _, i := range c {
			chained[i] = true
		}
	}
	var out [][]int
	for i := range r.exchanges {
		switch c, first := byFirst[i]; {
		case first:
			out = append(out, c)
		case !chained[i]:
			out = append(out, []int{i})
		}
	}
	return out
}

func readBackOK(status int) bool {
	return status >= http.StatusOK && status < http.StatusMultipleChoices
}

// compare re-sends entry's first request and reports how the answer
// differs: a 2xx entry by every path where its pages' union and the
// answer differ, a NotFound unless it answers its status and code.
func (r *readBacker) compare(entry []int) []string {
	i, ex := entry[0], r.exchanges[entry[0]]
	status, body, problem := r.resend(ex)
	if problem != "" {
		return []string{r.line(i, "%s", problem)}
	}
	answered, err := handlers.ParseLoadBody(ex.Protocol, body)
	if !readBackOK(ex.Status) {
		recorded, _ := handlers.ParseLoadBody(ex.Protocol, []byte(ex.Body)) // the load parsed it to read its code
		if status == ex.Status && err == nil && handlers.LoadErrorCode(answered) == handlers.LoadErrorCode(recorded) {
			return nil
		}
		return []string{r.line(i, "answered status %d, not the recorded NotFound (status %d, its code)", status, ex.Status)}
	}
	if !readBackOK(status) || err != nil {
		return []string{r.line(i, "answered status %d, which does not parse as a %d answer", status, ex.Status)}
	}
	pages := make([]*handlers.Tree, len(entry))
	for k, j := range entry {
		pages[k], _ = handlers.ParseLoadBody(ex.Protocol, []byte(r.exchanges[j].Body)) // the load parsed every 2xx body
	}
	recorded, err := handlers.MergePages(pages...)
	if err != nil {
		return []string{r.line(i, "its pages do not merge: %v", err)}
	}
	var out []string
	recordedOnly, answeredOnly := handlers.Diff(handlers.LoadKey{Service: ex.Service, Action: ex.Action}, recorded, answered)
	for _, p := range recordedOnly {
		out = append(out, r.line(i, "recorded only %s", p))
	}
	for _, p := range answeredOnly {
		out = append(out, r.line(i, "answered only %s", p))
	}
	return out
}

// readBackQuery sends a query service's request through its test
// helper, which adds Action and Version as infrafactory's reader does.
var readBackQuery = map[string]func(r *readBacker, action string, form url.Values) (*http.Response, []byte){
	"ec2": func(r *readBacker, action string, form url.Values) (*http.Response, []byte) {
		return ec2Call(r.t, r.srv, r.region, action, form)
	},
	"iam": func(r *readBacker, action string, form url.Values) (*http.Response, []byte) {
		return iamCall(r.t, r.srv, action, form)
	},
}

// resend sends ex's request as infrafactory's reader sent it
// (internal/harness/aws_reader.go, awsReplay.request): a query
// exchange's params as a form with Action and Version (readBackQuery),
// an SSM json one's as the body with X-Amz-Target (ssmDoIn). It returns
// the status and body, or why it sent nothing: an exchange of any other
// service is reported, never skipped.
func (r *readBacker) resend(ex readBackExchange) (int, []byte, string) {
	if ex.Service == "ssm" {
		resp, err := ssmDoIn(r.srv, r.region, ex.Action, string(ex.Params))
		require.NoError(r.t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(r.t, err)
		return resp.StatusCode, body, ""
	}
	send, ok := readBackQuery[ex.Service]
	if !ok {
		return 0, nil, "its service is not one a read-back re-sends"
	}
	var params map[string]string
	if err := json.Unmarshal(ex.Params, &params); err != nil {
		return 0, nil, "its params are not a query form"
	}
	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	resp, body := send(r, ex.Action, form)
	return resp.StatusCode, body, ""
}

// loadReadFixture is testdata/load/<name>.
func loadReadFixture(t *testing.T, name string) []byte {
	t.Helper()
	read, err := os.ReadFile(filepath.Join("..", "testdata", "load", name))
	require.NoError(t, err)
	return read
}

// readBackMarker is the value TestLoadReadBack_ReportsNoValue plants.
const readBackMarker = "SECRET-MARKER-123"

// plantMarker is read with value replaced by readBackMarker in within,
// which exchange i's body holds once.
func plantMarker(t *testing.T, read []byte, i int, within, value string) []byte {
	t.Helper()
	var env map[string]any
	require.NoError(t, json.Unmarshal(read, &env))
	ex := env["exchanges"].([]any)[i].(map[string]any)
	body := ex["body"].(string)
	require.Equal(t, 1, strings.Count(body, within), "exchange %d holds %q once", i, within)
	ex["body"] = strings.Replace(body, within, strings.Replace(within, value, readBackMarker, 1), 1)
	out, err := json.Marshal(env)
	require.NoError(t, err)
	return out
}

// TestLoadReadBack_ReportsNoValue: a value planted in a copy of the
// step-0 read fails it, whether the load refuses it by its reference
// (the refusal quoting it) or by the path where its rendering differs,
// or the read back differs, and the report names the exchange, its
// action and a path where it has one, never the value.
func TestLoadReadBack_ReportsNoValue(t *testing.T) {
	read := loadReadFixture(t, "step0-synthetic.json")
	for _, tc := range []struct {
		name     string
		exchange int
		within   string
		value    string
		want     []string
	}{
		{"the instance's key pair, which the load refuses naming it", 12, "<keyName>my-key-pair</keyName>", "my-key-pair",
			[]string{"planted: exchange 12: ec2 DescribeInstances: the load refused it (its text withheld: it can quote the read)"}},
		{"the subnet's zone id, which renders from the zone's row", 5, "<availabilityZoneId>usw2-az3</availabilityZoneId>", "usw2-az3",
			[]string{"planted: exchange 5: ec2 DescribeSubnets: the load refused it: recorded only subnetSet/item[0]/availabilityZoneId",
				"planted: exchange 5: ec2 DescribeSubnets: the load refused it: rendered only subnetSet/item[0]/availabilityZoneId"}},
		{"the tag key the VPC is read by", 0, "<key>infrafactory-run-id</key>", "infrafactory-run-id",
			[]string{"planted: exchange 0: ec2 DescribeVpcs: recorded only vpcSet/item[0]"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := readBack(t, "planted", plantMarker(t, read, tc.exchange, tc.within, tc.value))
			assert.Equal(t, tc.want, report)
			assert.NotContains(t, strings.Join(report, "\n"), readBackMarker)
		})
	}
}

// TestLoadReadBack_PagesAndNotFound: a paged read's pages, merged, equal
// the one answer fakeaws gives, and so do each chain's when the read
// sends the request twice; a role's IAM read reads back equal; a
// NotFound reads back equal only as its status and code, so one of a
// parameter another exchange loads fails, and so does one whose request
// fakeaws refuses with another code.
func TestLoadReadBack_PagesAndNotFound(t *testing.T) {
	const vpc = "vpc-0paged"
	subnets := func(params map[string]string, subnet, tail string) netRecorded {
		return netRecorded{"DescribeSubnets", params, "<DescribeSubnetsResponse><subnetSet>" + netSubnet(subnet, vpc, "") + "</subnetSet>" + tail + "</DescribeSubnetsResponse>"}
	}
	var paged []string
	for _, r := range append([]netRecorded{
		netVpcs(netVpc(vpc, "<isDefault>false</isDefault>")),
		subnets(map[string]string{}, "subnet-0first", "<nextToken>page-2</nextToken>"),
		subnets(map[string]string{"NextToken": "page-2"}, "subnet-0second", ""),
	}, netDNS(vpc, true)...) {
		paged = append(paged, r.exchange())
	}
	const notFoundBody = `{"__type":"ParameterNotFound","message":"x"}`
	notFound := ssmGetParameterExchange(http.StatusBadRequest, notFoundBody)
	badName, err := json.Marshal(map[string]any{"service": "ssm", "protocol": "json", "action": "GetParameter",
		"params": map[string]any{"Name": 5}, "status": http.StatusBadRequest, "body": notFoundBody})
	require.NoError(t, err)
	read := func(exchanges ...string) string { return loadEnvelope(loadAccount, netRegion, exchanges...) }
	for _, tc := range []struct {
		name string
		read string
		want []string
	}{
		{"paged", read(paged...), nil},
		{"paged, read twice", read(slices.Concat(paged, paged[1:3])...), nil},
		{"a role", iamReadEnvelope(t, iamRoleRead, asRecorded), nil},
		{"not found", read(notFound), nil},
		{"not found but loaded", read(ssmGetParameterExchange(http.StatusOK, ssmFixture(t)), notFound),
			[]string{"not found but loaded: exchange 1: ssm GetParameter: answered status 200, not the recorded NotFound (status 400, its code)"}},
		{"not found, refused with another code", read(string(badName)),
			[]string{"not found, refused with another code: exchange 0: ssm GetParameter: answered status 400, not the recorded NotFound (status 400, its code)"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, readBack(t, tc.name, []byte(tc.read)))
		})
	}
}

// TestLoadReadBack_UnreadableReadFails runs TestLoadReadBack with
// FAKEAWS_LOAD_READ naming a missing file, a directory and nothing:
// each fails, and none skips.
func TestLoadReadBack_UnreadableReadFails(t *testing.T) {
	for name, path := range map[string]string{
		"missing":     filepath.Join(t.TempDir(), "missing.json"),
		"a directory": t.TempDir(),
		"empty":       "",
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLoadReadBack$", "-test.v", "-test.count=1")
			cmd.Env = append(os.Environ(), loadReadEnv+"="+path)
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
			cmd.WaitDelay = 10 * time.Second
			out, err := cmd.CombinedOutput()

			require.NoError(t, ctx.Err(), "%s", out)
			var exit *exec.ExitError
			require.ErrorAs(t, err, &exit, "%s", out)
			assert.Contains(t, string(out), "--- FAIL: TestLoadReadBack")
			assert.NotContains(t, string(out), "--- SKIP")
		})
	}
}
