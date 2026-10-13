package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redscaresu/fakeaws/handlers"
)

// DescribeImages.xml's images: AL2023 x86_64, the al2023 parameter's
// value in GetParameter.json, and arm64, both Amazon's.
const (
	imageX86     = ssmFixtureAMI
	imageArm     = "ami-1234567890abcdef0"
	amazonOwner  = "137112412989"
	imageNameAll = "al2023-ami-2023.*"
)

// imagesRecorded is DescribeImages.xml as the answer to a read of both
// its images by id.
func imagesRecorded(t *testing.T) netRecorded {
	return netRecorded{"DescribeImages", map[string]string{"ImageId.1": imageX86, "ImageId.2": imageArm}, ec2Fixture(t, "DescribeImages")}
}

// loadImages loads exchanges into loadAccount in tagRegion, where
// describeImageIDs reads, and returns the answer.
func loadImages(t *testing.T, srv *httptest.Server, exchanges ...string) string {
	t.Helper()
	status, body := postLoad(t, srv, loadEnvelope(loadAccount, tagRegion, exchanges...))
	require.Equal(t, http.StatusOK, status, body)
	return body
}

// TestLoadEC2Images_AnswerAsRecorded: both images load, and
// DescribeImages by Owner.1=amazon with a name filter, by their numeric
// owner, and by id each answer DescribeImages.xml, by the load diff in
// both directions.
func TestLoadEC2Images_AnswerAsRecorded(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	recorded := imagesRecorded(t)
	assert.JSONEq(t, `{"loaded":{"image":2},"absent":{},"unresolved":{}}`, loadImages(t, srv, recorded.exchange()))

	want, err := handlers.ParseXML([]byte(recorded.body))
	require.NoError(t, err)
	for _, params := range []url.Values{
		{"Owner.1": {"amazon"}, "Filter.1.Name": {"name"}, "Filter.1.Value.1": {imageNameAll}},
		{"Owner.1": {amazonOwner}},
		{"ImageId.1": {imageX86}, "ImageId.2": {imageArm}},
	} {
		answered, err := handlers.ParseXML(mustOK(t)(ec2Call(t, srv, tagRegion, "DescribeImages", params)))
		require.NoError(t, err)
		rec, ren := handlers.Diff(handlers.LoadKey{Service: "ec2", Action: "DescribeImages"}, want, answered)
		assert.Empty(t, rec, "%v: recorded only", params)
		assert.Empty(t, ren, "%v: answered only", params)
	}
}

// TestLoadEC2Images_Filters: each filter the loader's fields answer
// selects the loaded images that hold it; the fixtures stay suppressed,
// and no loaded image is the caller's own.
func TestLoadEC2Images_Filters(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	loadImages(t, srv, imagesRecorded(t).exchange())
	filter := func(name, value string) url.Values {
		return url.Values{"Filter.1.Name": {name}, "Filter.1.Value.1": {value}}
	}
	both := []string{imageX86, imageArm}
	for _, c := range []struct {
		params url.Values
		want   []string
	}{
		{filter("architecture", "arm64"), []string{imageArm}},
		{filter("architecture", "x86_64"), []string{imageX86}},
		{filter("owner-alias", "amazon"), both},
		{filter("is-public", "true"), both},
		{filter("is-public", "false"), nil},
		{filter("root-device-type", "ebs"), both},
		{filter("platform-details", "Linux/UNIX"), both},
		{filter("platform-details", "Windows"), nil},
		{url.Values{"Owner.1": {"amazon"}}, both},
		{url.Values{"Owner.1": {"aws-marketplace"}}, nil},
		{url.Values{"Owner.1": {"self"}}, nil},
		{nil, both},
	} {
		assert.ElementsMatch(t, c.want, describeImageIDs(t, srv, c.params), "%v", c.params)
	}
}

// TestLoadEC2Images_ResolveReferences: a recorded DescribeImages of the
// image the al2023 parameter's value or a loaded instance names
// resolves it, so the load answers no image under unresolved.
func TestLoadEC2Images_ResolveReferences(t *testing.T) {
	t.Run("al2023 parameter", func(t *testing.T) {
		_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
		images := netRecorded{"DescribeImages", map[string]string{"ImageId.1": imageX86}, ec2Fixture(t, "DescribeImages")}
		var answer struct{ Unresolved map[string][]string }
		require.NoError(t, json.Unmarshal([]byte(loadImages(t, srv, ssmGetParameterExchange(http.StatusOK, ssmFixture(t)), images.exchange())), &answer))
		assert.Empty(t, answer.Unresolved)
	})
	t.Run("instance", func(t *testing.T) {
		_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
		body := strings.ReplaceAll(ec2Fixture(t, "DescribeImages"), imageX86, fixtureImage)
		images := netRecorded{"DescribeImages", map[string]string{"ImageId.1": fixtureImage}, body}
		var answer struct{ Unresolved map[string][]string }
		require.NoError(t, json.Unmarshal([]byte(loadNet(t, srv, append(instanceRecording(t), images)...)), &answer))
		assert.NotContains(t, answer.Unresolved, "image")
		assert.Contains(t, answer.Unresolved, "instance-profile", "the rest stays unresolved")
	})
}

// TestLoadEC2Images_SeedRefusesRecordedFields: /mock/images seeds no
// field only a load stores.
func TestLoadEC2Images_SeedRefusesRecordedFields(t *testing.T) {
	_, srv := newLoadApp(t, handlers.Options{DBPath: ":memory:"})
	status, body := mockCall(t, srv, http.MethodPost, "/mock/images",
		`{"ami_id":"ami-0123456789abcdef0","name":"x","root_device_name":"/dev/xvda","region":"us-east-1","architecture":"arm64"}`)
	assert.Equal(t, http.StatusBadRequest, status, body)
	assert.Contains(t, body, "a seeded image holds no recorded field")
}
