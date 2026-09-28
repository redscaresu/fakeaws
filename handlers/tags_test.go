package handlers_test

import (
	"encoding/json"
	"encoding/xml"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every ARN-addressed service runs the same script: create with
// tagsAtCreate (a tag with no value, a key with ':' and '/'), read them
// back exactly, add tagsAdded, remove removedKey, and see the rest
// untouched each time.
var (
	tagsAtCreate = map[string]string{"run-id": "r1", "empty": "", "kubernetes.io/cluster:demo": "owned"}
	tagsAdded    = map[string]string{"added": "a", "run-id": "r2"}
	removedKey   = "kubernetes.io/cluster:demo"
)

func tagsAfterAdd() map[string]string {
	out := maps.Clone(tagsAtCreate)
	maps.Copy(out, tagsAdded)
	return out
}

func tagsAfterRemove() map[string]string {
	out := tagsAfterAdd()
	delete(out, removedKey)
	return out
}

// queryTagParams sets tags as a flattened <prefix>N.Key / <prefix>N.Value list.
func queryTagParams(p url.Values, prefix string, tags map[string]string) url.Values {
	for i, k := range slices.Sorted(maps.Keys(tags)) {
		n := prefix + strconv.Itoa(i+1) + "."
		p.Set(n+"Key", k)
		p.Set(n+"Value", tags[k])
	}
	return p
}

// xmlTags collects every <Key>/<Value> pair in an XML body.
func xmlTags(t *testing.T, body []byte) map[string]string {
	t.Helper()
	out := map[string]string{}
	dec := xml.NewDecoder(strings.NewReader(string(body)))
	var key, elem string
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return out
		}
		require.NoError(t, err, "decode %s", body)
		switch tok := tok.(type) {
		case xml.StartElement:
			elem = tok.Name.Local
			if elem == "Value" {
				out[key] = ""
			}
		case xml.CharData:
			switch elem {
			case "Key":
				key = string(tok)
			case "Value":
				out[key] = string(tok)
			}
		case xml.EndElement:
			elem = ""
		}
	}
}

func TestSQS_TagsRoundTrip(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	create, _ := json.Marshal(map[string]any{"QueueName": "tagged", "tags": tagsAtCreate})
	resp, body := sqsCall(t, srv, "CreateQueue", string(create))
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateQueue: %s", body)
	queueURL := srv.URL + "/000000000000/tagged"

	listed := func() map[string]string {
		resp, body := sqsCall(t, srv, "ListQueueTags", `{"QueueUrl":"`+queueURL+`"}`)
		require.Equal(t, http.StatusOK, resp.StatusCode, "ListQueueTags: %s", body)
		var out struct{ Tags map[string]string }
		require.NoError(t, json.Unmarshal(body, &out))
		return out.Tags
	}
	assert.Equal(t, tagsAtCreate, listed(), "tags at create")

	add, _ := json.Marshal(map[string]any{"QueueUrl": queueURL, "Tags": tagsAdded})
	resp, body = sqsCall(t, srv, "TagQueue", string(add))
	require.Equal(t, http.StatusOK, resp.StatusCode, "TagQueue: %s", body)
	assert.Equal(t, tagsAfterAdd(), listed(), "after TagQueue")

	resp, body = sqsCall(t, srv, "UntagQueue", `{"QueueUrl":"`+queueURL+`","TagKeys":["`+removedKey+`"]}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "UntagQueue: %s", body)
	assert.Equal(t, tagsAfterRemove(), listed(), "after UntagQueue")

	for _, op := range []string{"ListQueueTags", "TagQueue", "UntagQueue"} {
		resp, body = sqsCall(t, srv, op, `{"QueueUrl":"`+srv.URL+`/000000000000/missing","Tags":{"a":"b"},"TagKeys":["a"]}`)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, op)
		assert.Contains(t, string(body), "AWS.SimpleQueueService.NonExistentQueue", op)
	}
}

func TestIAM_TagsRoundTrip(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const policyDoc = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
	kinds := []struct {
		kind, create, get string
		params            url.Values
		id                string // the value tag calls name the entity by
		missing           string
	}{
		{"Role", "CreateRole", "GetRole", url.Values{"RoleName": {"tagged"}, "AssumeRolePolicyDocument": {policyDoc}}, "tagged", "nope"},
		{"User", "CreateUser", "GetUser", url.Values{"UserName": {"tagged"}}, "tagged", "nope"},
		{"Policy", "CreatePolicy", "GetPolicy", url.Values{"PolicyName": {"tagged"}, "PolicyDocument": {policyDoc}},
			"arn:aws:iam::000000000000:policy/tagged", "arn:aws:iam::000000000000:policy/nope"},
	}
	for _, k := range kinds {
		t.Run(k.kind, func(t *testing.T) {
			param := map[string]string{"Role": "RoleName", "User": "UserName", "Policy": "PolicyArn"}[k.kind]
			resp, body := iamCall(t, srv, k.create, queryTagParams(k.params, "Tags.member.", tagsAtCreate))
			require.Equal(t, http.StatusOK, resp.StatusCode, "%s: %s", k.create, body)
			assert.Equal(t, tagsAtCreate, xmlTags(t, body), "%s response", k.create)

			getParams := url.Values{param: {k.id}}
			if k.kind != "Policy" {
				getParams = maps.Clone(k.params)
			}
			listed := func() map[string]string {
				resp, body := iamCall(t, srv, "List"+k.kind+"Tags", url.Values{param: {k.id}})
				require.Equal(t, http.StatusOK, resp.StatusCode, "List%sTags: %s", k.kind, body)
				_, got := iamCall(t, srv, k.get, getParams)
				assert.Equal(t, xmlTags(t, body), xmlTags(t, got), "%s shows the listed tags", k.get)
				return xmlTags(t, body)
			}
			assert.Equal(t, tagsAtCreate, listed(), "tags at create")

			resp, body = iamCall(t, srv, "Tag"+k.kind, queryTagParams(url.Values{param: {k.id}}, "Tags.member.", tagsAdded))
			require.Equal(t, http.StatusOK, resp.StatusCode, "Tag%s: %s", k.kind, body)
			assert.Equal(t, tagsAfterAdd(), listed(), "after Tag%s", k.kind)

			resp, body = iamCall(t, srv, "Untag"+k.kind, url.Values{param: {k.id}, "TagKeys.member.1": {removedKey}})
			require.Equal(t, http.StatusOK, resp.StatusCode, "Untag%s: %s", k.kind, body)
			assert.Equal(t, tagsAfterRemove(), listed(), "after Untag%s", k.kind)

			for _, op := range []string{"List" + k.kind + "Tags", "Tag" + k.kind, "Untag" + k.kind} {
				resp, body = iamCall(t, srv, op, url.Values{param: {k.missing}, "Tags.member.1.Key": {"a"}, "TagKeys.member.1": {"a"}})
				assert.Equal(t, http.StatusNotFound, resp.StatusCode, op)
				assert.Contains(t, string(body), "<Code>NoSuchEntity</Code>", op)
			}
		})
	}
}

func TestRDS_TagsRoundTrip(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"
	_, _, subnetA, subnetB := eksSetupPrereqs(t, srv, region)
	arn := "arn:aws:rds:us-east-1:000000000000:"
	kinds := []struct {
		name, create string
		params       url.Values
		arn          string
		notFound     string
	}{
		{"subnet group", "CreateDBSubnetGroup", url.Values{"DBSubnetGroupName": {"tagged"}, "DBSubnetGroupDescription": {"d"},
			"SubnetIds.member.1": {subnetA}, "SubnetIds.member.2": {subnetB}}, arn + "subgrp:tagged", "DBSubnetGroupNotFoundFault"},
		{"parameter group", "CreateDBParameterGroup", url.Values{"DBParameterGroupName": {"tagged"}, "DBParameterGroupFamily": {"postgres15"}, "Description": {"d"}},
			arn + "pg:tagged", "DBParameterGroupNotFound"},
		{"instance", "CreateDBInstance", url.Values{"DBInstanceIdentifier": {"tagged"}, "Engine": {"postgres"}, "DBInstanceClass": {"db.t3.micro"}},
			arn + "db:tagged", "DBInstanceNotFound"},
	}
	for _, k := range kinds {
		t.Run(k.name, func(t *testing.T) {
			resp, body := rdsCall(t, srv, region, k.create, queryTagParams(k.params, "Tags.Tag.", tagsAtCreate))
			require.Equal(t, http.StatusOK, resp.StatusCode, "%s: %s", k.create, body)
			listed := func() map[string]string {
				resp, body := rdsCall(t, srv, region, "ListTagsForResource", url.Values{"ResourceName": {k.arn}})
				require.Equal(t, http.StatusOK, resp.StatusCode, "ListTagsForResource: %s", body)
				return xmlTags(t, body)
			}
			assert.Equal(t, tagsAtCreate, listed(), "tags at create")

			resp, body = rdsCall(t, srv, region, "AddTagsToResource", queryTagParams(url.Values{"ResourceName": {k.arn}}, "Tags.Tag.", tagsAdded))
			require.Equal(t, http.StatusOK, resp.StatusCode, "AddTagsToResource: %s", body)
			assert.Equal(t, tagsAfterAdd(), listed(), "after AddTagsToResource")

			resp, body = rdsCall(t, srv, region, "RemoveTagsFromResource", url.Values{"ResourceName": {k.arn}, "TagKeys.member.1": {removedKey}})
			require.Equal(t, http.StatusOK, resp.StatusCode, "RemoveTagsFromResource: %s", body)
			assert.Equal(t, tagsAfterRemove(), listed(), "after RemoveTagsFromResource")

			missing := strings.TrimSuffix(k.arn, "tagged") + "nope"
			for _, op := range []string{"ListTagsForResource", "AddTagsToResource", "RemoveTagsFromResource"} {
				resp, body = rdsCall(t, srv, region, op, url.Values{"ResourceName": {missing}, "Tags.Tag.1.Key": {"a"}, "TagKeys.member.1": {"a"}})
				assert.Equal(t, http.StatusNotFound, resp.StatusCode, op)
				assert.Contains(t, string(body), "<Code>"+k.notFound+"</Code>", op)
			}
		})
	}

	_, body := rdsCall(t, srv, region, "DescribeDBInstances", url.Values{"DBInstanceIdentifier": {"tagged"}})
	assert.Equal(t, tagsAfterRemove(), xmlTags(t, body), "DescribeDBInstances TagList")
}

func TestRoute53_TagsRoundTrip(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, body := r53Request(t, srv, http.MethodPost, "/route53/2013-04-01/hostedzone",
		`<CreateHostedZoneRequest><Name>tagged.com.</Name><CallerReference>r1</CallerReference></CreateHostedZoneRequest>`)
	zoneID := strings.TrimPrefix(extractEC2Tag(body, "Id"), "/hostedzone/")
	require.NotEmpty(t, zoneID, "CreateHostedZone: %s", body)
	path := "/route53/2013-04-01/tags/hostedzone/" + zoneID

	change := func(add map[string]string, remove ...string) {
		t.Helper()
		var b strings.Builder
		b.WriteString(`<ChangeTagsForResourceRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><AddTags>`)
		for _, k := range slices.Sorted(maps.Keys(add)) {
			b.WriteString("<Tag><Key>" + k + "</Key><Value>" + add[k] + "</Value></Tag>")
		}
		b.WriteString("</AddTags><RemoveTagKeys>")
		for _, k := range remove {
			b.WriteString("<Key>" + k + "</Key>")
		}
		b.WriteString("</RemoveTagKeys></ChangeTagsForResourceRequest>")
		resp, body := r53Request(t, srv, http.MethodPost, path, b.String())
		require.Equal(t, http.StatusOK, resp.StatusCode, "ChangeTagsForResource: %s", body)
	}
	listed := func() map[string]string {
		resp, body := r53Request(t, srv, http.MethodGet, path, "")
		require.Equal(t, http.StatusOK, resp.StatusCode, "ListTagsForResource: %s", body)
		return xmlTags(t, body)
	}

	change(tagsAtCreate)
	assert.Equal(t, tagsAtCreate, listed(), "tags at create")
	change(tagsAdded)
	assert.Equal(t, tagsAfterAdd(), listed(), "after adding")
	change(nil, removedKey)
	assert.Equal(t, tagsAfterRemove(), listed(), "after removing")

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		resp, body := r53Request(t, srv, method, "/route53/2013-04-01/tags/hostedzone/ZNOPE",
			`<ChangeTagsForResourceRequest><AddTags><Tag><Key>a</Key><Value>b</Value></Tag></AddTags></ChangeTagsForResourceRequest>`)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, method)
		assert.Contains(t, string(body), "<Code>NoSuchHostedZone</Code>", method)
	}
}

func TestDynamoDB_TagsRoundTrip(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"
	const arn = "arn:aws:dynamodb:us-east-1:000000000000:table/tagged"
	ddbTags := func(tags map[string]string) []map[string]string {
		out := []map[string]string{}
		for _, k := range slices.Sorted(maps.Keys(tags)) {
			out = append(out, map[string]string{"Key": k, "Value": tags[k]})
		}
		return out
	}
	create, _ := json.Marshal(map[string]any{
		"TableName":            "tagged",
		"AttributeDefinitions": []map[string]string{{"AttributeName": "id", "AttributeType": "S"}},
		"KeySchema":            []map[string]string{{"AttributeName": "id", "KeyType": "HASH"}},
		"Tags":                 ddbTags(tagsAtCreate),
	})
	resp, body := ddbCall(t, srv, region, "CreateTable", string(create))
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateTable: %s", body)

	listed := func() map[string]string {
		resp, body := ddbCall(t, srv, region, "ListTagsOfResource", `{"ResourceArn":"`+arn+`"}`)
		require.Equal(t, http.StatusOK, resp.StatusCode, "ListTagsOfResource: %s", body)
		var out struct{ Tags []struct{ Key, Value string } }
		require.NoError(t, json.Unmarshal(body, &out))
		m := map[string]string{}
		for _, tag := range out.Tags {
			m[tag.Key] = tag.Value
		}
		return m
	}
	assert.Equal(t, tagsAtCreate, listed(), "tags at create")

	add, _ := json.Marshal(map[string]any{"ResourceArn": arn, "Tags": ddbTags(tagsAdded)})
	resp, body = ddbCall(t, srv, region, "TagResource", string(add))
	require.Equal(t, http.StatusOK, resp.StatusCode, "TagResource: %s", body)
	assert.Equal(t, tagsAfterAdd(), listed(), "after TagResource")

	resp, body = ddbCall(t, srv, region, "UntagResource", `{"ResourceArn":"`+arn+`","TagKeys":["`+removedKey+`"]}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "UntagResource: %s", body)
	assert.Equal(t, tagsAfterRemove(), listed(), "after UntagResource")

	for _, op := range []string{"ListTagsOfResource", "TagResource", "UntagResource"} {
		resp, body = ddbCall(t, srv, region, op, `{"ResourceArn":"`+arn+`x","Tags":[{"Key":"a","Value":"b"}],"TagKeys":["a"]}`)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, op)
		assert.Contains(t, string(body), `"__type":"ResourceNotFoundException"`, op)
	}
}

func TestEKS_TagsRoundTrip(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"
	const arn = "arn:aws:eks:us-east-1:000000000000:cluster/tagged"
	tagsPath := "/eks/region/" + region + "/tags/" + url.PathEscape(arn)
	clusterRole, _, sa, sb := eksSetupPrereqs(t, srv, region)
	create, _ := json.Marshal(map[string]any{
		"name": "tagged", "roleArn": clusterRole,
		"resourcesVpcConfig": map[string]any{"subnetIds": []string{sa, sb}},
		"tags":               tagsAtCreate,
	})
	resp, body := eksRequest(t, srv, http.MethodPost, "/eks/region/"+region+"/clusters", string(create))
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateCluster: %s", body)

	listed := func() map[string]string {
		resp, body := eksRequest(t, srv, http.MethodGet, "/eks/region/"+region+"/clusters/tagged", "")
		require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeCluster: %s", body)
		var described struct {
			Cluster struct{ Tags map[string]string }
		}
		require.NoError(t, json.Unmarshal(body, &described))
		resp, body = eksRequest(t, srv, http.MethodGet, tagsPath, "")
		require.Equal(t, http.StatusOK, resp.StatusCode, "ListTagsForResource: %s", body)
		var list struct{ Tags map[string]string }
		require.NoError(t, json.Unmarshal(body, &list))
		assert.Equal(t, described.Cluster.Tags, list.Tags, "ListTagsForResource agrees with DescribeCluster")
		return described.Cluster.Tags
	}
	assert.Equal(t, tagsAtCreate, listed(), "tags at create")

	add, _ := json.Marshal(map[string]any{"tags": tagsAdded})
	resp, body = eksRequest(t, srv, http.MethodPost, tagsPath, string(add))
	require.Equal(t, http.StatusOK, resp.StatusCode, "TagResource: %s", body)
	assert.Equal(t, tagsAfterAdd(), listed(), "after TagResource")

	resp, body = eksRequest(t, srv, http.MethodDelete, tagsPath+"?tagKeys="+url.QueryEscape(removedKey), "")
	require.Equal(t, http.StatusOK, resp.StatusCode, "UntagResource: %s", body)
	assert.Equal(t, tagsAfterRemove(), listed(), "after UntagResource")

	missing := "/eks/region/" + region + "/tags/" + url.PathEscape(arn+"x")
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		resp, body = eksRequest(t, srv, method, missing+"?tagKeys=a", `{"tags":{"a":"b"}}`)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, method)
		assert.Contains(t, string(body), `"__type":"NotFoundException"`, method)
	}
}

// TestTagsGoWithTheirResource: a queue deleted and recreated under the
// same name starts untagged, rather than inheriting stale tags that
// would show up as drift.
func TestTagsGoWithTheirResource(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	queueURL := srv.URL + "/000000000000/again"
	sqsCall(t, srv, "CreateQueue", `{"QueueName":"again","tags":{"a":"1"}}`)
	sqsCall(t, srv, "DeleteQueue", `{"QueueUrl":"`+queueURL+`"}`)
	sqsCall(t, srv, "CreateQueue", `{"QueueName":"again"}`)
	_, body := sqsCall(t, srv, "ListQueueTags", `{"QueueUrl":"`+queueURL+`"}`)
	assert.JSONEq(t, `{"Tags":{}}`, string(body))
}
