package handlers_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func r53Request(t *testing.T, srv *httptest.Server, method, path, body string) (*http.Response, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, srv.URL+path, rd)
	if body != "" {
		req.Header.Set("Content-Type", "application/xml")
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

func TestRoute53_HostedZoneLifecycle(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	// Create.
	resp, body := r53Request(t, srv, http.MethodPost, "/route53/2013-04-01/hostedzone",
		`<CreateHostedZoneRequest><Name>example.com.</Name><CallerReference>r1</CallerReference></CreateHostedZoneRequest>`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateHostedZone: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), `<Name>example.com.</Name>`) {
		t.Errorf("CreateHostedZone body: %s", body)
	}
	// Extract zone id from "/hostedzone/Z..."
	idStart := strings.Index(string(body), "<Id>/hostedzone/") + len("<Id>/hostedzone/")
	idEnd := strings.Index(string(body)[idStart:], "</Id>") + idStart
	zoneID := string(body)[idStart:idEnd]

	// List.
	_, body = r53Request(t, srv, http.MethodGet, "/route53/2013-04-01/hostedzone", "")
	if !strings.Contains(string(body), zoneID) {
		t.Errorf("ListHostedZones: %s", body)
	}

	// Get.
	resp, body = r53Request(t, srv, http.MethodGet, "/route53/2013-04-01/hostedzone/"+zoneID, "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GetHostedZone: %d %s", resp.StatusCode, body)
	}

	// Delete (empty zone after default NS+SOA — non-empty refusal won't fire).
	resp, _ = r53Request(t, srv, http.MethodDelete, "/route53/2013-04-01/hostedzone/"+zoneID, "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("DeleteHostedZone: %d", resp.StatusCode)
	}
}

func TestRoute53_ChangeBatchTransactional(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	// Setup zone.
	_, body := r53Request(t, srv, http.MethodPost, "/route53/2013-04-01/hostedzone",
		`<CreateHostedZoneRequest><Name>example.com.</Name><CallerReference>x</CallerReference></CreateHostedZoneRequest>`)
	idStart := strings.Index(string(body), "<Id>/hostedzone/") + len("<Id>/hostedzone/")
	idEnd := strings.Index(string(body)[idStart:], "</Id>") + idStart
	zoneID := string(body)[idStart:idEnd]

	// Apex CNAME forbidden — transactional batch rejects.
	apex := `<ChangeResourceRecordSetsRequest><ChangeBatch><Changes>
		<Change><Action>CREATE</Action><ResourceRecordSet>
			<Name>example.com.</Name><Type>CNAME</Type><TTL>300</TTL>
			<ResourceRecords><ResourceRecord><Value>target.example.net</Value></ResourceRecord></ResourceRecords>
		</ResourceRecordSet></Change>
	</Changes></ChangeBatch></ChangeResourceRecordSetsRequest>`
	resp, _ := r53Request(t, srv, http.MethodPost, "/route53/2013-04-01/hostedzone/"+zoneID+"/rrset/", apex)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("apex CNAME: got %d, want 409", resp.StatusCode)
	}

	// CNAME on a child works.
	good := `<ChangeResourceRecordSetsRequest><ChangeBatch><Changes>
		<Change><Action>CREATE</Action><ResourceRecordSet>
			<Name>www.example.com.</Name><Type>CNAME</Type><TTL>300</TTL>
			<ResourceRecords><ResourceRecord><Value>example.com.</Value></ResourceRecord></ResourceRecords>
		</ResourceRecordSet></Change>
	</Changes></ChangeBatch></ChangeResourceRecordSetsRequest>`
	resp, body = r53Request(t, srv, http.MethodPost, "/route53/2013-04-01/hostedzone/"+zoneID+"/rrset/", good)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("child CNAME: %d %s", resp.StatusCode, body)
	}

	// List.
	_, body = r53Request(t, srv, http.MethodGet, "/route53/2013-04-01/hostedzone/"+zoneID+"/rrset", "")
	if !strings.Contains(string(body), "www.example.com.") {
		t.Errorf("ListResourceRecordSets missing www: %s", body)
	}

	// Non-empty zone delete refused.
	resp, _ = r53Request(t, srv, http.MethodDelete, "/route53/2013-04-01/hostedzone/"+zoneID, "")
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("non-empty zone delete: got %d, want 409", resp.StatusCode)
	}
}

// TestRoute53_AliasTargetRoundTrip pins Codex pass 2 BLOCKING #1:
// AliasTarget must persist on write and re-emit on read.
func TestRoute53_AliasTargetRoundTrip(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, body := r53Request(t, srv, http.MethodPost, "/route53/2013-04-01/hostedzone",
		`<CreateHostedZoneRequest><Name>example.com.</Name><CallerReference>a</CallerReference></CreateHostedZoneRequest>`)
	idStart := strings.Index(string(body), "<Id>/hostedzone/") + len("<Id>/hostedzone/")
	idEnd := strings.Index(string(body)[idStart:], "</Id>") + idStart
	zoneID := string(body)[idStart:idEnd]

	// Apex ALIAS — type=A with AliasTarget instead of ResourceRecords.
	alias := `<ChangeResourceRecordSetsRequest><ChangeBatch><Changes>
		<Change><Action>CREATE</Action><ResourceRecordSet>
			<Name>example.com.</Name><Type>A</Type>
			<AliasTarget>
				<HostedZoneId>Z2FDTNDATAQYW2</HostedZoneId>
				<DNSName>d111111abcdef8.cloudfront.net.</DNSName>
				<EvaluateTargetHealth>false</EvaluateTargetHealth>
			</AliasTarget>
		</ResourceRecordSet></Change>
	</Changes></ChangeBatch></ChangeResourceRecordSetsRequest>`
	resp, _ := r53Request(t, srv, http.MethodPost, "/route53/2013-04-01/hostedzone/"+zoneID+"/rrset/", alias)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("apex ALIAS: %d", resp.StatusCode)
	}

	// List must round-trip the AliasTarget.
	_, body = r53Request(t, srv, http.MethodGet, "/route53/2013-04-01/hostedzone/"+zoneID+"/rrset", "")
	if !strings.Contains(string(body), "d111111abcdef8.cloudfront.net.") {
		t.Errorf("AliasTarget DNSName not round-tripped: %s", body)
	}
	if !strings.Contains(string(body), "Z2FDTNDATAQYW2") {
		t.Errorf("AliasTarget HostedZoneId not round-tripped: %s", body)
	}
}

func TestRoute53_BatchAtomicityOnInvalidChange(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	_, body := r53Request(t, srv, http.MethodPost, "/route53/2013-04-01/hostedzone",
		`<CreateHostedZoneRequest><Name>example.com.</Name><CallerReference>y</CallerReference></CreateHostedZoneRequest>`)
	idStart := strings.Index(string(body), "<Id>/hostedzone/") + len("<Id>/hostedzone/")
	idEnd := strings.Index(string(body)[idStart:], "</Id>") + idStart
	zoneID := string(body)[idStart:idEnd]

	// Mixed batch: one good, one invalid (apex CNAME). The whole batch
	// must reject — neither change should apply (transactional contract).
	mixed := `<ChangeResourceRecordSetsRequest><ChangeBatch><Changes>
		<Change><Action>CREATE</Action><ResourceRecordSet>
			<Name>www.example.com.</Name><Type>A</Type><TTL>300</TTL>
			<ResourceRecords><ResourceRecord><Value>192.0.2.1</Value></ResourceRecord></ResourceRecords>
		</ResourceRecordSet></Change>
		<Change><Action>CREATE</Action><ResourceRecordSet>
			<Name>example.com.</Name><Type>CNAME</Type><TTL>300</TTL>
			<ResourceRecords><ResourceRecord><Value>bad</Value></ResourceRecord></ResourceRecords>
		</ResourceRecordSet></Change>
	</Changes></ChangeBatch></ChangeResourceRecordSetsRequest>`
	resp, _ := r53Request(t, srv, http.MethodPost, "/route53/2013-04-01/hostedzone/"+zoneID+"/rrset/", mixed)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("mixed batch: %d, want 409", resp.StatusCode)
	}
	// Verify NEITHER change applied.
	_, body = r53Request(t, srv, http.MethodGet, "/route53/2013-04-01/hostedzone/"+zoneID+"/rrset", "")
	if strings.Contains(string(body), "www.example.com.") {
		t.Errorf("transactional violation: www record applied despite batch failure: %s", body)
	}
}

// TestRoute53_ListSortsLexicographically pins S96's fix for the
// aws-route53 sweep-3 flake. terraform-provider-aws's per-record Read
// sends `?name=<n>&type=<t>&maxitems=1` expecting the FIRST record
// at-or-after that key in lexicographic order. Without sorting,
// fakeaws walked storage order — the auto-inserted NS record could
// sit before the user's A record, so MaxItems=1 returned the NS
// record and the provider's A-record Read surfaced as "empty result".
//
// After fix: records are sorted by (normalised name, type,
// setIdentifier) before filtering. NS sorts AFTER A alphabetically,
// so the A record wins.
func TestContract_route53_records_sorted_lexicographically(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	_, body := r53Request(t, srv, http.MethodPost, "/route53/2013-04-01/hostedzone",
		`<CreateHostedZoneRequest><Name>test.example.invalid.</Name><CallerReference>x</CallerReference></CreateHostedZoneRequest>`)
	idStart := strings.Index(string(body), "<Id>/hostedzone/") + len("<Id>/hostedzone/")
	idEnd := strings.Index(string(body)[idStart:], "</Id>") + idStart
	zoneID := string(body)[idStart:idEnd]

	// Zone creation auto-inserts NS records. Now add an apex A record
	// — this is the shape the aws-route53 scenario produces.
	apex := `<ChangeResourceRecordSetsRequest><ChangeBatch><Changes>
		<Change><Action>CREATE</Action><ResourceRecordSet>
			<Name>test.example.invalid.</Name><Type>A</Type><TTL>300</TTL>
			<ResourceRecords><ResourceRecord><Value>192.0.2.1</Value></ResourceRecord></ResourceRecords>
		</ResourceRecordSet></Change>
	</Changes></ChangeBatch></ChangeResourceRecordSetsRequest>`
	r53Request(t, srv, http.MethodPost, "/route53/2013-04-01/hostedzone/"+zoneID+"/rrset/", apex)

	// terraform-provider-aws per-record Read shape.
	_, body = r53Request(t, srv, http.MethodGet,
		"/route53/2013-04-01/hostedzone/"+zoneID+"/rrset?name=test.example.invalid&type=A&maxitems=1", "")
	if !strings.Contains(string(body), `<Type>A</Type>`) {
		t.Errorf("expected A record first (lex order), got: %s", body)
	}
	if strings.Contains(string(body), `<Type>NS</Type>`) {
		t.Errorf("expected ONLY A record (maxitems=1), NS record leaked: %s", body)
	}
}

// TestRoute53_ChangeTagsForResourceAccepts pins S96's second fix.
// terraform-provider-aws's aws_route53_zone with `tags = {...}` POSTs
// to /tags/<type>/<id>. Without the handler, fakeaws 404'd and the
// LLM oscillated between adding + removing tags. Accept-and-ignore
// is fine — we don't model zone tag storage, so the existing
// ListTagsForResource (empty) round-trips correctly.
func TestRoute53_ChangeTagsForResourceAccepts(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	_, body := r53Request(t, srv, http.MethodPost, "/route53/2013-04-01/hostedzone",
		`<CreateHostedZoneRequest><Name>example.com.</Name><CallerReference>x</CallerReference></CreateHostedZoneRequest>`)
	idStart := strings.Index(string(body), "<Id>/hostedzone/") + len("<Id>/hostedzone/")
	idEnd := strings.Index(string(body)[idStart:], "</Id>") + idStart
	zoneID := string(body)[idStart:idEnd]

	resp, _ := r53Request(t, srv, http.MethodPost, "/route53/2013-04-01/tags/hostedzone/"+zoneID,
		`<ChangeTagsForResourceRequest><AddTags><Tag><Key>Owner</Key><Value>platform</Value></Tag></AddTags></ChangeTagsForResourceRequest>`)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("ChangeTagsForResource: %d, want 200", resp.StatusCode)
	}

	// ListTagsForResource still returns empty (we don't model storage).
	resp, body = r53Request(t, srv, http.MethodGet, "/route53/2013-04-01/tags/hostedzone/"+zoneID, "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("ListTagsForResource after change: %d, want 200", resp.StatusCode)
	}
	_ = body
}
