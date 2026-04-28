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
