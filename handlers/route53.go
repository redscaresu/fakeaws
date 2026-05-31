package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/redscaresu/fakeaws/handlers/awsproto"
	"github.com/redscaresu/fakeaws/models"
	"github.com/redscaresu/fakeaws/repository"
)

// Route53 handlers. Per fakeaws/PLAN.md § "Phase 5 — DNS + secrets":
// Route53 is global (no region in ARN) and speaks XML REST. Endpoint
// convention mirrors AWS:
//
//   POST   /route53/2013-04-01/hostedzone          CreateHostedZone
//   GET    /route53/2013-04-01/hostedzone          ListHostedZones
//   GET    /route53/2013-04-01/hostedzone/{id}     GetHostedZone
//   DELETE /route53/2013-04-01/hostedzone/{id}     DeleteHostedZone
//   POST   /route53/2013-04-01/hostedzone/{id}/rrset/  ChangeResourceRecordSets (transactional batch)
//   GET    /route53/2013-04-01/hostedzone/{id}/rrset   ListResourceRecordSets
//   GET    /route53/2013-04-01/change/{id}        GetChange
//
// ChangeResourceRecordSets is TRANSACTIONAL: all changes in the batch
// must validate before any apply. Apex-CNAME rejection (S47-T0
// pitfall) fires here.

func (app *Application) registerRoute53Routes(r chi.Router) {
	r.Route("/route53/2013-04-01", func(r chi.Router) {
		r.Get("/hostedzone", app.r53ListHostedZones)
		r.Post("/hostedzone", app.r53CreateHostedZone)
		r.Get("/hostedzone/{id}", app.r53GetHostedZone)
		r.Delete("/hostedzone/{id}", app.r53DeleteHostedZone)
		// The AWS SDK posts to `/rrset` (no trailing slash); chi treats
		// trailing/no-trailing as distinct routes so register both
		// to match the SDK in either shape.
		r.Post("/hostedzone/{id}/rrset", app.r53ChangeResourceRecordSets)
		r.Post("/hostedzone/{id}/rrset/", app.r53ChangeResourceRecordSets)
		r.Get("/hostedzone/{id}/rrset", app.r53ListResourceRecordSets)
		r.Get("/hostedzone/{id}/rrset/", app.r53ListResourceRecordSets)
		r.Get("/change/{id}", app.r53GetChange)
		// terraform-provider-aws's aws_route53_zone read path calls
		// ListTagsForResource on every refresh — we don't model tag
		// storage on hosted zones (yet), so return an empty tag set
		// which is the correct "no tags here" answer real AWS gives.
		r.Get("/tags/{resourceType}/{resourceID}", app.r53ListTagsForResource)
		// terraform-provider-aws's aws_route53_zone read path calls
		// GetDNSSEC after refresh. We don't model DNSSEC; return the
		// AWS "NOT_SIGNING" default so the provider sees a valid
		// not-enabled answer instead of a 501.
		r.Get("/hostedzone/{id}/dnssec", app.r53GetDNSSEC)
	})
}

// ----- Hosted Zone -----

type r53CreateHostedZoneRequest struct {
	XMLName          xml.Name             `xml:"CreateHostedZoneRequest"`
	Name             string               `xml:"Name"`
	CallerReference  string               `xml:"CallerReference"`
	HostedZoneConfig *r53HostedZoneConfig `xml:"HostedZoneConfig,omitempty"`
}

type r53HostedZoneConfig struct {
	Comment     string `xml:"Comment,omitempty"`
	PrivateZone bool   `xml:"PrivateZone"`
}

type r53HostedZoneXML struct {
	Id                     string               `xml:"Id"`
	Name                   string               `xml:"Name"`
	CallerReference        string               `xml:"CallerReference,omitempty"`
	Config                 *r53HostedZoneConfig `xml:"Config,omitempty"`
	ResourceRecordSetCount int                  `xml:"ResourceRecordSetCount,omitempty"`
}

type r53CreateHostedZoneResponse struct {
	XMLName       xml.Name            `xml:"CreateHostedZoneResponse"`
	HostedZone    r53HostedZoneXML    `xml:"HostedZone"`
	ChangeInfo    r53ChangeInfoXML    `xml:"ChangeInfo"`
	DelegationSet r53DelegationSetXML `xml:"DelegationSet"`
}

type r53ChangeInfoXML struct {
	Id          string `xml:"Id"`
	Status      string `xml:"Status"`
	SubmittedAt string `xml:"SubmittedAt"`
}

// r53DelegationSetXML is the NS-records block that real Route53
// returns on CreateHostedZone / GetHostedZone. terraform-provider-aws
// reads NameServers from this block to populate the zone's
// `name_servers` attribute; omitting the block makes the provider
// nil-deref on plan.(*GRPCProvider).ApplyResourceChange, which
// surfaces as the opaque "Plugin did not respond" error rather than
// a structured AWS-shaped failure.
type r53DelegationSetXML struct {
	NameServers []string `xml:"NameServers>NameServer"`
}

type r53GetHostedZoneResponse struct {
	XMLName       xml.Name            `xml:"GetHostedZoneResponse"`
	HostedZone    r53HostedZoneXML    `xml:"HostedZone"`
	DelegationSet r53DelegationSetXML `xml:"DelegationSet"`
}

// synthDelegationSet returns a deterministic NS-record set per zone.
// Real AWS returns 4 NS records under a `*.awsdns-*.{com,net,org,co.uk}`
// rotation; the provider just needs the count + recognisable shape.
func synthDelegationSet(zoneID string) r53DelegationSetXML {
	return r53DelegationSetXML{NameServers: []string{
		"ns-1." + zoneID + ".awsdns-01.com",
		"ns-2." + zoneID + ".awsdns-02.net",
		"ns-3." + zoneID + ".awsdns-03.org",
		"ns-4." + zoneID + ".awsdns-04.co.uk",
	}}
}

type r53ListHostedZonesResponse struct {
	XMLName     xml.Name           `xml:"ListHostedZonesResponse"`
	HostedZones []r53HostedZoneXML `xml:"HostedZones>HostedZone"`
	IsTruncated bool               `xml:"IsTruncated"`
}

func r53ZoneToXML(z *repository.Route53HostedZone) r53HostedZoneXML {
	out := r53HostedZoneXML{
		Id:   "/hostedzone/" + z.ID,
		Name: z.Name,
	}
	if z.Comment != "" || z.Private {
		out.Config = &r53HostedZoneConfig{Comment: z.Comment, PrivateZone: z.Private}
	}
	return out
}

func (app *Application) r53CreateHostedZone(w http.ResponseWriter, r *http.Request) {
	const account = awsproto.FakeAccountID
	body, err := io.ReadAll(r.Body)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeXML, fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}
	var in r53CreateHostedZoneRequest
	if err := xml.Unmarshal(body, &in); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeXML, fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}
	if in.Name == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeXML,
			fmt.Errorf("Name required: %w", models.ErrConflict))
		return
	}
	zoneID := "Z" + r53RandID()
	z := &repository.Route53HostedZone{
		ID: zoneID, Name: in.Name,
		ARN:       awsproto.BuildRoute53HostedZoneARN(zoneID),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if in.HostedZoneConfig != nil {
		z.Comment = in.HostedZoneConfig.Comment
		z.Private = in.HostedZoneConfig.PrivateZone
	}
	if err := app.repo.CreateHostedZone(account, z); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeXML, err)
		return
	}
	change := &repository.Route53Change{
		ID: "C" + r53RandID(), ZoneID: zoneID,
		Status: "INSYNC", SubmittedAt: z.CreatedAt,
	}
	app.repo.RecordChange(account, change)
	awsproto.WriteXMLResponse(w, http.StatusOK, &r53CreateHostedZoneResponse{
		HostedZone:    r53ZoneToXML(z),
		ChangeInfo:    r53ChangeInfoXML{Id: "/change/" + change.ID, Status: change.Status, SubmittedAt: change.SubmittedAt},
		DelegationSet: synthDelegationSet(zoneID),
	})
}

func (app *Application) r53GetHostedZone(w http.ResponseWriter, r *http.Request) {
	const account = awsproto.FakeAccountID
	zoneID := strings.TrimPrefix(chi.URLParam(r, "id"), "/hostedzone/")
	z, err := app.repo.GetHostedZone(account, zoneID)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeXML, err)
		return
	}
	awsproto.WriteXMLResponse(w, http.StatusOK, &r53GetHostedZoneResponse{
		HostedZone:    r53ZoneToXML(z),
		DelegationSet: synthDelegationSet(z.ID),
	})
}

func (app *Application) r53ListHostedZones(w http.ResponseWriter, r *http.Request) {
	const account = awsproto.FakeAccountID
	zones, err := app.repo.ListHostedZones(account)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeXML, err)
		return
	}
	out := r53ListHostedZonesResponse{}
	for _, z := range zones {
		out.HostedZones = append(out.HostedZones, r53ZoneToXML(z))
	}
	awsproto.WriteXMLResponse(w, http.StatusOK, &out)
}

func (app *Application) r53DeleteHostedZone(w http.ResponseWriter, r *http.Request) {
	const account = awsproto.FakeAccountID
	zoneID := strings.TrimPrefix(chi.URLParam(r, "id"), "/hostedzone/")
	if err := app.repo.DeleteHostedZone(account, zoneID); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeXML, err)
		return
	}
	change := &repository.Route53Change{
		ID: "C" + r53RandID(), ZoneID: zoneID,
		Status: "INSYNC", SubmittedAt: time.Now().UTC().Format(time.RFC3339),
	}
	app.repo.RecordChange(account, change)
	awsproto.WriteXMLResponse(w, http.StatusOK, &struct {
		XMLName    xml.Name         `xml:"DeleteHostedZoneResponse"`
		ChangeInfo r53ChangeInfoXML `xml:"ChangeInfo"`
	}{
		ChangeInfo: r53ChangeInfoXML{Id: "/change/" + change.ID, Status: "INSYNC", SubmittedAt: change.SubmittedAt},
	})
}

// ----- Record Set Changes (transactional) -----

type r53ChangeBatchRequest struct {
	XMLName     xml.Name       `xml:"ChangeResourceRecordSetsRequest"`
	ChangeBatch r53ChangeBatch `xml:"ChangeBatch"`
}

type r53ChangeBatch struct {
	Changes []r53Change `xml:"Changes>Change"`
}

type r53Change struct {
	Action            string          `xml:"Action"` // CREATE | UPSERT | DELETE
	ResourceRecordSet r53RecordSetXML `xml:"ResourceRecordSet"`
}

type r53RecordSetXML struct {
	Name            string              `xml:"Name"`
	Type            string              `xml:"Type"`
	TTL             int                 `xml:"TTL,omitempty"`
	ResourceRecords []r53ResourceRecord `xml:"ResourceRecords>ResourceRecord,omitempty"`
	SetIdentifier   string              `xml:"SetIdentifier,omitempty"`
	AliasTarget     *r53AliasTarget     `xml:"AliasTarget,omitempty"`
}

type r53ResourceRecord struct {
	Value string `xml:"Value"`
}

type r53AliasTarget struct {
	HostedZoneId         string `xml:"HostedZoneId"`
	DNSName              string `xml:"DNSName"`
	EvaluateTargetHealth bool   `xml:"EvaluateTargetHealth"`
}

func (app *Application) r53ChangeResourceRecordSets(w http.ResponseWriter, r *http.Request) {
	const account = awsproto.FakeAccountID
	zoneID := strings.TrimPrefix(chi.URLParam(r, "id"), "/hostedzone/")

	z, err := app.repo.GetHostedZone(account, zoneID)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeXML, err)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeXML, fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}
	var in r53ChangeBatchRequest
	if err := xml.Unmarshal(body, &in); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeXML, fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}

	// TRANSACTIONAL: validate ALL changes before applying any
	// (concepts.md "Standing patterns" item 7). Apex-CNAME rejection
	// fires here per S47-T0 pitfall.
	for i, ch := range in.ChangeBatch.Changes {
		switch ch.Action {
		case "CREATE", "UPSERT", "DELETE":
		default:
			awsproto.WriteAWSError(w, awsproto.ShapeXML,
				fmt.Errorf("InvalidChangeBatch: unknown Action %q at index %d: %w", ch.Action, i, models.ErrConflict))
			return
		}
		if ch.ResourceRecordSet.Type == "CNAME" && r53IsApex(ch.ResourceRecordSet.Name, z.Name) {
			awsproto.WriteAWSError(w, awsproto.ShapeXML,
				fmt.Errorf("InvalidChangeBatch: apex CNAME forbidden on %q (use ALIAS): %w",
					z.Name, models.ErrConflict))
			return
		}
		if ch.ResourceRecordSet.Name == "" || ch.ResourceRecordSet.Type == "" {
			awsproto.WriteAWSError(w, awsproto.ShapeXML,
				fmt.Errorf("InvalidChangeBatch: Name and Type required at index %d: %w", i, models.ErrConflict))
			return
		}
	}

	// Apply.
	for _, ch := range in.ChangeBatch.Changes {
		rs := ch.ResourceRecordSet
		records := make([]string, 0, len(rs.ResourceRecords))
		for _, rr := range rs.ResourceRecords {
			records = append(records, rr.Value)
		}
		// Real Route53 normalises every record name to a trailing-dot
		// FQDN on storage. terraform-provider-aws sometimes sends
		// "foo.example.com" and sometimes "foo.example.com." depending
		// on whether the user wrote the dot in HCL. Without normalising
		// at write time, a later DELETE that uses the opposite shape
		// silently misses the record → records linger → DeleteHostedZone
		// rejects with 409 because the zone "still has records."
		normalisedName := rs.Name
		if normalisedName != "" && !strings.HasSuffix(normalisedName, ".") {
			normalisedName += "."
		}
		switch ch.Action {
		case "CREATE", "UPSERT":
			alias := ""
			if rs.AliasTarget != nil {
				// Persist alias target as JSON; round-trip in
				// ListResourceRecordSets (Codex pass 2 BLOCKING #1).
				if b, err := json.Marshal(rs.AliasTarget); err == nil {
					alias = string(b)
				}
			}
			if err := app.repo.PutRecordSet(account, &repository.Route53RecordSet{
				ZoneID: zoneID, Name: normalisedName, Type: rs.Type, TTL: rs.TTL,
				Records: records, AliasTarget: alias, SetIdentifier: rs.SetIdentifier,
			}); err != nil {
				awsproto.WriteAWSError(w, awsproto.ShapeXML, err)
				return
			}
		case "DELETE":
			// DELETE is idempotent at AWS; ignore not-found.
			_ = app.repo.DeleteRecordSet(account, zoneID, normalisedName, rs.Type, rs.SetIdentifier)
		}
	}

	change := &repository.Route53Change{
		ID: "C" + r53RandID(), ZoneID: zoneID,
		Status: "INSYNC", SubmittedAt: time.Now().UTC().Format(time.RFC3339),
	}
	app.repo.RecordChange(account, change)
	awsproto.WriteXMLResponse(w, http.StatusOK, &struct {
		XMLName    xml.Name         `xml:"ChangeResourceRecordSetsResponse"`
		ChangeInfo r53ChangeInfoXML `xml:"ChangeInfo"`
	}{
		ChangeInfo: r53ChangeInfoXML{Id: "/change/" + change.ID, Status: "INSYNC", SubmittedAt: change.SubmittedAt},
	})
}

func (app *Application) r53ListResourceRecordSets(w http.ResponseWriter, r *http.Request) {
	const account = awsproto.FakeAccountID
	zoneID := strings.TrimPrefix(chi.URLParam(r, "id"), "/hostedzone/")
	rsets, err := app.repo.ListRecordSets(account, zoneID)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeXML, err)
		return
	}

	// Honour the AWS SDK's filter query params. terraform-provider-aws
	// reads individual records by calling with StartRecordName/Type +
	// MaxItems=1 and expecting the response to start at the matching
	// record. Returning the unfiltered insertion-order list collapses
	// into "empty result" at the provider boundary when MaxItems=1.
	q := r.URL.Query()
	startName := q.Get("name")
	startType := q.Get("type")
	startSetID := q.Get("identifier")
	maxItems := 0
	if v := q.Get("maxitems"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			maxItems = n
		}
	}

	// Filter to records at-or-after the start key. AWS Route53 orders
	// by name, then type, then SetIdentifier. We normalise the name
	// for comparison so a missing trailing dot on either side doesn't
	// cause a miss (provider sometimes sends without the dot).
	matches := rsets[:0:0]
	for _, rs := range rsets {
		if startName != "" {
			if r53NormaliseName(rs.Name) < r53NormaliseName(startName) {
				continue
			}
			if r53NormaliseName(rs.Name) == r53NormaliseName(startName) {
				if startType != "" && rs.Type < startType {
					continue
				}
				if startType != "" && rs.Type == startType && startSetID != "" && rs.SetIdentifier < startSetID {
					continue
				}
			}
		}
		matches = append(matches, rs)
	}
	if maxItems > 0 && len(matches) > maxItems {
		matches = matches[:maxItems]
	}

	type listResult struct {
		XMLName            xml.Name          `xml:"ListResourceRecordSetsResponse"`
		ResourceRecordSets []r53RecordSetXML `xml:"ResourceRecordSets>ResourceRecordSet"`
		IsTruncated        bool              `xml:"IsTruncated"`
	}
	out := listResult{}
	for _, rs := range matches {
		// Real Route53 always emits FQDN names with a trailing dot,
		// regardless of how the caller stored them. terraform-provider-
		// aws's read path matches `*rs.Name == startRecordName` exactly,
		// so a stored "foo.example.com" returned verbatim against an
		// SDK query for "foo.example.com." silently misses → "empty
		// result". Force the trailing dot on the wire.
		emittedName := rs.Name
		if !strings.HasSuffix(emittedName, ".") {
			emittedName += "."
		}
		x := r53RecordSetXML{Name: emittedName, Type: rs.Type, TTL: rs.TTL, SetIdentifier: rs.SetIdentifier}
		for _, v := range rs.Records {
			x.ResourceRecords = append(x.ResourceRecords, r53ResourceRecord{Value: v})
		}
		// Emit AliasTarget when stored — Codex pass 2 BLOCKING #1
		// fix. Apex ALIAS records round-trip through this path.
		if rs.AliasTarget != "" {
			var alias r53AliasTarget
			if err := json.Unmarshal([]byte(rs.AliasTarget), &alias); err == nil {
				x.AliasTarget = &alias
			}
		}
		out.ResourceRecordSets = append(out.ResourceRecordSets, x)
	}
	awsproto.WriteXMLResponse(w, http.StatusOK, &out)
}

// r53NormaliseName makes record-name comparison tolerant of trailing
// dots so the provider's filter matches storage regardless of whether
// the FQDN was passed with or without one.
func r53NormaliseName(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".")
}

func (app *Application) r53GetChange(w http.ResponseWriter, r *http.Request) {
	const account = awsproto.FakeAccountID
	id := strings.TrimPrefix(chi.URLParam(r, "id"), "/change/")
	c, err := app.repo.GetChange(account, id)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeXML, err)
		return
	}
	awsproto.WriteXMLResponse(w, http.StatusOK, &struct {
		XMLName    xml.Name         `xml:"GetChangeResponse"`
		ChangeInfo r53ChangeInfoXML `xml:"ChangeInfo"`
	}{
		ChangeInfo: r53ChangeInfoXML{Id: "/change/" + c.ID, Status: c.Status, SubmittedAt: c.SubmittedAt},
	})
}

// r53GetDNSSEC returns the AWS default "NOT_SIGNING" DNSSEC status.
// We don't model DNSSEC; terraform-provider-aws calls this on every
// aws_route53_zone refresh to read the current key-signing config,
// and the not-signing default matches real AWS when DNSSEC was
// never enabled.
func (app *Application) r53GetDNSSEC(w http.ResponseWriter, r *http.Request) {
	awsproto.WriteXMLResponse(w, http.StatusOK, &struct {
		XMLName xml.Name `xml:"GetDNSSECResponse"`
		Status  struct {
			ServeSignature string `xml:"ServeSignature"`
		} `xml:"Status"`
		KeySigningKeys []string `xml:"KeySigningKeys>KeySigningKey,omitempty"`
	}{
		Status: struct {
			ServeSignature string `xml:"ServeSignature"`
		}{ServeSignature: "NOT_SIGNING"},
	})
}

// r53ListTagsForResource returns an empty <Tags/> set for any
// resourceType + resourceID. fakeaws doesn't model Route53 tag
// storage (no scenario sets them); the empty set matches the real
// AWS response shape when nothing's been tagged. terraform-provider-aws
// calls this on every aws_route53_zone refresh.
func (app *Application) r53ListTagsForResource(w http.ResponseWriter, r *http.Request) {
	resourceType := chi.URLParam(r, "resourceType")
	resourceID := chi.URLParam(r, "resourceID")
	awsproto.WriteXMLResponse(w, http.StatusOK, &struct {
		XMLName        xml.Name `xml:"ListTagsForResourceResponse"`
		ResourceTagSet struct {
			ResourceType string   `xml:"ResourceType"`
			ResourceId   string   `xml:"ResourceId"`
			Tags         []string `xml:"Tags>Tag,omitempty"`
		} `xml:"ResourceTagSet"`
	}{
		ResourceTagSet: struct {
			ResourceType string   `xml:"ResourceType"`
			ResourceId   string   `xml:"ResourceId"`
			Tags         []string `xml:"Tags>Tag,omitempty"`
		}{
			ResourceType: resourceType,
			ResourceId:   resourceID,
		},
	})
}

// ----- helpers -----

func r53RandID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return strings.ToUpper(hex.EncodeToString(b)) + "FAKEAWS"
}

// r53IsApex returns true if recordName is the zone-root name.
// Both forms are handled (with and without trailing dot).
func r53IsApex(recordName, zoneName string) bool {
	r := strings.TrimSuffix(recordName, ".")
	z := strings.TrimSuffix(zoneName, ".")
	return r == z
}

// ----- /mock/state gather -----

// gatherRoute53StateReal emits the Route53 block of /mock/state.
//
// Codex pass 3 BLOCKING #2 fix: hosted zones now also surface their
// non-default record sets (was previously only emitting zones).
// NS+SOA defaults are excluded so the count reflects user records only.
func (app *Application) gatherRoute53StateReal() map[string]any {
	const account = awsproto.FakeAccountID
	out := map[string]any{
		"hosted_zones": []any{},
		"record_sets":  []any{},
	}
	zones, _ := app.repo.ListHostedZones(account)
	zOut := make([]map[string]any, 0, len(zones))
	rsOut := []map[string]any{}
	for _, z := range zones {
		zOut = append(zOut, map[string]any{
			"id": z.ID, "name": z.Name, "comment": z.Comment, "private": z.Private,
			"arn": z.ARN,
		})
		rsets, _ := app.repo.ListRecordSets(account, z.ID)
		for _, rs := range rsets {
			// Skip the auto-seeded NS + SOA at the apex — they
			// inflate user-record counts that scenarios assert against.
			if (rs.Type == "NS" || rs.Type == "SOA") && rs.Name == z.Name {
				continue
			}
			entry := map[string]any{
				"zone_id": rs.ZoneID, "name": rs.Name, "type": rs.Type,
				"ttl": rs.TTL, "records": rs.Records,
				"set_identifier": rs.SetIdentifier,
			}
			// Codex pass 13 BLOCKING #2: ALIAS records persist an
			// alias_target JSON blob that was previously dropped from
			// /mock/state, leaving them indistinguishable from
			// no-record entries. Decode and surface it so update/
			// identity checks can see the alias contract.
			if rs.AliasTarget != "" {
				var alias any
				if err := json.Unmarshal([]byte(rs.AliasTarget), &alias); err == nil {
					entry["alias_target"] = alias
				} else {
					entry["alias_target"] = rs.AliasTarget
				}
			}
			rsOut = append(rsOut, entry)
		}
	}
	out["hosted_zones"] = zOut
	out["record_sets"] = rsOut
	return out
}
