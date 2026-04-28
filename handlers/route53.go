package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
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
		r.Post("/hostedzone/{id}/rrset/", app.r53ChangeResourceRecordSets)
		r.Get("/hostedzone/{id}/rrset", app.r53ListResourceRecordSets)
		r.Get("/change/{id}", app.r53GetChange)
	})
}

// ----- Hosted Zone -----

type r53CreateHostedZoneRequest struct {
	XMLName          xml.Name              `xml:"CreateHostedZoneRequest"`
	Name             string                `xml:"Name"`
	CallerReference  string                `xml:"CallerReference"`
	HostedZoneConfig *r53HostedZoneConfig  `xml:"HostedZoneConfig,omitempty"`
}

type r53HostedZoneConfig struct {
	Comment     string `xml:"Comment,omitempty"`
	PrivateZone bool   `xml:"PrivateZone"`
}

type r53HostedZoneXML struct {
	Id              string `xml:"Id"`
	Name            string `xml:"Name"`
	CallerReference string `xml:"CallerReference,omitempty"`
	Config          *r53HostedZoneConfig `xml:"Config,omitempty"`
	ResourceRecordSetCount int `xml:"ResourceRecordSetCount,omitempty"`
}

type r53CreateHostedZoneResponse struct {
	XMLName    xml.Name         `xml:"CreateHostedZoneResponse"`
	HostedZone r53HostedZoneXML `xml:"HostedZone"`
	ChangeInfo r53ChangeInfoXML `xml:"ChangeInfo"`
}

type r53ChangeInfoXML struct {
	Id          string `xml:"Id"`
	Status      string `xml:"Status"`
	SubmittedAt string `xml:"SubmittedAt"`
}

type r53GetHostedZoneResponse struct {
	XMLName    xml.Name         `xml:"GetHostedZoneResponse"`
	HostedZone r53HostedZoneXML `xml:"HostedZone"`
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
		HostedZone: r53ZoneToXML(z),
		ChangeInfo: r53ChangeInfoXML{Id: "/change/" + change.ID, Status: change.Status, SubmittedAt: change.SubmittedAt},
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
	awsproto.WriteXMLResponse(w, http.StatusOK, &r53GetHostedZoneResponse{HostedZone: r53ZoneToXML(z)})
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
	XMLName     xml.Name        `xml:"ChangeResourceRecordSetsRequest"`
	ChangeBatch r53ChangeBatch  `xml:"ChangeBatch"`
}

type r53ChangeBatch struct {
	Changes []r53Change `xml:"Changes>Change"`
}

type r53Change struct {
	Action            string             `xml:"Action"` // CREATE | UPSERT | DELETE
	ResourceRecordSet r53RecordSetXML    `xml:"ResourceRecordSet"`
}

type r53RecordSetXML struct {
	Name             string             `xml:"Name"`
	Type             string             `xml:"Type"`
	TTL              int                `xml:"TTL,omitempty"`
	ResourceRecords  []r53ResourceRecord `xml:"ResourceRecords>ResourceRecord,omitempty"`
	SetIdentifier    string             `xml:"SetIdentifier,omitempty"`
	AliasTarget      *r53AliasTarget    `xml:"AliasTarget,omitempty"`
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
		switch ch.Action {
		case "CREATE", "UPSERT":
			if err := app.repo.PutRecordSet(account, &repository.Route53RecordSet{
				ZoneID: zoneID, Name: rs.Name, Type: rs.Type, TTL: rs.TTL,
				Records: records, SetIdentifier: rs.SetIdentifier,
			}); err != nil {
				awsproto.WriteAWSError(w, awsproto.ShapeXML, err)
				return
			}
		case "DELETE":
			// DELETE is idempotent at AWS; ignore not-found.
			_ = app.repo.DeleteRecordSet(account, zoneID, rs.Name, rs.Type, rs.SetIdentifier)
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
	type listResult struct {
		XMLName            xml.Name          `xml:"ListResourceRecordSetsResponse"`
		ResourceRecordSets []r53RecordSetXML `xml:"ResourceRecordSets>ResourceRecordSet"`
		IsTruncated        bool              `xml:"IsTruncated"`
	}
	out := listResult{}
	for _, rs := range rsets {
		x := r53RecordSetXML{Name: rs.Name, Type: rs.Type, TTL: rs.TTL, SetIdentifier: rs.SetIdentifier}
		for _, v := range rs.Records {
			x.ResourceRecords = append(x.ResourceRecords, r53ResourceRecord{Value: v})
		}
		out.ResourceRecordSets = append(out.ResourceRecordSets, x)
	}
	awsproto.WriteXMLResponse(w, http.StatusOK, &out)
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

func (app *Application) gatherRoute53StateReal() map[string]any {
	const account = awsproto.FakeAccountID
	out := map[string]any{
		"hosted_zones": []any{},
	}
	zones, _ := app.repo.ListHostedZones(account)
	zOut := make([]map[string]any, 0, len(zones))
	for _, z := range zones {
		zOut = append(zOut, map[string]any{
			"id": z.ID, "name": z.Name, "comment": z.Comment, "private": z.Private,
			"arn": z.ARN,
		})
	}
	out["hosted_zones"] = zOut
	return out
}
