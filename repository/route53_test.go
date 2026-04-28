package repository

import (
	"errors"
	"testing"

	"github.com/redscaresu/fakeaws/models"
)

func TestRoute53HostedZoneCRUD(t *testing.T) {
	r := setupRepo(t)
	z := &Route53HostedZone{
		ID: "Zabcdef00", Name: "example.com.", Comment: "test", ARN: "arn:aws:route53:::hostedzone/Zabcdef00", CreatedAt: "t",
	}
	if err := r.CreateHostedZone(testAccount, z); err != nil {
		t.Fatalf("CreateHostedZone: %v", err)
	}

	got, err := r.GetHostedZone(testAccount, "Zabcdef00")
	if err != nil {
		t.Fatalf("GetHostedZone: %v", err)
	}
	if got.Name != "example.com." {
		t.Errorf("name: %q", got.Name)
	}

	// Default NS + SOA records seeded.
	rsets, _ := r.ListRecordSets(testAccount, "Zabcdef00")
	gotNS, gotSOA := false, false
	for _, rs := range rsets {
		if rs.Type == "NS" {
			gotNS = true
		}
		if rs.Type == "SOA" {
			gotSOA = true
		}
	}
	if !gotNS || !gotSOA {
		t.Errorf("default NS+SOA missing: NS=%v SOA=%v", gotNS, gotSOA)
	}
}

func TestRoute53HostedZoneDelete_RefuseIfNonEmpty(t *testing.T) {
	r := setupRepo(t)
	r.CreateHostedZone(testAccount, &Route53HostedZone{
		ID: "Zabc", Name: "example.com.", ARN: "arn", CreatedAt: "t",
	})
	// Add a user record.
	r.PutRecordSet(testAccount, &Route53RecordSet{
		ZoneID: "Zabc", Name: "www.example.com.", Type: "A", TTL: 300,
		Records: []string{"192.0.2.1"},
	})

	// Delete must reject.
	if err := r.DeleteHostedZone(testAccount, "Zabc"); !errors.Is(err, models.ErrConflict) {
		t.Errorf("non-empty zone delete: want ErrConflict, got %v", err)
	}

	// Delete the user record then retry.
	r.DeleteRecordSet(testAccount, "Zabc", "www.example.com.", "A", "")
	if err := r.DeleteHostedZone(testAccount, "Zabc"); err != nil {
		t.Errorf("empty zone delete: %v", err)
	}
}

func TestRoute53RecordSetUpsert(t *testing.T) {
	r := setupRepo(t)
	r.CreateHostedZone(testAccount, &Route53HostedZone{ID: "Zabc", Name: "example.com.", ARN: "arn", CreatedAt: "t"})

	rs := &Route53RecordSet{ZoneID: "Zabc", Name: "www.example.com.", Type: "A", TTL: 300, Records: []string{"192.0.2.1"}}
	r.PutRecordSet(testAccount, rs)

	// Upsert: same key, different records.
	rs2 := &Route53RecordSet{ZoneID: "Zabc", Name: "www.example.com.", Type: "A", TTL: 600, Records: []string{"192.0.2.2"}}
	r.PutRecordSet(testAccount, rs2)

	got, _ := r.GetRecordSet(testAccount, "Zabc", "www.example.com.", "A", "")
	if got.TTL != 600 || got.Records[0] != "192.0.2.2" {
		t.Errorf("upsert: %#v", got)
	}
}

func TestRoute53RecordSetMissingZone404(t *testing.T) {
	r := setupRepo(t)
	if err := r.PutRecordSet(testAccount, &Route53RecordSet{
		ZoneID: "Zmissing", Name: "x.example.com.", Type: "A", Records: []string{"1.2.3.4"},
	}); !errors.Is(err, models.ErrNotFound) {
		t.Errorf("PutRecordSet on missing zone: want ErrNotFound, got %v", err)
	}
}
