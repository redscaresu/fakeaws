package repository

import (
	"errors"
	"testing"

	"github.com/redscaresu/fakeaws/models"
)

func TestSecretCRUD(t *testing.T) {
	r := setupRepo(t)
	s := &SecretsManagerSecret{
		Name: "db-creds", ARN: "arn:aws:secretsmanager:us-east-1:000000000000:secret:db-creds-AbCdEf",
		Description: "test", RecoveryWindowInDays: 30,
		Region: testRegion, CreatedAt: "t",
	}
	if err := r.CreateSecret(testAccount, s); err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	got, err := r.GetSecret(testAccount, testRegion, "db-creds")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if got.State != SecretStateActive {
		t.Errorf("state default: %q", got.State)
	}
}

func TestSecretStateMachine(t *testing.T) {
	r := setupRepo(t)
	r.CreateSecret(testAccount, &SecretsManagerSecret{
		Name: "x", ARN: "arn", RecoveryWindowInDays: 30,
		Region: testRegion, CreatedAt: "t",
	})

	// Active → schedule with window > 0 → PendingDeletion.
	s, err := r.ScheduleSecretDeletion(testAccount, testRegion, "x", 30, "now")
	if err != nil {
		t.Fatalf("ScheduleSecretDeletion: %v", err)
	}
	if s.State != SecretStatePendingDeletion {
		t.Errorf("state: %q want PendingDeletion", s.State)
	}

	// PendingDeletion → restore → Active.
	s, err = r.RestoreSecret(testAccount, testRegion, "x")
	if err != nil {
		t.Fatalf("RestoreSecret: %v", err)
	}
	if s.State != SecretStateActive {
		t.Errorf("after restore: %q", s.State)
	}

	// Schedule with window=0 → immediately Destroyed.
	s, _ = r.ScheduleSecretDeletion(testAccount, testRegion, "x", 0, "now")
	if s.State != SecretStateDestroyed {
		t.Errorf("window=0 destination: %q want Destroyed", s.State)
	}

	// Restore on Destroyed → 409 (terminal-state refusal).
	if _, err := r.RestoreSecret(testAccount, testRegion, "x"); !errors.Is(err, models.ErrConflict) {
		t.Errorf("RestoreSecret on Destroyed: want ErrConflict, got %v", err)
	}

	// Re-schedule on Destroyed → 409.
	if _, err := r.ScheduleSecretDeletion(testAccount, testRegion, "x", 0, "now"); !errors.Is(err, models.ErrConflict) {
		t.Errorf("ScheduleSecretDeletion on Destroyed: want ErrConflict, got %v", err)
	}
}

func TestSecretVersions_AWSCURRENT_AWSPREVIOUS(t *testing.T) {
	r := setupRepo(t)
	r.CreateSecret(testAccount, &SecretsManagerSecret{Name: "x", ARN: "arn", RecoveryWindowInDays: 30, Region: testRegion, CreatedAt: "t"})

	r.PutSecretValue(testAccount, testRegion, "x", &SecretsManagerVersion{
		VersionID: "v1", SecretString: "secret1", CreatedAt: "t1",
	})
	r.PutSecretValue(testAccount, testRegion, "x", &SecretsManagerVersion{
		VersionID: "v2", SecretString: "secret2", CreatedAt: "t2",
	})

	// AWSCURRENT is v2.
	got, err := r.GetSecretValue(testAccount, testRegion, "x", "AWSCURRENT", "")
	if err != nil {
		t.Fatalf("GetSecretValue AWSCURRENT: %v", err)
	}
	if got.VersionID != "v2" || got.SecretString != "secret2" {
		t.Errorf("AWSCURRENT: %#v", got)
	}

	// AWSPREVIOUS is v1.
	got, err = r.GetSecretValue(testAccount, testRegion, "x", "AWSPREVIOUS", "")
	if err != nil {
		t.Fatalf("GetSecretValue AWSPREVIOUS: %v", err)
	}
	if got.VersionID != "v1" {
		t.Errorf("AWSPREVIOUS: %s want v1", got.VersionID)
	}
}

func TestSecretVersions_DefaultStageIsAWSCURRENT(t *testing.T) {
	r := setupRepo(t)
	r.CreateSecret(testAccount, &SecretsManagerSecret{Name: "x", ARN: "arn", RecoveryWindowInDays: 30, Region: testRegion, CreatedAt: "t"})
	r.PutSecretValue(testAccount, testRegion, "x", &SecretsManagerVersion{VersionID: "v1", SecretString: "s", CreatedAt: "t"})

	// No VersionStage / VersionID → defaults to AWSCURRENT.
	got, _ := r.GetSecretValue(testAccount, testRegion, "x", "", "")
	if got.VersionID != "v1" {
		t.Errorf("default stage: %s", got.VersionID)
	}
}
