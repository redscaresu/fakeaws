package handlers_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/redscaresu/fakeaws/handlers"
	"github.com/redscaresu/fakeaws/handlers/awsproto"
	"github.com/redscaresu/fakeaws/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAdminMockState_ReturnsDocumentedShape pins the /mock/state
// contract topology_derive_aws will key off. The shape is documented
// inline in admin.go § stateSchemaVersion; this test asserts the keys
// the audit will look for.
func TestAdminMockState_ReturnsDocumentedShape(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	resp, body := doGet(t, srv, "/mock/state")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var state map[string]any
	require.NoError(t, json.Unmarshal(body, &state), "decode")
	for _, want := range []string{"schema_version", "operations", "audit", "iam", "s3"} {
		assert.Contains(t, state, want, "missing key %q in /mock/state response: %s", want, body)
	}
	v, _ := state["schema_version"].(float64)
	assert.Equal(t, float64(1), v, "schema_version: got %v want 1", state["schema_version"])
}

func TestAdminMockState_PerServiceFiltersToBlock(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	resp, body := doGet(t, srv, "/mock/state/iam")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var state map[string]any
	require.NoError(t, json.Unmarshal(body, &state), "decode")
	assert.Contains(t, state, "iam", "expected iam block in per-service response: %s", body)
	assert.NotContains(t, state, "s3", "per-service /state/iam should NOT include s3 block: %s", body)
}

func TestAdminMockState_UnknownServiceReturnsEmptyBlock(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	resp, body := doGet(t, srv, "/mock/state/notreal")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), `"notreal":{}`, "expected empty block for unknown service: %s", body)
}

// stateBreak makes one read behind a service's /mock/state block fail:
// seed rows (nil seeds nothing), then breakSQL drops the table or
// corrupts a stored value read sends back (JSON that does not decode, a
// column that does not scan). name defaults to read.
type stateBreak struct {
	read, service, breakSQL, name string
	seed                          func(t *testing.T, app *handlers.Application, srv *httptest.Server)
}

const stateRegion = "us-east-1"

// seedEKS writes an EKS cluster with one node group and one addon
// straight to the tables, skipping the role and subnet checks.
func seedEKS(t *testing.T, app *handlers.Application, _ *httptest.Server) {
	for _, q := range []string{
		`INSERT INTO eks_clusters (account_id, region, name, role_arn, arn, data, created_at)
		 VALUES (?, 'us-east-1', 'fc', 'r', 'a', '{"name":"fc","region":"us-east-1"}', 't')`,
		`INSERT INTO eks_node_groups (account_id, region, cluster_name, name, node_role_arn, arn, data, created_at)
		 VALUES (?, 'us-east-1', 'fc', 'ng', 'r', 'a', '{"cluster_name":"fc","name":"ng","scaling_config":"{}"}', 't')`,
		`INSERT INTO eks_addons (account_id, region, cluster_name, name, arn, data, created_at)
		 VALUES (?, 'us-east-1', 'fc', 'vpc-cni', 'a', '{"cluster_name":"fc","name":"vpc-cni"}', 't')`,
	} {
		_, err := app.Repository().DB().Exec(q, awsproto.FakeAccountID)
		require.NoError(t, err)
	}
}

func seedZone(t *testing.T, srv *httptest.Server, name string) string {
	zone := mustOK(t)(r53Request(t, srv, http.MethodPost, "/route53/2013-04-01/hostedzone",
		`<CreateHostedZoneRequest><Name>`+name+`.example.</Name><CallerReference>`+name+`</CallerReference></CreateHostedZoneRequest>`))
	return strings.TrimPrefix(xmlExtract(zone, "Id"), "/hostedzone/")
}

func seedVPC(t *testing.T, srv *httptest.Server) string {
	return extractEC2Tag(mustOK(t)(ec2Call(t, srv, stateRegion, "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})), "vpcId")
}

func seedSG(t *testing.T, srv *httptest.Server, vpcID, name string) string {
	return extractEC2Tag(mustOK(t)(ec2Call(t, srv, stateRegion, "CreateSecurityGroup", url.Values{
		"GroupName": {name}, "GroupDescription": {"d"}, "VpcId": {vpcID},
	})), "groupId")
}

func seedTable(t *testing.T, srv *httptest.Server, name string) {
	mustOK(t)(ddbCall(t, srv, stateRegion, "CreateTable", `{"TableName":"`+name+`",
		"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],
		"KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"BillingMode":"PAY_PER_REQUEST"}`))
}

func seedBucket(t *testing.T, srv *httptest.Server, name string) {
	mustOK(t)(s3Do(t, srv, http.MethodPut, "/s3/"+name+"/", "", ""))
	mustOK(t)(s3Do(t, srv, http.MethodPut, "/s3/"+name+"/?versioning",
		`<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`, "application/xml"))
}

// stateBreaks has a case for every read behind /mock/state;
// TestAdminMockState_UnreadableTableIs500 fails when a read has none.
var stateBreaks = []stateBreak{
	{read: "ListRoles", service: "iam", breakSQL: `DROP TABLE iam_roles`},
	{read: "ListPolicies", service: "iam", breakSQL: `DROP TABLE iam_policies`},
	{read: "ListInstanceProfiles", service: "iam", breakSQL: `DROP TABLE iam_instance_profiles`},
	{read: "ListUsers", service: "iam", breakSQL: `DROP TABLE iam_users`},
	{read: "ListAccessKeys", service: "iam", breakSQL: `DROP TABLE iam_access_keys`},

	{read: "ListBuckets", service: "s3", breakSQL: `DROP TABLE s3_buckets`},
	{read: "ListBucketConfigs", service: "s3", breakSQL: `DROP TABLE s3_bucket_configs`,
		seed: func(t *testing.T, _ *handlers.Application, srv *httptest.Server) { seedBucket(t, srv, "fc") }},
	{read: "ListBucketConfigs", name: "bucket config JSON", service: "s3", breakSQL: `UPDATE s3_bucket_configs SET data = 'not json'`,
		seed: func(t *testing.T, _ *handlers.Application, srv *httptest.Server) { seedBucket(t, srv, "fc") }},

	{read: "ListVPCs", service: "ec2", breakSQL: `DROP TABLE ec2_vpcs`},
	{read: "ListSubnets", service: "ec2", breakSQL: `DROP TABLE ec2_subnets`},
	{read: "ListNetworkInterfaces", service: "ec2", breakSQL: `DROP TABLE ec2_network_interfaces`},
	{read: "ListVolumes", service: "ec2", breakSQL: `DROP TABLE ec2_volumes`},
	{read: "ListInstances", service: "ec2", breakSQL: `DROP TABLE ec2_instances`},
	{read: "ListSecurityGroups", service: "ec2", breakSQL: `DROP TABLE ec2_security_groups`},
	{read: "ListSecurityGroupRules", service: "ec2", breakSQL: `DROP TABLE ec2_security_group_rules`,
		seed: func(t *testing.T, _ *handlers.Application, srv *httptest.Server) {
			seedSG(t, srv, seedVPC(t, srv), "fc")
		}},
	{read: "ListSecurityGroupRules", name: "security group rule row", service: "ec2", breakSQL: `UPDATE ec2_security_group_rules SET from_port = 'not a port'`,
		seed: func(t *testing.T, _ *handlers.Application, srv *httptest.Server) {
			sgID := seedSG(t, srv, seedVPC(t, srv), "fc")
			mustOK(t)(ec2Call(t, srv, stateRegion, "AuthorizeSecurityGroupIngress", url.Values{
				"GroupId": {sgID}, "IpPermissions.1.IpProtocol": {"tcp"}, "IpPermissions.1.FromPort": {"22"},
				"IpPermissions.1.ToPort": {"22"}, "IpPermissions.1.IpRanges.1.CidrIp": {"10.0.0.0/8"},
			}))
		}},
	{read: "ListKeyPairs", service: "ec2", breakSQL: `DROP TABLE ec2_key_pairs`},
	{read: "ListInternetGateways", service: "ec2", breakSQL: `DROP TABLE ec2_internet_gateways`},
	{read: "ListRouteTables", service: "ec2", breakSQL: `DROP TABLE ec2_route_tables`},
	{read: "ListRoutes", service: "ec2", breakSQL: `DROP TABLE ec2_routes`,
		seed: func(t *testing.T, _ *handlers.Application, srv *httptest.Server) {
			rtbID := extractEC2Tag(mustOK(t)(ec2Call(t, srv, stateRegion, "CreateRouteTable", url.Values{"VpcId": {seedVPC(t, srv)}})), "routeTableId")
			mustOK(t)(ec2Call(t, srv, stateRegion, "CreateRoute", url.Values{
				"RouteTableId": {rtbID}, "DestinationCidrBlock": {"0.0.0.0/0"}, "GatewayId": {"igw-stub"},
			}))
		}},
	{read: "ListRouteTableAssociations", service: "ec2", breakSQL: `DROP TABLE ec2_route_table_associations`},
	{read: "ListEIPs", service: "ec2", breakSQL: `UPDATE ec2_eips SET data = 'not json'`,
		seed: func(t *testing.T, _ *handlers.Application, srv *httptest.Server) {
			mustOK(t)(ec2Call(t, srv, stateRegion, "AllocateAddress", url.Values{"Domain": {"vpc"}}))
		}},

	{read: "ListDBInstances", service: "rds", breakSQL: `DROP TABLE rds_db_instances`},
	{read: "ListDBSubnetGroups", service: "rds", breakSQL: `DROP TABLE rds_db_subnet_groups`},
	{read: "ListDBParameterGroups", service: "rds", breakSQL: `DROP TABLE rds_db_parameter_groups`},
	{read: "ListDBClusterParameterGroups", service: "rds", breakSQL: `DROP TABLE rds_db_cluster_parameter_groups`},
	{read: "ListDBClusters", service: "rds", breakSQL: `DROP TABLE rds_db_clusters`},

	{read: "ListDynamoDBTables", service: "dynamodb", breakSQL: `DROP TABLE dynamodb_tables`},
	{read: "ScanDynamoDBTable", service: "dynamodb", breakSQL: `DROP TABLE dynamodb_items`,
		seed: func(t *testing.T, _ *handlers.Application, srv *httptest.Server) { seedTable(t, srv, "fc") }},
	{read: "ScanDynamoDBTable", name: "dynamodb item JSON", service: "dynamodb", breakSQL: `UPDATE dynamodb_items SET item = 'not json'`,
		seed: func(t *testing.T, _ *handlers.Application, srv *httptest.Server) {
			seedTable(t, srv, "fc")
			mustOK(t)(ddbCall(t, srv, stateRegion, "PutItem", `{"TableName":"fc","Item":{"id":{"S":"a"}}}`))
		}},

	{read: "ListEKSClusters", service: "eks", breakSQL: `DROP TABLE eks_clusters`},
	{read: "ListEKSNodeGroups", service: "eks", breakSQL: `UPDATE eks_node_groups SET data = 'not json'`, seed: seedEKS},
	{read: "ListEKSNodeGroups", name: "eks scaling_config JSON", service: "eks", breakSQL: `UPDATE eks_node_groups SET data = json_set(data, '$.scaling_config', 'not json')`, seed: seedEKS},
	{read: "ListEKSAddons", service: "eks", breakSQL: `UPDATE eks_addons SET data = 'not json'`, seed: seedEKS},

	{read: "ListSQSQueues", service: "sqs", breakSQL: `DROP TABLE sqs_queues`},
	{read: "ListSQSMessages", service: "sqs", breakSQL: `DROP TABLE sqs_messages`,
		seed: func(t *testing.T, _ *handlers.Application, srv *httptest.Server) {
			var queue struct{ QueueUrl string }
			require.NoError(t, json.Unmarshal(mustOK(t)(sqsCall(t, srv, "CreateQueue", `{"QueueName":"fc"}`)), &queue))
			mustOK(t)(sqsCall(t, srv, "SendMessage", `{"QueueUrl":"`+queue.QueueUrl+`","MessageBody":"x"}`))
		}},

	{read: "ListHostedZones", service: "route53", breakSQL: `DROP TABLE route53_hosted_zones`},
	{read: "ListRecordSets", service: "route53", breakSQL: `UPDATE route53_record_sets SET records = 'not json'`,
		seed: func(t *testing.T, _ *handlers.Application, srv *httptest.Server) { seedZone(t, srv, "fc") }},
	{read: "ListRecordSets", name: "route53 alias_target JSON", service: "route53", breakSQL: `UPDATE route53_record_sets SET alias_target = 'not json' WHERE type = 'A'`,
		seed: func(t *testing.T, app *handlers.Application, srv *httptest.Server) {
			require.NoError(t, app.Repository().PutRecordSet(awsproto.FakeAccountID, &repository.Route53RecordSet{
				ZoneID: seedZone(t, srv, "fc"), Name: "www.fc.example.", Type: "A", AliasTarget: `{"DNSName":"d"}`,
			}))
		}},

	{read: "ListSecrets", service: "secretsmanager", breakSQL: `DROP TABLE secretsmanager_secrets`},
	{read: "ListSecrets", name: "secret tags JSON", service: "secretsmanager", breakSQL: `UPDATE secretsmanager_secrets SET tags = 'not json'`,
		seed: func(t *testing.T, _ *handlers.Application, srv *httptest.Server) {
			mustOK(t)(smCall(t, srv, "CreateSecret", `{"Name":"fc","SecretString":"s"}`))
		}},
	{read: "ListSecretVersions", service: "secretsmanager", breakSQL: `UPDATE secretsmanager_versions SET stages = 'not json'`,
		seed: func(t *testing.T, _ *handlers.Application, srv *httptest.Server) {
			mustOK(t)(smCall(t, srv, "CreateSecret", `{"Name":"fc","SecretString":"s"}`))
		}},

	{read: "ListSSMParameters", service: "ssm", breakSQL: `DROP TABLE ssm_parameters`},

	{read: "ListKMSKeys", service: "kms", breakSQL: `DROP TABLE kms_keys`},
	{read: "ListKMSKeys", name: "kms key data JSON", service: "kms", breakSQL: `UPDATE kms_keys SET data = 'not json'`,
		seed: func(t *testing.T, _ *handlers.Application, srv *httptest.Server) { kmsCreateKey(t, srv, "fc") }},
}

// TestAdminMockState_UnreadableTableIs500: every read behind a /mock/state
// block, a child read as much as a parent's, that fails (a dropped table,
// a stored value that does not decode or scan) answers 500 with only
// "<service> state could not be read": no state, and no SQL, table or
// decoder text, which goes to the log. Never an empty block an orphan
// check would pass. A read with no case fails the test.
func TestAdminMockState_UnreadableTableIs500(t *testing.T) {
	covered := map[string]bool{}
	for _, c := range stateBreaks {
		covered[c.read] = true
		name := c.name
		if name == "" {
			name = c.read
		}
		t.Run(name, func(t *testing.T) {
			app, srv := newTestApp(t, ":memory:")
			if c.seed != nil {
				c.seed(t, app, srv)
			}
			res, err := app.Repository().DB().Exec(c.breakSQL)
			require.NoError(t, err)
			if strings.HasPrefix(c.breakSQL, "UPDATE") {
				n, err := res.RowsAffected()
				require.NoError(t, err)
				require.Positive(t, n, "the seed left no row to corrupt")
			}
			var logs bytes.Buffer
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(os.Stderr) })

			for _, path := range []string{"/mock/state", "/mock/state/" + c.service} {
				resp, body := doGet(t, srv, path)
				assert.Equal(t, http.StatusInternalServerError, resp.StatusCode, "GET %s: %s", path, body)
				var got map[string]any
				require.NoError(t, json.Unmarshal(body, &got), "GET %s: %s", path, body)
				assert.Equal(t, map[string]any{"status": "error", "message": c.service + " state could not be read"}, got, "GET %s", path)
			}
			assert.Contains(t, logs.String(), "read "+c.service+" state: ", "the detail is logged")
		})
	}

	reads := stateGatherReads(t)
	for _, read := range reads {
		assert.True(t, covered[read], "no case in stateBreaks makes %s fail", read)
	}
	for read := range covered {
		assert.Contains(t, reads, read, "a stateBreaks case names %s, which no gather reads", read)
	}
}

// TestAdminMockState_SkipsWhatAFollowUpReadNoLongerFinds: a parent a
// list returns but a follow-up read no longer finds (models.ErrNotFound)
// was deleted between the two; /mock/state leaves it out, keeps its
// sibling, and answers 200. hide stands in for that delete on the
// parent listed first, so a break or an early return loses the sibling:
// it changes a column the follow-up read matches but the list neither
// filters nor orders by (to a BLOB, which equals no text), or the key
// inside the data the list decodes.
func TestAdminMockState_SkipsWhatAFollowUpReadNoLongerFinds(t *testing.T) {
	for _, c := range []struct {
		name, service, hide string
		seed                func(t *testing.T, srv *httptest.Server) (string, string)
	}{
		{name: "security group rules", service: "ec2",
			hide: `UPDATE ec2_security_groups SET region = CAST(region AS BLOB) WHERE id = ?`,
			seed: func(t *testing.T, srv *httptest.Server) (string, string) {
				vpcID := seedVPC(t, srv)
				return seedSG(t, srv, vpcID, "fc-a"), seedSG(t, srv, vpcID, "fc-b")
			}},
		{name: "internet gateway", service: "ec2",
			hide: `UPDATE ec2_internet_gateways SET region = CAST(region AS BLOB) WHERE id = ?`,
			seed: func(t *testing.T, srv *httptest.Server) (string, string) {
				igw := func() string {
					return extractEC2Tag(mustOK(t)(ec2Call(t, srv, stateRegion, "CreateInternetGateway", nil)), "internetGatewayId")
				}
				return igw(), igw()
			}},
		{name: "hosted zone", service: "route53",
			hide: `UPDATE route53_hosted_zones SET data = json_set(data, '$.id', id || '-gone') WHERE id = ?`,
			seed: func(t *testing.T, srv *httptest.Server) (string, string) {
				return seedZone(t, srv, "fc-a"), seedZone(t, srv, "fc-b")
			}},
		{name: "dynamodb table", service: "dynamodb",
			hide: `UPDATE dynamodb_tables SET region = CAST(region AS BLOB) WHERE name = ?`,
			seed: func(t *testing.T, srv *httptest.Server) (string, string) {
				seedTable(t, srv, "fc-a")
				seedTable(t, srv, "fc-b")
				return "fc-a", "fc-b"
			}},
		{name: "bucket configs", service: "s3",
			hide: `UPDATE s3_buckets SET data = json_set(data, '$.name', name || '-gone') WHERE name = ?`,
			seed: func(t *testing.T, srv *httptest.Server) (string, string) {
				seedBucket(t, srv, "fc-a")
				seedBucket(t, srv, "fc-b")
				return "fc-a", "fc-b"
			}},
		// Secrets list by region, then name: the hidden one moves to a
		// region that sorts first.
		{name: "secret versions", service: "secretsmanager",
			hide: `UPDATE secretsmanager_secrets SET region = 'af-south-1', name = CAST(name AS BLOB) WHERE name = ?`,
			seed: func(t *testing.T, srv *httptest.Server) (string, string) {
				mustOK(t)(smCall(t, srv, "CreateSecret", `{"Name":"fc-a","SecretString":"s"}`))
				mustOK(t)(smCall(t, srv, "CreateSecret", `{"Name":"fc-b","SecretString":"s"}`))
				return "fc-a", "fc-b"
			}},
	} {
		t.Run(c.name, func(t *testing.T) {
			app, srv := newTestApp(t, ":memory:")
			a, b := c.seed(t, srv)
			gone, kept := min(a, b), max(a, b)
			db := app.Repository().DB()
			_, err := db.Exec(`PRAGMA foreign_keys = OFF`)
			require.NoError(t, err)
			res, err := db.Exec(c.hide, gone)
			require.NoError(t, err)
			n, err := res.RowsAffected()
			require.NoError(t, err)
			require.EqualValues(t, 1, n)
			_, err = db.Exec(`PRAGMA foreign_keys = ON`)
			require.NoError(t, err)

			resp, body := doGet(t, srv, "/mock/state")
			require.Equal(t, http.StatusOK, resp.StatusCode, "%s", body)
			var state map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(body, &state))
			assert.NotContains(t, string(state[c.service]), gone)
			assert.Contains(t, string(state[c.service]), kept, "the sibling listed after it stays")
		})
	}
}

// TestAdminMockState_PerServiceReadsOnlyItsTables: /mock/state/<service>
// reads only that service's tables, so another service's unreadable
// table leaves it 200.
func TestAdminMockState_PerServiceReadsOnlyItsTables(t *testing.T) {
	app, srv := newTestApp(t, ":memory:")
	_, err := app.Repository().DB().Exec(`DROP TABLE ssm_parameters`)
	require.NoError(t, err)

	resp, body := doGet(t, srv, "/mock/state/iam")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "%s", body)
}

func TestAdminMockReset_OK(t *testing.T) {
	srv := newTestServer(t, ":memory:")

	resp, body := doPost(t, srv, "/mock/reset")
	require.Equal(t, http.StatusOK, resp.StatusCode, "body %s", body)
}

func TestAdminMockSnapshot_MemoryConflict(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, body := doPost(t, srv, "/mock/snapshot")
	require.Equal(t, http.StatusConflict, resp.StatusCode, "snapshot meaningless on :memory:; body: %s", body)
}

func TestAdminMockRestore_NoBaselineIs404(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	srv := newTestServer(t, dbPath)

	resp, body := doPost(t, srv, "/mock/restore")
	require.Equal(t, http.StatusNotFound, resp.StatusCode, "no snapshot baseline; body: %s", body)
}

func TestAdminMockSnapshotRestore_FileBackedRoundTrips(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	srv := newTestServer(t, dbPath)

	// Snapshot the empty state.
	r, b := doPost(t, srv, "/mock/snapshot")
	require.Equal(t, http.StatusOK, r.StatusCode, "snapshot body %s", b)

	// Restore — the snapshot file exists, so this should 200.
	r, b = doPost(t, srv, "/mock/restore")
	require.Equal(t, http.StatusOK, r.StatusCode, "restore body %s", b)
}

func TestAdminMockRestore_MemoryConflict(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	resp, body := doPost(t, srv, "/mock/restore")
	require.Equal(t, http.StatusConflict, resp.StatusCode, "restore meaningless on :memory:; body: %s", body)
	assert.NoFileExists(t, ":memory:", ":memory: must not create a file")
}

// A snapshot at another db schema version is refused 409 naming the
// stored and wanted versions, and the live state is as it was.
func TestContract_restore_refuses_other_schema_version(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	app, srv := newTestApp(t, dbPath)
	resp, body := sqsCall(t, srv, "CreateQueue", `{"QueueName":"in-snapshot"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateQueue: %s", body)
	resp, body = doPost(t, srv, "/mock/snapshot")
	require.Equal(t, http.StatusOK, resp.StatusCode, "snapshot: %s", body)
	resp, body = sqsCall(t, srv, "CreateQueue", `{"QueueName":"after-snapshot"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateQueue: %s", body)

	var want string
	require.NoError(t, app.Repository().DB().QueryRow(`SELECT version FROM schema_version`).Scan(&want))
	snap, err := sql.Open("sqlite", dbPath+".snapshot")
	require.NoError(t, err)
	_, err = snap.Exec(`UPDATE schema_version SET version = 1`)
	require.NoError(t, err)
	require.NoError(t, snap.Close())
	_, before := doGet(t, srv, "/mock/state")

	resp, body = doPost(t, srv, "/mock/restore")
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "restore: %s", body)
	assert.Contains(t, string(body), dbPath+".snapshot: database schema version 1, fakeaws needs "+want)
	_, after := doGet(t, srv, "/mock/state")
	assert.Equal(t, string(before), string(after), "/mock/state as it was")
}

// assertOwnerOnly checks each path is a file with mode exactly 0600.
func assertOwnerOnly(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		fi, err := os.Stat(p)
		if assert.NoError(t, err) {
			assert.Equal(t, os.FileMode(0o600).String(), fi.Mode().Perm().String(), filepath.Base(p))
		}
	}
}

func TestContract_file_backed_db_owner_only(t *testing.T) {
	// Under umask 022 a file created without an explicit mode is 0644.
	umask := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(umask) })
	dbPath := filepath.Join(t.TempDir(), "test.db")
	live := []string{dbPath, dbPath + "-wal", dbPath + "-shm"}
	srv := newTestServer(t, dbPath)

	resp, body := sqsCall(t, srv, "CreateQueue", `{"QueueName":"owner-only"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateQueue: %s", body)
	assertOwnerOnly(t, live...)

	// Left by a snapshot killed mid-VACUUM.
	require.NoError(t, os.WriteFile(dbPath+".snapshot.tmp", []byte("partial"), 0o644))
	resp, body = doPost(t, srv, "/mock/snapshot")
	require.Equal(t, http.StatusOK, resp.StatusCode, "snapshot: %s", body)
	assertOwnerOnly(t, dbPath+".snapshot")
	assert.NoFileExists(t, dbPath+".snapshot.tmp")

	resp, body = doPost(t, srv, "/mock/restore")
	require.Equal(t, http.StatusOK, resp.StatusCode, "restore: %s", body)
	assertOwnerOnly(t, live...)

	require.NoError(t, os.Remove(dbPath))
	resp, body = doPost(t, srv, "/mock/restore")
	require.Equal(t, http.StatusOK, resp.StatusCode, "restore over a removed db: %s", body)
	assertOwnerOnly(t, live...)
}

// A failed VACUUM INTO leaves no .snapshot, so the next restore is 404
// instead of copying an empty file over the live db. Nor is there one
// while VACUUM runs, so a kill then leaves none either.
func TestAdminMockSnapshot_FailedVacuumLeavesNoSnapshot(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	srv := newTestServer(t, dbPath)
	resp, body := sqsCall(t, srv, "CreateQueue", `{"QueueName":"survives"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateQueue: %s", body)

	var statDuringVacuum error
	vacuum := repository.VacuumInto
	repository.VacuumInto = func(*sql.DB, string) error {
		_, statDuringVacuum = os.Stat(dbPath + ".snapshot")
		return errors.New("forced vacuum failure")
	}
	t.Cleanup(func() { repository.VacuumInto = vacuum })

	resp, body = doPost(t, srv, "/mock/snapshot")
	require.Equal(t, http.StatusInternalServerError, resp.StatusCode, "snapshot: %s", body)
	assert.ErrorIs(t, statDuringVacuum, os.ErrNotExist, ".snapshot exists while VACUUM runs")
	assert.NoFileExists(t, dbPath+".snapshot")
	assert.NoFileExists(t, dbPath+".snapshot.tmp")

	resp, body = doPost(t, srv, "/mock/restore")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "restore after a failed snapshot: %s", body)
	resp, body = sqsCall(t, srv, "GetQueueUrl", `{"QueueName":"survives"}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "live db intact: %s", body)
}

func TestAdminMockImages_SeededImageLaunches(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	const region = "us-east-1"
	const ami = "ami-0123456789abcdef0"

	seed := `{"ami_id":"` + ami + `","name":"al2023-ami-real","region":"us-east-1","root_device_name":"/dev/sdz","account_id":"000000000000"}`
	resp, body := doPostJSON(t, srv, "/mock/images", seed)
	require.Equal(t, http.StatusOK, resp.StatusCode, "seed: %s", body)
	resp, body = doPostJSON(t, srv, "/mock/images", seed)
	require.Equal(t, http.StatusOK, resp.StatusCode, "identical re-seed: %s", body)

	resp, body = ec2Call(t, srv, region, "DescribeImages", url.Values{"ImageId.1": {ami}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeImages: %s", body)
	assert.Contains(t, string(body), ami)
	assert.Contains(t, string(body), "<rootDeviceName>/dev/sdz</rootDeviceName>", "seeded root device: %s", body)
	assert.Contains(t, string(body), "<imageOwnerId>amazon</imageOwnerId>", "owner defaults to the AL2023 fixture's: %s", body)

	subnetID := adminTestSubnet(t, srv, region)
	resp, body = runImage(t, srv, region, subnetID, ami)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "RunInstances seeded: %s", body)
	resp, body = runImage(t, srv, region, subnetID, "ami-0fedcba9876543210")
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "InvalidAMIID.NotFound", "unseeded id still refused")

	resp, body = doPost(t, srv, "/mock/reset")
	require.Equal(t, http.StatusOK, resp.StatusCode, "reset: %s", body)
	subnetID = adminTestSubnet(t, srv, region)
	resp, body = runImage(t, srv, region, subnetID, ami)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "InvalidAMIID.NotFound", "reset drops the seeded image")
}

// TestAdminMockImages_ReseedConflicts pins that a re-seed never
// changes a stored image: identical fields are 200 with the stored row,
// any differing field is 409 naming it. Fixture ids count as stored,
// in a region touched before or not.
func TestAdminMockImages_ReseedConflicts(t *testing.T) {
	app, srv := newTestApp(t, ":memory:")
	const ami = "ami-0123456789abcdef0"

	seed := `{"ami_id":"` + ami + `","name":"al2023-ami-real","region":"us-east-1","root_device_name":"/dev/sdz"}`
	resp, body := doPostJSON(t, srv, "/mock/images", seed)
	require.Equal(t, http.StatusOK, resp.StatusCode, "seed: %s", body)

	for name, tc := range map[string]struct{ body, wantMessage, region, ami, wantRootDevice string }{
		"differing re-seed": {
			body:        `{"ami_id":"` + ami + `","name":"al2023-ami-other","region":"us-east-1","root_device_name":"/dev/xvda"}`,
			wantMessage: ami + " already exists in us-east-1 with a different name, root_device_name",
			region:      "us-east-1", ami: ami, wantRootDevice: "/dev/sdz",
		},
		"differing AL2023 fixture": {
			body:        `{"ami_id":"` + handlers.AL2023AMIID + `","name":"al2023-ami-real","region":"us-east-1","root_device_name":"/dev/xvda","owner_id":"137112412989"}`,
			wantMessage: handlers.AL2023AMIID + " already exists in us-east-1 with a different name, owner_id",
			region:      "us-east-1", ami: handlers.AL2023AMIID, wantRootDevice: "/dev/xvda",
		},
		"differing fixture in an untouched region": {
			body:        `{"ami_id":"ami-0abcd1234","name":"amzn2-ami-hvm-2.0","region":"eu-west-3","root_device_name":"/dev/sdz","virtualization_type":"paravirtual"}`,
			wantMessage: "ami-0abcd1234 already exists in eu-west-3 with a different virtualization_type, root_device_name",
			region:      "eu-west-3", ami: "ami-0abcd1234", wantRootDevice: "/dev/xvda",
		},
	} {
		t.Run(name, func(t *testing.T) {
			before := amiRowCount(t, app)
			resp, body := doPostJSON(t, srv, "/mock/images", tc.body)
			assert.Equal(t, http.StatusConflict, resp.StatusCode, "body: %s", body)
			assert.Equal(t, tc.wantMessage, adminErrorMessage(t, body))
			assert.Equal(t, before, amiRowCount(t, app), "conflict wrote an image row")

			resp, body = ec2Call(t, srv, tc.region, "DescribeImages", url.Values{"ImageId.1": {tc.ami}})
			require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeImages: %s", body)
			assert.Contains(t, string(body), "<rootDeviceName>"+tc.wantRootDevice+"</rootDeviceName>", "stored row unchanged: %s", body)
		})
	}

	for name, tc := range map[string]struct{ body, wantName string }{
		"identical re-seed":        {seed, "al2023-ami-real"},
		"identical AL2023 fixture": {`{"ami_id":"` + handlers.AL2023AMIID + `","name":"al2023-ami-2023.6.20241010.0-kernel-6.1-x86_64","region":"us-east-1","root_device_name":"/dev/xvda"}`, "al2023-ami-2023.6.20241010.0-kernel-6.1-x86_64"},
	} {
		t.Run(name, func(t *testing.T) {
			resp, body := doPostJSON(t, srv, "/mock/images", tc.body)
			require.Equal(t, http.StatusOK, resp.StatusCode, "body: %s", body)
			var got struct {
				Image map[string]string `json:"image"`
			}
			require.NoError(t, json.Unmarshal(body, &got), "decode %s", body)
			assert.Equal(t, tc.wantName, got.Image["name"], "returns the stored row")
		})
	}
}

func TestAdminMockImages_InvalidBodyWritesNothing(t *testing.T) {
	app, srv := newTestApp(t, ":memory:")
	bigName := strings.Repeat("x", 64<<10)

	for name, tc := range map[string]struct{ body, wantMessage string }{
		"malformed id in an untouched region": {`{"ami_id":"ami-NOTHEX","name":"x","region":"ap-south-2","root_device_name":"/dev/xvda"}`,
			"ami_id must be ami- followed by 8 or 17 lowercase hex digits"},
		"id of another length": {`{"ami_id":"ami-0123456789","name":"x","region":"us-east-1","root_device_name":"/dev/xvda"}`,
			"ami_id must be ami- followed by 8 or 17 lowercase hex digits"},
		"no region": {`{"ami_id":"ami-0aaaaaaaaaaaaaaa1","name":"x","root_device_name":"/dev/xvda"}`,
			"region must look like us-east-1"},
		"upper-case region": {`{"ami_id":"ami-0aaaaaaaaaaaaaaa6","name":"x","region":"US-East-1","root_device_name":"/dev/xvda"}`,
			"region must look like us-east-1"},
		"region with trailing space": {`{"ami_id":"ami-0aaaaaaaaaaaaaaa7","name":"x","region":"us-east-1 ","root_device_name":"/dev/xvda"}`,
			"region must look like us-east-1"},
		"no name": {`{"ami_id":"ami-0aaaaaaaaaaaaaaa9","region":"us-east-1","root_device_name":"/dev/xvda"}`,
			"name is required"},
		"no root device name": {`{"ami_id":"ami-0aaaaaaaaaaaaaaa2","name":"x","region":"us-east-1"}`,
			"root_device_name is required"},
		"other account": {`{"ami_id":"ami-0aaaaaaaaaaaaaaa5","name":"x","region":"us-east-1","root_device_name":"/dev/xvda","account_id":"111122223333"}`,
			"account_id must be 000000000000"},
		"trailing data": {`{"ami_id":"ami-0aaaaaaaaaaaaaaa4","name":"x","region":"us-east-1","root_device_name":"/dev/xvda"} junk`,
			"invalid body: one JSON object expected"},
		"unknown field (typo)": {`{"ami_id":"ami-0aaaaaaaaaaaaaaa3","name":"x","region":"us-east-1","root_device":"/dev/xvda"}`,
			`invalid body: json: unknown field "root_device"`},
		"oversized body": {`{"ami_id":"ami-0aaaaaaaaaaaaaaa8","region":"us-east-1","root_device_name":"/dev/xvda","name":"` + bigName + `"}`,
			"invalid body: http: request body too large"},
	} {
		t.Run(name, func(t *testing.T) {
			before := amiRowCount(t, app)
			resp, body := doPostJSON(t, srv, "/mock/images", tc.body)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "body: %s", body)
			assert.Equal(t, tc.wantMessage, adminErrorMessage(t, body))
			assert.Equal(t, before, amiRowCount(t, app), "rejected request wrote an image row in some region or account")
		})
	}
}

// ----- helpers -----

// amiRowCount counts image rows across every account and region.
func amiRowCount(t *testing.T, app *handlers.Application) int {
	t.Helper()
	var n int
	require.NoError(t, app.Repository().DB().QueryRow(`SELECT COUNT(*) FROM ec2_amis`).Scan(&n))
	return n
}

func adminErrorMessage(t *testing.T, body []byte) string {
	t.Helper()
	var got struct {
		Status, Message string
	}
	require.NoError(t, json.Unmarshal(body, &got), "decode %s", body)
	assert.Equal(t, "error", got.Status)
	return got.Message
}

func adminTestSubnet(t *testing.T, srv *httptest.Server, region string) string {
	t.Helper()
	resp, body := ec2Call(t, srv, region, "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateVpc: %s", body)
	resp, body = ec2Call(t, srv, region, "CreateSubnet", url.Values{
		"VpcId": {extractEC2Tag(body, "vpcId")}, "CidrBlock": {"10.0.1.0/24"},
	})
	require.Equal(t, http.StatusOK, resp.StatusCode, "CreateSubnet: %s", body)
	return extractEC2Tag(body, "subnetId")
}

func runImage(t *testing.T, srv *httptest.Server, region, subnetID, ami string) (*http.Response, []byte) {
	t.Helper()
	return ec2Call(t, srv, region, "RunInstances", url.Values{
		"SubnetId": {subnetID}, "ImageId": {ami}, "InstanceType": {"t3.micro"},
	})
}

func doPostJSON(t *testing.T, srv *httptest.Server, path, payload string) (*http.Response, []byte) {
	t.Helper()
	resp, err := srv.Client().Post(srv.URL+path, "application/json", strings.NewReader(payload))
	require.NoError(t, err, "POST %s", path)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

// newTestApp is newTestServer that also hands back the Application,
// for tests that read the repository directly.
func newTestApp(t *testing.T, dbPath string) (*handlers.Application, *httptest.Server) {
	t.Helper()
	return newOptionsApp(t, handlers.Options{DBPath: dbPath})
}

// newOptionsApp is newTestApp for an Application built from opts.
func newOptionsApp(t *testing.T, opts handlers.Options) (*handlers.Application, *httptest.Server) {
	t.Helper()
	app, err := handlers.NewApplication(opts)
	require.NoError(t, err, "NewApplication")
	srv := httptest.NewServer(app.Router())
	t.Cleanup(func() {
		srv.Close()
		_ = app.Close()
	})
	return app, srv
}

func newTestServer(t *testing.T, dbPath string) *httptest.Server {
	t.Helper()
	_, srv := newTestApp(t, dbPath)
	return srv
}

func doGet(t *testing.T, srv *httptest.Server, path string) (*http.Response, []byte) {
	t.Helper()
	resp, err := srv.Client().Get(srv.URL + path)
	require.NoError(t, err, "GET %s", path)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

func doPost(t *testing.T, srv *httptest.Server, path string) (*http.Response, []byte) {
	t.Helper()
	resp, err := srv.Client().Post(srv.URL+path, "application/json", nil)
	require.NoError(t, err, "POST %s", path)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

const adminToken = "s3cr3t-admin-token"

// doAdmin sends method path with header and returns the status and body.
func doAdmin(t *testing.T, srv *httptest.Server, method, path string, header http.Header) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, nil)
	require.NoError(t, err)
	req.Header = header
	resp, err := srv.Client().Do(req)
	require.NoError(t, err, "%s %s", method, path)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(body)
}

type adminRoute struct{ method, path string }

// mockRoutes walks app's router for its /mock routes, filling the
// {service} parameter, and adds an unknown /mock path.
func mockRoutes(t *testing.T, app *handlers.Application) []adminRoute {
	t.Helper()
	var routes []adminRoute
	err := chi.Walk(app.Router().(chi.Routes), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if strings.HasPrefix(route, "/mock/") {
			routes = append(routes, adminRoute{method, strings.ReplaceAll(route, "{service}", "iam")})
		}
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, routes, "no /mock routes found")
	return append(routes, adminRoute{http.MethodGet, "/mock/x"})
}

func bearer(token string) http.Header {
	return http.Header{"Authorization": {"Bearer " + token}}
}

func TestContract_listen_addr_default_all_interfaces(t *testing.T) {
	assert.Equal(t, ":8082", handlers.Options{Port: 8082}.ListenAddr())
	assert.Equal(t, "[::1]:8082", handlers.Options{Bind: "::1", Port: 8082}.ListenAddr())

	ln, err := net.Listen("tcp", handlers.Options{Bind: "127.0.0.1"}.ListenAddr())
	require.NoError(t, err)
	defer ln.Close()
	assert.Equal(t, "127.0.0.1", ln.Addr().(*net.TCPAddr).IP.String())
}

func TestContract_mock_admin_token_required(t *testing.T) {
	app, guarded := newOptionsApp(t, handlers.Options{DBPath: ":memory:", AdminToken: adminToken})
	plain := newTestServer(t, ":memory:")

	for _, rt := range mockRoutes(t, app) {
		for name, h := range map[string]http.Header{
			"no Authorization": {},
			"wrong token":      bearer("wrong"),
			"non-Bearer":       {"Authorization": {"Basic " + adminToken}},
		} {
			status, body := doAdmin(t, guarded, rt.method, rt.path, h)
			assert.Equal(t, http.StatusUnauthorized, status, "%s %s, %s: %s", rt.method, rt.path, name, body)
			assert.NotContains(t, body, adminToken, "%s %s, %s", rt.method, rt.path, name)
		}

		wantStatus, wantBody := doAdmin(t, plain, rt.method, rt.path, http.Header{})
		status, body := doAdmin(t, guarded, rt.method, rt.path, bearer(adminToken))
		assert.Equal(t, wantStatus, status, "%s %s with the token", rt.method, rt.path)
		assert.Equal(t, wantBody, body, "%s %s with the token", rt.method, rt.path)
	}

	status, _ := doAdmin(t, guarded, http.MethodGet, "/healthz", http.Header{})
	assert.Equal(t, http.StatusOK, status, "/healthz is not gated")
	resp, body := stsCall(t, guarded, "GetCallerIdentity")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "provider routes are not gated: %s", body)
}

func TestContract_mock_admin_origin_loopback_only(t *testing.T) {
	app, srv := newOptionsApp(t, handlers.Options{DBPath: ":memory:", AdminToken: adminToken})

	for _, origin := range []string{"https://evil.example", "null", "http://localhost.evil", "http://127.0.0.1.evil"} {
		for _, rt := range mockRoutes(t, app) {
			h := bearer(adminToken)
			h.Set("Origin", origin)
			status, body := doAdmin(t, srv, rt.method, rt.path, h)
			assert.Equal(t, http.StatusForbidden, status, "%s %s, Origin %s: %s", rt.method, rt.path, origin, body)
			assert.NotContains(t, body, adminToken)
		}
	}

	for _, origin := range []string{"", "http://127.0.0.1:4173", "http://localhost:4173", "http://[::1]:4173"} {
		h := bearer(adminToken)
		if origin != "" {
			h.Set("Origin", origin)
		}
		status, body := doAdmin(t, srv, http.MethodGet, "/mock/state", h)
		assert.Equal(t, http.StatusOK, status, "Origin %q: %s", origin, body)
	}
}

// Without an admin token /mock is as open as it always was: a
// non-loopback Origin and no Authorization change nothing.
func TestAdminMock_NoTokenIsUngated(t *testing.T) {
	srv := newTestServer(t, ":memory:")
	evil := http.Header{"Origin": {"https://evil.example"}}

	for _, tc := range []struct {
		path   string
		status int
	}{
		{"/mock/state", http.StatusOK},
		{"/mock/x", http.StatusNotImplemented},
	} {
		wantStatus, wantBody := doAdmin(t, srv, http.MethodGet, tc.path, http.Header{})
		status, body := doAdmin(t, srv, http.MethodGet, tc.path, evil)
		assert.Equal(t, tc.status, wantStatus, tc.path)
		assert.Equal(t, wantStatus, status, tc.path)
		assert.Equal(t, wantBody, body, tc.path)
	}
}

const (
	otherAccount = "123456789012"
	thirdAccount = "210987654321"
	refusedMsg   = "resource conflict: account " + otherAccount + " refused: the database is not empty and holds account 000000000000"
)

func accountID(t *testing.T, app *handlers.Application) string {
	t.Helper()
	id, err := app.AccountID()
	require.NoError(t, err)
	return id
}

func storedIdentity(t *testing.T, app *handlers.Application) repository.Identity {
	t.Helper()
	id, err := app.Repository().GetIdentity()
	require.NoError(t, err)
	return id
}

func TestContract_identity_change_refused_on_non_empty_db(t *testing.T) {
	setOther := `{"account_id":"` + otherAccount + `","region":"eu-west-1"}`
	for name, create := range map[string]func(*testing.T, *httptest.Server){
		"role": func(t *testing.T, srv *httptest.Server) { createRole(t, srv, "identity-role") },
		"vpc": func(t *testing.T, srv *httptest.Server) {
			resp, body := ec2Call(t, srv, "us-east-1", "CreateVpc", url.Values{"CidrBlock": {"10.0.0.0/16"}})
			require.Equal(t, http.StatusOK, resp.StatusCode, "CreateVpc: %s", body)
		},
		"kms key": func(t *testing.T, srv *httptest.Server) { mustOK(t)(kmsCall(t, srv, "us-east-1", "CreateKey", `{}`)) },
	} {
		t.Run(name, func(t *testing.T) {
			app, srv := newTestApp(t, ":memory:")
			create(t, srv)
			resp, body := doPostJSON(t, srv, "/mock/identity", setOther)
			assert.Equal(t, http.StatusConflict, resp.StatusCode, "body: %s", body)
			assert.Equal(t, refusedMsg, adminErrorMessage(t, body))
			assert.Equal(t, awsproto.FakeAccountID, accountID(t, app))
		})
	}

	app, srv := newTestApp(t, ":memory:")
	resp, body := doPostJSON(t, srv, "/mock/identity", setOther)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "empty database: %s", body)
	assert.Equal(t, otherAccount, accountID(t, app))

	dbPath := filepath.Join(t.TempDir(), "test.db")
	app, srv = newTestApp(t, dbPath)
	createRole(t, srv, "identity-role")
	require.NoError(t, app.Close())
	_, err := handlers.NewApplication(handlers.Options{DBPath: dbPath, AccountID: otherAccount})
	require.Error(t, err, "boot with another account on a non-empty file database")
	assert.Equal(t, refusedMsg, err.Error())
}

func TestContract_identity_stored_in_database(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	app, srv := newTestApp(t, dbPath)
	want := repository.Identity{AccountID: otherAccount, Region: "eu-west-1"}

	resp, body := doPostJSON(t, srv, "/mock/identity", `{"account_id":"`+otherAccount+`","region":"eu-west-1"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "set: %s", body)
	resp, body = doPost(t, srv, "/mock/snapshot")
	require.Equal(t, http.StatusOK, resp.StatusCode, "snapshot: %s", body)
	resp, body = doPostJSON(t, srv, "/mock/identity", `{"account_id":"`+thirdAccount+`"}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "set again: %s", body)
	require.Equal(t, thirdAccount, accountID(t, app))

	resp, body = doPost(t, srv, "/mock/restore")
	require.Equal(t, http.StatusOK, resp.StatusCode, "restore: %s", body)
	assert.Equal(t, otherAccount, accountID(t, app), "restore")
	assert.Equal(t, want, storedIdentity(t, app), "restore")

	require.NoError(t, app.Close())
	app, srv = newTestApp(t, dbPath)
	assert.Equal(t, want, storedIdentity(t, app), "reopened with no AccountID")

	createRole(t, srv, "identity-role")
	require.NoError(t, app.Close())
	app, srv = newOptionsApp(t, handlers.Options{DBPath: dbPath, AccountID: otherAccount})
	assert.Equal(t, want, storedIdentity(t, app), "reopened non-empty with the same account and no region")

	resp, body = doPost(t, srv, "/mock/reset")
	require.Equal(t, http.StatusOK, resp.StatusCode, "reset: %s", body)
	assert.Equal(t, awsproto.FakeAccountID, accountID(t, app), "reset")
}

func TestAdminMockIdentity_UnreadableIdentityIs500(t *testing.T) {
	app, srv := newTestApp(t, ":memory:")
	_, err := app.Repository().DB().Exec(`DROP TABLE identity`)
	require.NoError(t, err)

	_, err = app.AccountID()
	assert.Error(t, err)
	resp, body := doPostJSON(t, srv, "/mock/identity", `{"account_id":"`+otherAccount+`"}`)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode, "POST /mock/identity: %s", body)
	resp, body = doPostJSON(t, srv, "/mock/images", `{"ami_id":"ami-0123456789abcdef0","name":"x","region":"us-east-1","root_device_name":"/dev/xvda"}`)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode, "POST /mock/images: %s", body)
	for _, path := range []string{"/mock/state", "/mock/state/iam"} {
		resp, body := doGet(t, srv, path)
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode, "GET %s: %s", path, body)
	}
}

// A new table seeded at boot that does not join repository's
// emptyExclusions makes every fresh database read as non-empty, which
// fails this test.
func TestAdminMockIdentity_FixturesCountAsEmpty(t *testing.T) {
	app, srv := newTestApp(t, ":memory:")
	resp, body := ec2Call(t, srv, "ap-south-2", "DescribeImages", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "DescribeImages: %s", body)
	var n int
	require.NoError(t, app.Repository().DB().QueryRow(`SELECT COUNT(*) FROM ec2_amis WHERE region = 'ap-south-2'`).Scan(&n))
	require.Positive(t, n, "DescribeImages lazily seeds the fixtures into an unseeded region")

	resp, body = doPostJSON(t, srv, "/mock/identity", `{"account_id":"`+otherAccount+`"}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "body: %s", body)
}

// Until EC2 reads the stored account, these rows are invisible to
// RunInstances under any account but the default.
func TestAdminMockIdentity_SeedsGoUnderStoredAccount(t *testing.T) {
	app, srv := newOptionsApp(t, handlers.Options{DBPath: ":memory:", AccountID: otherAccount})
	amis := func(account string) int {
		var n int
		require.NoError(t, app.Repository().DB().QueryRow(`SELECT COUNT(*) FROM ec2_amis WHERE account_id = ?`, account).Scan(&n))
		return n
	}
	assert.Positive(t, amis(otherAccount), "boot fixtures under the stored account")
	assert.Zero(t, amis(awsproto.FakeAccountID), "boot fixtures under the default")

	before := amis(otherAccount)
	seed := `{"ami_id":"ami-0123456789abcdef0","name":"x","region":"us-east-1","root_device_name":"/dev/xvda"`
	resp, body := doPostJSON(t, srv, "/mock/images", seed+`,"account_id":"000000000000"}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "body: %s", body)
	assert.Equal(t, "account_id must be "+otherAccount, adminErrorMessage(t, body))
	resp, body = doPostJSON(t, srv, "/mock/images", seed+`}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, "body: %s", body)
	assert.Equal(t, before+1, amis(otherAccount), "seeded image under the stored account")

	resp, body = doPostJSON(t, srv, "/mock/identity", `{"account_id":"`+thirdAccount+`"}`)
	assert.Equal(t, http.StatusConflict, resp.StatusCode, "a seeded image is not empty: %s", body)
}

func TestAdminMockIdentity_InvalidBodyWritesNothing(t *testing.T) {
	app, srv := newTestApp(t, ":memory:")
	for name, tc := range map[string]struct{ body, wantMessage string }{
		"two digits":       {`{"account_id":"12"}`, "account_id must be 12 digits"},
		"thirteen digits":  {`{"account_id":"1234567890123"}`, "account_id must be 12 digits"},
		"not digits":       {`{"account_id":"12345678901a"}`, "account_id must be 12 digits"},
		"no account":       {`{"region":"eu-west-1"}`, "account_id must be 12 digits"},
		"malformed region": {`{"account_id":"` + otherAccount + `","region":"eu-west"}`, "region must look like us-east-1"},
		"unknown field":    {`{"account_id":"` + otherAccount + `","acount":"x"}`, `invalid body: json: unknown field "acount"`},
		"trailing data":    {`{"account_id":"` + otherAccount + `"} junk`, "invalid body: one JSON object expected"},
		"two objects":      {`{"account_id":"` + otherAccount + `"}{}`, "invalid body: one JSON object expected"},
	} {
		t.Run(name, func(t *testing.T) {
			resp, body := doPostJSON(t, srv, "/mock/identity", tc.body)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "body: %s", body)
			assert.Equal(t, tc.wantMessage, adminErrorMessage(t, body))
			_, err := app.Repository().GetIdentity()
			assert.ErrorIs(t, err, sql.ErrNoRows, "rejected request stored an identity")
		})
	}

	_, guarded := newOptionsApp(t, handlers.Options{DBPath: ":memory:", AdminToken: adminToken})
	resp, body := doPostJSON(t, guarded, "/mock/identity", `{"account_id":"`+otherAccount+`"}`)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "no bearer: %s", body)
}

// TestStoredAccount_ServiceARNs: under a stored account the SSM, KMS,
// DynamoDB, Secrets Manager, SQS, EKS and RDS ARNs, the KMS key
// policy's root principal and the SQS queue URL carry that account,
// and /mock/state lists the rows.
func TestStoredAccount_ServiceARNs(t *testing.T) {
	_, srv := newOptionsApp(t, handlers.Options{DBPath: ":memory:", AccountID: otherAccount})
	const region = "us-east-1"
	acct := ":" + otherAccount + ":"
	_, _, subnetA, subnetB := eksSetupPrereqs(t, srv, region)
	created := func(service string, body []byte) []byte {
		t.Helper()
		assert.Contains(t, string(body), acct, "%s: %s", service, body)
		assert.NotContains(t, string(body), awsproto.FakeAccountID, "%s: %s", service, body)
		return body
	}

	mustOK(t)(ssmCall(t, srv, "PutParameter", `{"Name":"/acct/param","Type":"String","Value":"v"}`))
	created("SSM GetParameter", mustOK(t)(ssmCall(t, srv, "GetParameter", `{"Name":"/acct/param"}`)))
	created("SSM DescribeParameters", mustOK(t)(ssmCall(t, srv, "DescribeParameters", `{}`)))

	var key struct {
		KeyMetadata struct{ Arn, AWSAccountId, KeyId string }
	}
	require.NoError(t, json.Unmarshal(created("KMS CreateKey", mustOK(t)(kmsCall(t, srv, region, "CreateKey", `{}`))), &key))
	assert.Equal(t, "arn:aws:kms:us-east-1:"+otherAccount+":key/"+key.KeyMetadata.KeyId, key.KeyMetadata.Arn)
	assert.Equal(t, otherAccount, key.KeyMetadata.AWSAccountId)
	var policy struct{ Policy string }
	require.NoError(t, json.Unmarshal(mustOK(t)(kmsCall(t, srv, region, "GetKeyPolicy", `{"KeyId":"`+key.KeyMetadata.KeyId+`"}`)), &policy))
	assert.Contains(t, policy.Policy, `"Principal":{"AWS":"arn:aws:iam::`+otherAccount+`:root"}`)
	assert.NotContains(t, policy.Policy, awsproto.FakeAccountID)

	created("DynamoDB CreateTable", mustOK(t)(ddbCall(t, srv, region, "CreateTable", `{"TableName":"acct",
		"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],
		"KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"BillingMode":"PAY_PER_REQUEST"}`)))
	var secret struct{ ARN string }
	require.NoError(t, json.Unmarshal(created("CreateSecret", mustOK(t)(smCall(t, srv, "CreateSecret", `{"Name":"acct","SecretString":"s"}`))), &secret))

	var queue struct{ QueueUrl string }
	require.NoError(t, json.Unmarshal(mustOK(t)(sqsCall(t, srv, "CreateQueue", `{"QueueName":"acct"}`)), &queue))
	assert.True(t, strings.HasSuffix(queue.QueueUrl, "/"+otherAccount+"/acct"), queue.QueueUrl)
	created("SQS GetQueueAttributes", mustOK(t)(sqsCall(t, srv, "GetQueueAttributes",
		`{"QueueUrl":"`+queue.QueueUrl+`","AttributeNames":["QueueArn"]}`)))

	// The EKS creates find the IAM roles and EC2 subnets under the
	// stored account.
	created("EKS CreateCluster", mustOK(t)(eksRequest(t, srv, http.MethodPost, "/eks/region/"+region+"/clusters",
		`{"name":"acct","roleArn":"`+awsproto.BuildIAMRoleARN(otherAccount, "eks-cluster-role")+
			`","resourcesVpcConfig":{"subnetIds":["`+subnetA+`","`+subnetB+`"]}}`)))
	created("EKS CreateNodegroup", mustOK(t)(eksRequest(t, srv, http.MethodPost, "/eks/region/"+region+"/clusters/acct/node-groups",
		`{"nodegroupName":"ng","nodeRole":"`+awsproto.BuildIAMRoleARN(otherAccount, "eks-node-role")+`","subnets":["`+subnetA+`"]}`)))

	// CreateDBSubnetGroup finds the EC2 subnets under the stored account.
	created("CreateDBSubnetGroup", mustOK(t)(rdsCall(t, srv, region, "CreateDBSubnetGroup", url.Values{
		"DBSubnetGroupName": {"acct"}, "DBSubnetGroupDescription": {"d"},
		"SubnetIds.member.1": {subnetA}, "SubnetIds.member.2": {subnetB},
	})))
	created("CreateDBParameterGroup", mustOK(t)(rdsCall(t, srv, region, "CreateDBParameterGroup", url.Values{
		"DBParameterGroupName": {"acct"}, "DBParameterGroupFamily": {"postgres15"}, "Description": {"d"},
	})))
	created("CreateDBCluster", mustOK(t)(rdsCall(t, srv, region, "CreateDBCluster", url.Values{
		"DBClusterIdentifier": {"acct"}, "Engine": {"aurora-postgresql"},
	})))
	created("CreateDBInstance", mustOK(t)(rdsCall(t, srv, region, "CreateDBInstance", url.Values{
		"DBInstanceIdentifier": {"acct"}, "Engine": {"postgres"},
		"DBInstanceClass": {"db.t3.micro"}, "DBSubnetGroupName": {"acct"},
	})))

	stateARNs := arnsIn(t, srv)
	for _, want := range []string{
		"arn:aws:dynamodb:us-east-1:" + otherAccount + ":table/acct",
		secret.ARN,
		"arn:aws:sqs:us-east-1:" + otherAccount + ":acct",
		"arn:aws:eks:us-east-1:" + otherAccount + ":cluster/acct",
		"arn:aws:eks:us-east-1:" + otherAccount + ":nodegroup/acct/ng/deterministic",
		"arn:aws:rds:us-east-1:" + otherAccount + ":db:acct",
		"arn:aws:rds:us-east-1:" + otherAccount + ":cluster:acct",
		"arn:aws:rds:us-east-1:" + otherAccount + ":subgrp:acct",
		"arn:aws:rds:us-east-1:" + otherAccount + ":pg:acct",
	} {
		assert.Contains(t, stateARNs, want, "/mock/state ARNs")
	}
	assert.Regexp(t, `^arn:aws:secretsmanager:us-east-1:`+otherAccount+`:secret:acct-[A-Za-z0-9]{6}$`, secret.ARN)
	var state struct {
		SSM struct{ Parameters []struct{ Name string } } `json:"ssm"`
	}
	body := mustOK(t)(doGet(t, srv, "/mock/state"))
	require.NoError(t, json.Unmarshal(body, &state))
	require.Len(t, state.SSM.Parameters, 1, "%s", body)
	assert.Equal(t, "/acct/param", state.SSM.Parameters[0].Name)
	assert.NotContains(t, string(body), awsproto.FakeAccountID)
}

// TestStoredAccount_ZonesAndBucketsListed: under a stored account a
// hosted zone and a bucket created through the API are listed by
// ListHostedZones, ListBuckets and /mock/state, and the bucket owner is
// the stored account; rows under 000000000000 in the same database are
// not listed.
func TestStoredAccount_ZonesAndBucketsListed(t *testing.T) {
	app, srv := newOptionsApp(t, handlers.Options{DBPath: ":memory:", AccountID: otherAccount})
	repo := app.Repository()
	require.NoError(t, repo.CreateBucket(awsproto.FakeAccountID, &repository.S3Bucket{Name: "default-bucket", Region: "us-east-1"}))
	require.NoError(t, repo.CreateHostedZone(awsproto.FakeAccountID, &repository.Route53HostedZone{ID: "ZDEFAULT", Name: "default.example."}))

	mustOK(t)(s3Do(t, srv, http.MethodPut, "/s3/acct-bucket/", "", ""))
	mustOK(t)(r53Request(t, srv, http.MethodPost, "/route53/2013-04-01/hostedzone",
		`<CreateHostedZoneRequest><Name>acct.example.</Name><CallerReference>acct</CallerReference></CreateHostedZoneRequest>`))

	var buckets struct {
		OwnerID string   `xml:"Owner>ID"`
		Names   []string `xml:"Buckets>Bucket>Name"`
	}
	require.NoError(t, xml.Unmarshal(mustOK(t)(s3Do(t, srv, http.MethodGet, "/s3/", "", "")), &buckets))
	assert.Equal(t, otherAccount, buckets.OwnerID)
	assert.Equal(t, []string{"acct-bucket"}, buckets.Names)

	var zones struct {
		Names []string `xml:"HostedZones>HostedZone>Name"`
	}
	require.NoError(t, xml.Unmarshal(mustOK(t)(r53Request(t, srv, http.MethodGet, "/route53/2013-04-01/hostedzone", "")), &zones))
	assert.Equal(t, []string{"acct.example."}, zones.Names)

	var state struct {
		S3      struct{ Buckets []struct{ Name string } } `json:"s3"`
		Route53 struct {
			HostedZones []struct{ Name string } `json:"hosted_zones"`
		} `json:"route53"`
	}
	body := mustOK(t)(doGet(t, srv, "/mock/state"))
	require.NoError(t, json.Unmarshal(body, &state))
	require.Len(t, state.S3.Buckets, 1, "%s", body)
	assert.Equal(t, "acct-bucket", state.S3.Buckets[0].Name)
	require.Len(t, state.Route53.HostedZones, 1, "%s", body)
	assert.Equal(t, "acct.example.", state.Route53.HostedZones[0].Name)
}

// TestStoredAccount_UnreadableIdentityIs500: with the identity table
// gone, one call per service answers 500 and never the default account.
func TestStoredAccount_UnreadableIdentityIs500(t *testing.T) {
	app, srv := newTestApp(t, ":memory:")
	_, err := app.Repository().DB().Exec(`DROP TABLE identity`)
	require.NoError(t, err)

	const region = "us-east-1"
	for service, call := range map[string]func() (*http.Response, []byte){
		"ssm":            func() (*http.Response, []byte) { return ssmCall(t, srv, "DescribeParameters", `{}`) },
		"kms":            func() (*http.Response, []byte) { return kmsCall(t, srv, region, "CreateKey", `{}`) },
		"dynamodb":       func() (*http.Response, []byte) { return ddbCall(t, srv, region, "ListTables", `{}`) },
		"secretsmanager": func() (*http.Response, []byte) { return smCall(t, srv, "ListSecrets", `{}`) },
		"sqs":            func() (*http.Response, []byte) { return sqsCall(t, srv, "ListQueues", `{}`) },
		"eks": func() (*http.Response, []byte) {
			return eksRequest(t, srv, http.MethodGet, "/eks/region/"+region+"/clusters", "")
		},
		"rds": func() (*http.Response, []byte) { return rdsCall(t, srv, region, "DescribeDBInstances", nil) },
		"route53": func() (*http.Response, []byte) {
			return r53Request(t, srv, http.MethodGet, "/route53/2013-04-01/hostedzone", "")
		},
		"s3": func() (*http.Response, []byte) { return s3Do(t, srv, http.MethodGet, "/s3/", "", "") },
	} {
		resp, body := call()
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode, "%s: %s", service, body)
		assert.NotContains(t, string(body), awsproto.FakeAccountID, service)
	}
}

// TestSetIdentity_RacesCreate races a queue create against an identity
// change on an empty database, many times: either the change is
// refused, or no row is left under the old account.
func TestSetIdentity_RacesCreate(t *testing.T) {
	app, srv := newTestApp(t, ":memory:")
	for i := range 200 {
		mustOK(t)(doPost(t, srv, "/mock/reset"))
		done := postAsync(srv, "/mock/identity", `{"account_id":"`+otherAccount+`"}`)
		mustOK(t)(sqsCall(t, srv, "CreateQueue", `{"QueueName":"race"}`))
		res := <-done
		require.NoError(t, res.err, "iteration %d", i)
		if res.status == http.StatusConflict {
			continue
		}
		require.Equal(t, http.StatusOK, res.status, "iteration %d", i)
		queues, err := app.Repository().ListSQSQueues(awsproto.FakeAccountID, "")
		require.NoError(t, err)
		require.Empty(t, queues, "iteration %d: a queue was created under the old account after the change", i)
	}
}

// TestMockReset_RacesCreate races a queue create against /mock/reset
// under a stored account, many times: no row is left under an account
// other than the one AccountID returns after the reset.
func TestMockReset_RacesCreate(t *testing.T) {
	app, srv := newTestApp(t, ":memory:")
	for i := range 200 {
		mustOK(t)(doPost(t, srv, "/mock/reset"))
		mustOK(t)(doPostJSON(t, srv, "/mock/identity", `{"account_id":"`+otherAccount+`"}`))
		done := postAsync(srv, "/mock/reset", "")
		mustOK(t)(sqsCall(t, srv, "CreateQueue", `{"QueueName":"race"}`))
		res := <-done
		require.NoError(t, res.err, "iteration %d", i)
		require.Equal(t, http.StatusOK, res.status, "iteration %d", i)
		require.Equal(t, awsproto.FakeAccountID, accountID(t, app), "iteration %d", i)
		queues, err := app.Repository().ListSQSQueues(otherAccount, "")
		require.NoError(t, err)
		require.Empty(t, queues, "iteration %d: a queue was created under the reset account", i)
	}
}

type postResult struct {
	status int
	err    error
}

// postAsync POSTs body to path on a goroutine and sends the status, or
// the error, on the returned channel, so a failure is asserted on the
// test goroutine.
func postAsync(srv *httptest.Server, path, body string) <-chan postResult {
	done := make(chan postResult, 1)
	client := *srv.Client()
	client.Timeout = 30 * time.Second
	go func() {
		resp, err := client.Post(srv.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			done <- postResult{err: err}
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		done <- postResult{status: resp.StatusCode}
	}()
	return done
}

// TestMockRestore_RacesStateAndSnapshot runs /mock/restore over and
// over while /mock/state and /mock/snapshot run beside it. Every call
// answers 200, and every state lists the bucket the live db and the
// snapshot both hold; go test -race catches a read of the db handle a
// restore is replacing.
func TestMockRestore_RacesStateAndSnapshot(t *testing.T) {
	_, srv := newTestApp(t, filepath.Join(t.TempDir(), "race.db"))
	mustOK(t)(s3Do(t, srv, http.MethodPut, "/s3/snap-bucket/", "", ""))
	mustOK(t)(doPost(t, srv, "/mock/snapshot"))

	const rounds = 30
	loop := func(path string) <-chan []postResult {
		out := make(chan []postResult, 1)
		go func() {
			var results []postResult
			for range rounds {
				results = append(results, <-postAsync(srv, path, ""))
			}
			out <- results
		}()
		return out
	}
	restores, snapshots := loop("/mock/restore"), loop("/mock/snapshot")
	for i := range rounds {
		resp, body := doGet(t, srv, "/mock/state/s3")
		require.Equal(t, http.StatusOK, resp.StatusCode, "state %d: %s", i, body)
		assert.Contains(t, string(body), `"name":"snap-bucket"`, "state %d", i)
	}
	for path, done := range map[string]<-chan []postResult{"/mock/restore": restores, "/mock/snapshot": snapshots} {
		for i, res := range <-done {
			require.NoError(t, res.err, "%s %d", path, i)
			assert.Equal(t, http.StatusOK, res.status, "%s %d", path, i)
		}
	}
}
