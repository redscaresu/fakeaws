package handlers

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/redscaresu/fakeaws/handlers/awsproto"
	"github.com/redscaresu/fakeaws/models"
	"github.com/redscaresu/fakeaws/repository"
)

// dbiResourceIDFor synthesises a stable RDS DbiResourceId from an
// instance identifier. Real AWS DbiResourceId is a random 21-char
// "db-<hex>" string with no relationship to the user-given
// DBInstanceIdentifier; terraform-provider-aws's Read flow uses it
// as a lookup key in some Describe* paths, so it MUST NOT be derived
// in a way that collides with the identifier. We hash the ID and
// take the first 16 hex chars after the "db-" prefix — stable
// across reads, visibly distinct from any plausible user identifier.
func dbiResourceIDFor(instanceID string) string {
	h := sha1.Sum([]byte(instanceID))
	return "db-" + strings.ToUpper(hex.EncodeToString(h[:])[:16])
}

// RDS dispatcher. Per fakeaws/PLAN.md § "Phase 3 — Stateful data":
// RDS routes at POST /rds/region/<region>. Same Query-RPC family
// as IAM/EC2; awsproto.ParseQueryRPC + WriteQueryRPCResponse carry
// over directly.

func (app *Application) registerRDSRoutes(r chi.Router) {
	r.Post("/rds/region/{region}", app.handleRDS)
}

func (app *Application) handleRDS(w http.ResponseWriter, r *http.Request) {
	region := chi.URLParam(r, "region")
	req, err := awsproto.ParseQueryRPC(r)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC,
			fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}
	const account = awsproto.FakeAccountID

	switch req.Action {
	// ----- DB Subnet Group -----
	case "CreateDBSubnetGroup":
		app.rdsCreateDBSubnetGroup(w, account, region, req)
	case "DescribeDBSubnetGroups":
		app.rdsDescribeDBSubnetGroups(w, account, region, req)
	case "DeleteDBSubnetGroup":
		app.rdsDeleteDBSubnetGroup(w, account, region, req)

	// ----- DB Parameter Group -----
	case "CreateDBParameterGroup":
		app.rdsCreateDBParameterGroup(w, account, region, req)
	case "DescribeDBParameterGroups":
		app.rdsDescribeDBParameterGroups(w, account, region, req)
	case "DeleteDBParameterGroup":
		app.rdsDeleteDBParameterGroup(w, account, region, req)

	// ----- DB Cluster Parameter Group -----
	case "CreateDBClusterParameterGroup":
		app.rdsCreateDBClusterParameterGroup(w, account, region, req)
	case "DescribeDBClusterParameterGroups":
		app.rdsDescribeDBClusterParameterGroups(w, account, region, req)
	case "DeleteDBClusterParameterGroup":
		app.rdsDeleteDBClusterParameterGroup(w, account, region, req)

	// ----- DB Cluster -----
	case "CreateDBCluster":
		app.rdsCreateDBCluster(w, account, region, req)
	case "DescribeDBClusters":
		app.rdsDescribeDBClusters(w, account, region, req)
	case "DeleteDBCluster":
		app.rdsDeleteDBCluster(w, account, region, req)

	// ----- DB Instance -----
	case "CreateDBInstance":
		app.rdsCreateDBInstance(w, account, region, req)
	case "DescribeDBInstances":
		app.rdsDescribeDBInstances(w, account, region, req)
	case "DeleteDBInstance":
		app.rdsDeleteDBInstance(w, account, region, req)
	case "ModifyDBInstance":
		app.rdsModifyDBInstance(w, account, region, req)

	case "ListTagsForResource":
		// terraform-provider-aws polls ListTagsForResource for every RDS
		// resource (DB instance, subnet group, parameter group). fakeaws
		// doesn't persist tags yet — return an empty list so the Read
		// flow doesn't error.
		awsproto.WriteQueryRPCResponse(w, "ListTagsForResource", &rdsListTagsResult{TagList: []rdsTagXML{}})

	case "DescribeDBParameters":
		// Provider's aws_db_parameter_group Read iterates all parameters
		// for diff detection. fakeaws doesn't persist per-parameter
		// values — return an empty list (the provider treats this as
		// "all parameters at family default", which is consistent with
		// a freshly-created group).
		awsproto.WriteQueryRPCResponse(w, "DescribeDBParameters", &rdsDescribeDBParametersResult{Parameters: []rdsParameterXML{}})

	default:
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC,
			fmt.Errorf("RDS action %q not yet implemented in fakeaws v1: %w", req.Action, models.ErrNotFound))
	}
}

type rdsTagXML struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

type rdsListTagsResult struct {
	TagList []rdsTagXML `xml:"TagList>Tag"`
}

type rdsParameterXML struct {
	ParameterName  string `xml:"ParameterName"`
	ParameterValue string `xml:"ParameterValue"`
}

type rdsDescribeDBParametersResult struct {
	Parameters []rdsParameterXML `xml:"Parameters>Parameter"`
}

// ----- DB Subnet Group -----

type rdsSubnetIdXML struct {
	SubnetIdentifier string `xml:"SubnetIdentifier"`
}

type rdsSubnetGroupXML struct {
	DBSubnetGroupName        string           `xml:"DBSubnetGroupName"`
	DBSubnetGroupDescription string           `xml:"DBSubnetGroupDescription"`
	VpcId                    string           `xml:"VpcId"`
	SubnetGroupStatus        string           `xml:"SubnetGroupStatus"`
	Subnets                  []rdsSubnetIdXML `xml:"Subnets>Subnet,omitempty"`
	DBSubnetGroupArn         string           `xml:"DBSubnetGroupArn"`
}

type rdsCreateSubnetGroupResult struct {
	DBSubnetGroup rdsSubnetGroupXML `xml:"DBSubnetGroup"`
}

type rdsDescribeSubnetGroupsResult struct {
	DBSubnetGroups []rdsSubnetGroupXML `xml:"DBSubnetGroups>DBSubnetGroup"`
}

func rdsSubnetGroupToXML(sg *repository.RDSSubnetGroup) rdsSubnetGroupXML {
	subnets := make([]rdsSubnetIdXML, 0, len(sg.SubnetIDs))
	for _, sid := range sg.SubnetIDs {
		subnets = append(subnets, rdsSubnetIdXML{SubnetIdentifier: sid})
	}
	return rdsSubnetGroupXML{
		DBSubnetGroupName:        sg.Name,
		DBSubnetGroupDescription: sg.Description,
		VpcId:                    sg.VPCID,
		SubnetGroupStatus:        "Complete",
		Subnets:                  subnets,
		DBSubnetGroupArn:         sg.ARN,
	}
}

func (app *Application) rdsCreateDBSubnetGroup(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	name := req.Params.Get("DBSubnetGroupName")
	desc := req.Params.Get("DBSubnetGroupDescription")
	if name == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC,
			fmt.Errorf("DBSubnetGroupName required: %w", models.ErrConflict))
		return
	}
	subnetIDs := parseSubnetIds(req)
	if len(subnetIDs) < 2 {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC,
			fmt.Errorf("at least 2 SubnetIds.<n> required: %w", models.ErrConflict))
		return
	}
	sg := &repository.RDSSubnetGroup{
		Name: name, Description: desc, SubnetIDs: subnetIDs, Region: region,
		ARN:       awsproto.BuildRDSSubnetGroupARN(region, name),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := app.repo.CreateDBSubnetGroup(account, sg); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	got, _ := app.repo.GetDBSubnetGroup(account, region, name)
	awsproto.WriteQueryRPCResponse(w, "CreateDBSubnetGroup",
		&rdsCreateSubnetGroupResult{DBSubnetGroup: rdsSubnetGroupToXML(got)})
}

func (app *Application) rdsDescribeDBSubnetGroups(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	name := req.Params.Get("DBSubnetGroupName")
	out := rdsDescribeSubnetGroupsResult{DBSubnetGroups: []rdsSubnetGroupXML{}}
	if name != "" {
		sg, err := app.repo.GetDBSubnetGroup(account, region, name)
		if err != nil {
			// Service-specific 404 code so terraform-provider-aws's
			// destroy-wait recognises "subnet group is gone" as a
			// successful deletion. The generic ResourceNotFoundException
			// bubbles out of the wait state machine as a fatal error.
			awsproto.WriteServiceError(w, awsproto.ShapeQueryRPC, http.StatusNotFound,
				"DBSubnetGroupNotFoundFault",
				fmt.Sprintf("DBSubnetGroup %s not found.", name))
			return
		}
		out.DBSubnetGroups = append(out.DBSubnetGroups, rdsSubnetGroupToXML(sg))
	}
	awsproto.WriteQueryRPCResponse(w, "DescribeDBSubnetGroups", &out)
}

func (app *Application) rdsDeleteDBSubnetGroup(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	if err := app.repo.DeleteDBSubnetGroup(account, region, req.Params.Get("DBSubnetGroupName")); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "DeleteDBSubnetGroup", nil)
}

// ----- DB Parameter Group / Cluster Parameter Group -----

type rdsParamGroupXML struct {
	DBParameterGroupName   string `xml:"DBParameterGroupName"`
	DBParameterGroupFamily string `xml:"DBParameterGroupFamily"`
	Description            string `xml:"Description"`
	DBParameterGroupArn    string `xml:"DBParameterGroupArn"`
}

type rdsClusterParamGroupXML struct {
	DBClusterParameterGroupName   string `xml:"DBClusterParameterGroupName"`
	DBParameterGroupFamily        string `xml:"DBParameterGroupFamily"`
	Description                   string `xml:"Description"`
	DBClusterParameterGroupArn    string `xml:"DBClusterParameterGroupArn"`
}

type rdsCreateParamGroupResult struct {
	DBParameterGroup rdsParamGroupXML `xml:"DBParameterGroup"`
}

type rdsDescribeParamGroupsResult struct {
	DBParameterGroups []rdsParamGroupXML `xml:"DBParameterGroups>DBParameterGroup"`
}

type rdsCreateClusterParamGroupResult struct {
	DBClusterParameterGroup rdsClusterParamGroupXML `xml:"DBClusterParameterGroup"`
}

type rdsDescribeClusterParamGroupsResult struct {
	DBClusterParameterGroups []rdsClusterParamGroupXML `xml:"DBClusterParameterGroups>DBClusterParameterGroup"`
}

func (app *Application) rdsCreateDBParameterGroup(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	name := req.Params.Get("DBParameterGroupName")
	family := req.Params.Get("DBParameterGroupFamily")
	if name == "" || family == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC,
			fmt.Errorf("DBParameterGroupName and DBParameterGroupFamily required: %w", models.ErrConflict))
		return
	}
	pg := &repository.RDSParameterGroup{
		Name: name, Family: family, Description: req.Params.Get("Description"),
		Region: region,
		ARN:    awsproto.BuildRDSParameterGroupARN(region, name),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := app.repo.CreateDBParameterGroup(account, pg); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "CreateDBParameterGroup",
		&rdsCreateParamGroupResult{DBParameterGroup: rdsParamGroupXML{
			DBParameterGroupName:   pg.Name,
			DBParameterGroupFamily: pg.Family,
			Description:            pg.Description,
			DBParameterGroupArn:    pg.ARN,
		}})
}

func (app *Application) rdsDescribeDBParameterGroups(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	name := req.Params.Get("DBParameterGroupName")
	out := rdsDescribeParamGroupsResult{DBParameterGroups: []rdsParamGroupXML{}}
	if name != "" {
		pg, err := app.repo.GetDBParameterGroup(account, region, name)
		if err != nil {
			awsproto.WriteServiceError(w, awsproto.ShapeQueryRPC, http.StatusNotFound,
				"DBParameterGroupNotFound",
				fmt.Sprintf("DBParameterGroup %s not found.", name))
			return
		}
		out.DBParameterGroups = append(out.DBParameterGroups, rdsParamGroupXML{
			DBParameterGroupName:   pg.Name,
			DBParameterGroupFamily: pg.Family,
			Description:            pg.Description,
			DBParameterGroupArn:    pg.ARN,
		})
	}
	awsproto.WriteQueryRPCResponse(w, "DescribeDBParameterGroups", &out)
}

func (app *Application) rdsDeleteDBParameterGroup(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	if err := app.repo.DeleteDBParameterGroup(account, region, req.Params.Get("DBParameterGroupName")); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "DeleteDBParameterGroup", nil)
}

func (app *Application) rdsCreateDBClusterParameterGroup(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	name := req.Params.Get("DBClusterParameterGroupName")
	family := req.Params.Get("DBParameterGroupFamily")
	if name == "" || family == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC,
			fmt.Errorf("DBClusterParameterGroupName and DBParameterGroupFamily required: %w", models.ErrConflict))
		return
	}
	pg := &repository.RDSClusterParameterGroup{
		Name: name, Family: family, Description: req.Params.Get("Description"),
		Region: region,
		ARN:    awsproto.BuildRDSClusterParameterGroupARN(region, name),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := app.repo.CreateDBClusterParameterGroup(account, pg); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "CreateDBClusterParameterGroup",
		&rdsCreateClusterParamGroupResult{DBClusterParameterGroup: rdsClusterParamGroupXML{
			DBClusterParameterGroupName: pg.Name,
			DBParameterGroupFamily:      pg.Family,
			Description:                 pg.Description,
			DBClusterParameterGroupArn:  pg.ARN,
		}})
}

func (app *Application) rdsDescribeDBClusterParameterGroups(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	name := req.Params.Get("DBClusterParameterGroupName")
	out := rdsDescribeClusterParamGroupsResult{DBClusterParameterGroups: []rdsClusterParamGroupXML{}}
	if name != "" {
		pg, err := app.repo.GetDBClusterParameterGroup(account, region, name)
		if err != nil {
			awsproto.WriteServiceError(w, awsproto.ShapeQueryRPC, http.StatusNotFound,
				"DBParameterGroupNotFound",
				fmt.Sprintf("DBClusterParameterGroup %s not found.", name))
			return
		}
		out.DBClusterParameterGroups = append(out.DBClusterParameterGroups, rdsClusterParamGroupXML{
			DBClusterParameterGroupName: pg.Name,
			DBParameterGroupFamily:      pg.Family,
			Description:                 pg.Description,
			DBClusterParameterGroupArn:  pg.ARN,
		})
	}
	awsproto.WriteQueryRPCResponse(w, "DescribeDBClusterParameterGroups", &out)
}

func (app *Application) rdsDeleteDBClusterParameterGroup(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	if err := app.repo.DeleteDBClusterParameterGroup(account, region, req.Params.Get("DBClusterParameterGroupName")); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "DeleteDBClusterParameterGroup", nil)
}

// ----- DB Cluster -----

type rdsClusterXML struct {
	DBClusterIdentifier         string `xml:"DBClusterIdentifier"`
	Engine                      string `xml:"Engine"`
	EngineVersion               string `xml:"EngineVersion,omitempty"`
	Status                      string `xml:"Status"`
	DBSubnetGroup               string `xml:"DBSubnetGroup,omitempty"`
	DBClusterParameterGroup     string `xml:"DBClusterParameterGroup,omitempty"`
	MasterUsername              string `xml:"MasterUsername,omitempty"`
	DeletionProtection          bool   `xml:"DeletionProtection"`
	DBClusterArn                string `xml:"DBClusterArn"`
}

type rdsCreateClusterResult struct {
	DBCluster rdsClusterXML `xml:"DBCluster"`
}

type rdsDescribeClustersResult struct {
	DBClusters []rdsClusterXML `xml:"DBClusters>DBCluster"`
}

func rdsClusterToXML(c *repository.RDSCluster) rdsClusterXML {
	return rdsClusterXML{
		DBClusterIdentifier:     c.ID,
		Engine:                  c.Engine,
		EngineVersion:           c.EngineVersion,
		Status:                  c.State,
		DBSubnetGroup:           c.SubnetGroupName,
		DBClusterParameterGroup: c.ClusterParameterGroupName,
		MasterUsername:          c.MasterUsername,
		DeletionProtection:      c.DeletionProtection,
		DBClusterArn:            c.ARN,
	}
}

func (app *Application) rdsCreateDBCluster(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	id := req.Params.Get("DBClusterIdentifier")
	engine := req.Params.Get("Engine")
	if id == "" || engine == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC,
			fmt.Errorf("DBClusterIdentifier and Engine required: %w", models.ErrConflict))
		return
	}
	c := &repository.RDSCluster{
		ID: id, Engine: engine,
		EngineVersion:             req.Params.Get("EngineVersion"),
		SubnetGroupName:           req.Params.Get("DBSubnetGroupName"),
		ClusterParameterGroupName: req.Params.Get("DBClusterParameterGroupName"),
		MasterUsername:            req.Params.Get("MasterUsername"),
		DeletionProtection:        req.Params.Get("DeletionProtection") == "true",
		Region:                    region,
		ARN:                       awsproto.BuildRDSClusterARN(region, id),
		CreatedAt:                 time.Now().UTC().Format(time.RFC3339),
	}
	if err := app.repo.CreateDBCluster(account, c); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	got, _ := app.repo.GetDBCluster(account, region, id)
	awsproto.WriteQueryRPCResponse(w, "CreateDBCluster",
		&rdsCreateClusterResult{DBCluster: rdsClusterToXML(got)})
}

func (app *Application) rdsDescribeDBClusters(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	id := req.Params.Get("DBClusterIdentifier")
	out := rdsDescribeClustersResult{DBClusters: []rdsClusterXML{}}
	if id != "" {
		c, err := app.repo.GetDBCluster(account, region, id)
		if err != nil {
			awsproto.WriteServiceError(w, awsproto.ShapeQueryRPC, http.StatusNotFound,
				"DBClusterNotFoundFault",
				fmt.Sprintf("DBCluster %s not found.", id))
			return
		}
		out.DBClusters = append(out.DBClusters, rdsClusterToXML(c))
	}
	awsproto.WriteQueryRPCResponse(w, "DescribeDBClusters", &out)
}

func (app *Application) rdsDeleteDBCluster(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	if err := app.repo.DeleteDBCluster(account, region, req.Params.Get("DBClusterIdentifier")); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "DeleteDBCluster", nil)
}

// ----- DB Instance -----

// rdsInstanceXML mirrors the real DescribeDBInstances/Member.DBInstance
// shape closely enough that terraform-provider-aws's aws_db_instance
// Read flow can populate state without errors. Without endpoint /
// allocated storage / master username / availability zone /
// preferred-backup-window / engine-version / port / etc., the provider
// treats the read as a "root object was present, but now absent"
// drift and bails the apply.
type rdsInstanceXML struct {
	DBInstanceIdentifier                  string             `xml:"DBInstanceIdentifier"`
	DBInstanceClass                       string             `xml:"DBInstanceClass"`
	Engine                                string             `xml:"Engine"`
	EngineVersion                         string             `xml:"EngineVersion,omitempty"`
	DBInstanceStatus                      string             `xml:"DBInstanceStatus"`
	MasterUsername                        string             `xml:"MasterUsername,omitempty"`
	DBName                                string             `xml:"DBName,omitempty"`
	Endpoint                              *rdsEndpointXML    `xml:"Endpoint,omitempty"`
	AllocatedStorage                      int                `xml:"AllocatedStorage"`
	StorageType                           string             `xml:"StorageType,omitempty"`
	StorageEncrypted                      bool               `xml:"StorageEncrypted"`
	InstanceCreateTime                    string             `xml:"InstanceCreateTime,omitempty"`
	PreferredBackupWindow                 string             `xml:"PreferredBackupWindow,omitempty"`
	BackupRetentionPeriod                 int                `xml:"BackupRetentionPeriod"`
	PreferredMaintenanceWindow            string             `xml:"PreferredMaintenanceWindow,omitempty"`
	MultiAZ                               bool               `xml:"MultiAZ"`
	AvailabilityZone                      string             `xml:"AvailabilityZone,omitempty"`
	PubliclyAccessible                    bool               `xml:"PubliclyAccessible"`
	AutoMinorVersionUpgrade               bool               `xml:"AutoMinorVersionUpgrade"`
	LicenseModel                          string             `xml:"LicenseModel,omitempty"`
	DbiResourceId                         string             `xml:"DbiResourceId,omitempty"`
	CACertificateIdentifier               string             `xml:"CACertificateIdentifier,omitempty"`
	CopyTagsToSnapshot                    bool               `xml:"CopyTagsToSnapshot"`
	IAMDatabaseAuthenticationEnabled      bool               `xml:"IAMDatabaseAuthenticationEnabled"`
	PerformanceInsightsEnabled            bool               `xml:"PerformanceInsightsEnabled"`
	DeletionProtection                    bool               `xml:"DeletionProtection"`
	DBSubnetGroup                         *rdsSubnetGroupXML `xml:"DBSubnetGroup,omitempty"`
	DBClusterIdentifier                   string             `xml:"DBClusterIdentifier,omitempty"`
	ReadReplicaSourceDBInstanceIdentifier string             `xml:"ReadReplicaSourceDBInstanceIdentifier,omitempty"`
	DBInstanceArn                         string             `xml:"DBInstanceArn"`
}

// rdsEndpointXML mirrors the DescribeDBInstances Endpoint sub-object.
// Provider reads Address+Port to populate the aws_db_instance.endpoint
// computed attribute; missing it makes the apply fail post-create.
type rdsEndpointXML struct {
	Address      string `xml:"Address"`
	Port         int    `xml:"Port"`
	HostedZoneId string `xml:"HostedZoneId,omitempty"`
}

type rdsCreateInstanceResult struct {
	DBInstance rdsInstanceXML `xml:"DBInstance"`
}

type rdsDescribeInstancesResult struct {
	DBInstances []rdsInstanceXML `xml:"DBInstances>DBInstance"`
}

func (app *Application) rdsInstanceToXML(account string, inst *repository.RDSInstance) rdsInstanceXML {
	// Echo persisted values; fall back to safe defaults only when
	// the user didn't supply them. Hard-coding any field that the
	// HCL also sets forces terraform-provider-aws to detect drift
	// on plan and trigger a replacement (e.g. before this change
	// MasterUsername was always "fakeaws" → plan showed
	// `username "fakeaws" -> "appuser" # forces replacement`).
	masterUser := inst.MasterUsername
	if masterUser == "" {
		masterUser = "fakeaws"
	}
	allocated := inst.AllocatedStorage
	if allocated == 0 {
		allocated = 20
	}
	storageType := inst.StorageType
	if storageType == "" {
		storageType = "gp2"
	}
	port := inst.Port
	if port == 0 {
		port = 5432
	}
	x := rdsInstanceXML{
		DBInstanceIdentifier:                  inst.ID,
		Engine:                                inst.Engine,
		EngineVersion:                         inst.EngineVersion,
		DBInstanceClass:                       inst.InstanceClass,
		DBInstanceStatus:                      inst.State,
		MasterUsername:                        masterUser,
		AllocatedStorage:                      allocated,
		StorageType:                           storageType,
		StorageEncrypted:                      inst.StorageEncrypted,
		InstanceCreateTime:                    inst.CreatedAt,
		PreferredBackupWindow:                 "07:00-08:00",
		BackupRetentionPeriod:                 inst.BackupRetentionPeriod,
		PreferredMaintenanceWindow:            "sun:08:00-sun:09:00",
		MultiAZ:                               inst.MultiAZ,
		AvailabilityZone:                      inst.Region + "a",
		PubliclyAccessible:                    inst.PubliclyAccessible,
		AutoMinorVersionUpgrade:               true,
		LicenseModel:                          "postgresql-license",
		// DbiResourceId must NOT be a derivative of DBInstanceIdentifier.
		// terraform-provider-aws's aws_db_instance Read flow has a code
		// path that uses DbiResourceId as a lookup key in some Describe
		// calls. If we return e.g. "db-test-db" for an instance named
		// "test-db", the provider issues a follow-up
		// DescribeDBInstances?DBInstanceIdentifier=db-test-db, gets 404
		// (because that's not the identifier), and treats the resource
		// as gone → "reading RDS DB Instance: ResourceNotFoundException".
		// Real AWS DbiResourceId is a random 21-char identifier
		// (e.g. db-ABCDEFG1234567890123) with no relationship to the
		// user-given DBInstanceIdentifier. We synthesise the same shape
		// from the SHA-1 of the instance ID so it's stable across reads
		// but visibly distinct from the identifier.
		DbiResourceId: dbiResourceIDFor(inst.ID),
		CACertificateIdentifier:               "rds-ca-rsa2048-g1",
		CopyTagsToSnapshot:                    false,
		IAMDatabaseAuthenticationEnabled:      false,
		PerformanceInsightsEnabled:            false,
		DBClusterIdentifier:                   inst.ClusterID,
		ReadReplicaSourceDBInstanceIdentifier: inst.ReplicateSourceDB,
		DeletionProtection:                    inst.DeletionProtection,
		DBInstanceArn:                         inst.ARN,
		Endpoint: &rdsEndpointXML{
			Address: fmt.Sprintf("%s.fakeaws.local", inst.ID),
			Port:    port,
		},
	}
	if inst.SubnetGroupName != "" {
		if sg, err := app.repo.GetDBSubnetGroup(account, inst.Region, inst.SubnetGroupName); err == nil {
			sgXML := rdsSubnetGroupToXML(sg)
			x.DBSubnetGroup = &sgXML
		}
	}
	return x
}

func (app *Application) rdsCreateDBInstance(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	id := req.Params.Get("DBInstanceIdentifier")
	engine := req.Params.Get("Engine")
	class := req.Params.Get("DBInstanceClass")
	if id == "" || engine == "" || class == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC,
			fmt.Errorf("DBInstanceIdentifier, Engine, DBInstanceClass required: %w", models.ErrConflict))
		return
	}
	inst := &repository.RDSInstance{
		ID: id, Engine: engine, EngineVersion: req.Params.Get("EngineVersion"),
		InstanceClass:       class,
		SubnetGroupName:     req.Params.Get("DBSubnetGroupName"),
		ClusterID:           req.Params.Get("DBClusterIdentifier"),
		ParameterGroupName:  req.Params.Get("DBParameterGroupName"),
		ReplicateSourceDB:   req.Params.Get("ReplicateSourceDB"),
		DeletionProtection:  req.Params.Get("DeletionProtection") == "true",
		SkipFinalSnapshot:   req.Params.Get("SkipFinalSnapshot") != "false",
		Region:              region,
		ARN:                 awsproto.BuildRDSDBARN(region, id),
		CreatedAt:           time.Now().UTC().Format(time.RFC3339),
		// Persist user-supplied values so Read echoes them back
		// verbatim — see rdsInstanceToXML's comment about plan
		// drift / replacement.
		MasterUsername:        req.Params.Get("MasterUsername"),
		AllocatedStorage:      atoiOrZero(req.Params.Get("AllocatedStorage")),
		StorageType:           req.Params.Get("StorageType"),
		StorageEncrypted:      req.Params.Get("StorageEncrypted") == "true",
		MultiAZ:               req.Params.Get("MultiAZ") == "true",
		Port:                  atoiOrZero(req.Params.Get("Port")),
		PubliclyAccessible:    req.Params.Get("PubliclyAccessible") == "true",
		BackupRetentionPeriod: atoiOrZero(req.Params.Get("BackupRetentionPeriod")),
		Tags:                  parseRDSTags(req),
	}
	if err := app.repo.CreateDBInstance(account, inst); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	got, _ := app.repo.GetDBInstance(account, region, id)
	awsproto.WriteQueryRPCResponse(w, "CreateDBInstance",
		&rdsCreateInstanceResult{DBInstance: app.rdsInstanceToXML(account, got)})
}

func (app *Application) rdsDescribeDBInstances(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	id := req.Params.Get("DBInstanceIdentifier")
	out := rdsDescribeInstancesResult{DBInstances: []rdsInstanceXML{}}

	// terraform-provider-aws's refresh & wait paths sometimes use
	// Filters.Filter.N.Name=dbi-resource-id&Filters.Filter.N.Values.Value.M=<id>
	// in place of the direct DBInstanceIdentifier param. We must
	// resolve those to the underlying instance; otherwise the
	// unfiltered fall-through path returns all instances, the
	// provider sees zero matches, and treats the resource as gone.
	filterName, filterValues := parseRDSFilter(req, "dbi-resource-id")

	if id != "" {
		inst, err := app.repo.GetDBInstance(account, region, id)
		if err != nil {
			rdsWriteInstanceNotFound(w, id, err)
			return
		}
		out.DBInstances = append(out.DBInstances, app.rdsInstanceToXML(account, inst))
	} else if filterName == "dbi-resource-id" && len(filterValues) > 0 {
		all, err := app.repo.ListDBInstances(account, region)
		if err != nil {
			awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
			return
		}
		want := make(map[string]struct{}, len(filterValues))
		for _, v := range filterValues {
			want[v] = struct{}{}
		}
		for _, inst := range all {
			if _, ok := want[dbiResourceIDFor(inst.ID)]; ok {
				out.DBInstances = append(out.DBInstances, app.rdsInstanceToXML(account, inst))
			}
		}
		if len(out.DBInstances) == 0 {
			rdsWriteInstanceNotFound(w, filterValues[0], nil)
			return
		}
	} else {
		// Unfiltered list (uncommon but the AWS provider's import path uses it).
		all, err := app.repo.ListDBInstances(account, region)
		if err != nil {
			awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
			return
		}
		for _, inst := range all {
			out.DBInstances = append(out.DBInstances, app.rdsInstanceToXML(account, inst))
		}
	}
	awsproto.WriteQueryRPCResponse(w, "DescribeDBInstances", &out)
}

// rdsWriteInstanceNotFound emits the RDS-specific
// "DBInstanceNotFound" error code (HTTP 404) the SDK & terraform-
// provider-aws's delete-wait state machine actually checks for.
// Returning the generic ResourceNotFoundException bubbles out of
// the wait as a hard error and breaks destroy.
func rdsWriteInstanceNotFound(w http.ResponseWriter, id string, _ error) {
	awsproto.WriteServiceError(w, awsproto.ShapeQueryRPC, http.StatusNotFound,
		"DBInstanceNotFound",
		fmt.Sprintf("DBInstance %s not found.", id))
}

func (app *Application) rdsDeleteDBInstance(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	id := req.Params.Get("DBInstanceIdentifier")
	// Real RDS DeleteDBInstance returns the instance in "deleting"
	// state inside a <DeleteDBInstanceResult><DBInstance>...</...>
	// envelope. Returning a bare envelope (nil payload) errors the
	// SDK with "DeleteDBInstanceResult node not found, failed to
	// decode response body" — read the instance BEFORE deletion,
	// mutate status to "deleting", then run the delete and emit the
	// snapshot.
	inst, err := app.repo.GetDBInstance(account, region, id)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	if err := app.repo.DeleteDBInstance(account, region, id); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	deleting := app.rdsInstanceToXML(account, inst)
	deleting.DBInstanceStatus = "deleting"
	awsproto.WriteQueryRPCResponse(w, "DeleteDBInstance",
		&rdsDeleteInstanceResult{DBInstance: deleting})
}

// rdsDeleteInstanceResult is the DeleteDBInstance response payload
// shape. Real RDS wraps the snapshot of the deleting instance in
// <DeleteDBInstanceResult><DBInstance>...</DBInstance></...>; SDK
// fails to deserialise if the inner wrapper is missing.
type rdsDeleteInstanceResult struct {
	DBInstance rdsInstanceXML `xml:"DBInstance"`
}

// rdsModifyDBInstance is intentionally minimal at v1 — handlers
// surface "instance exists" semantics so the AWS provider's refresh
// path doesn't 404. Apply-time changes (engine version, instance
// class) are no-ops; the deletion_protection toggle is the one
// modification that matters for destroy flows.
func (app *Application) rdsModifyDBInstance(w http.ResponseWriter, account, region string, req awsproto.QueryRPCRequest) {
	id := req.Params.Get("DBInstanceIdentifier")
	if id == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC,
			fmt.Errorf("DBInstanceIdentifier required: %w", models.ErrConflict))
		return
	}
	inst, err := app.repo.GetDBInstance(account, region, id)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeQueryRPC, err)
		return
	}
	awsproto.WriteQueryRPCResponse(w, "ModifyDBInstance",
		&rdsCreateInstanceResult{DBInstance: app.rdsInstanceToXML(account, inst)})
}

// ----- helpers -----

// parseSubnetIds reads SubnetIds.member.<n> params (the AWS
// Query-RPC list shape — RDS uses .member., not the bare .<n>
// EC2 uses).
func parseSubnetIds(req awsproto.QueryRPCRequest) []string {
	var out []string
	for k, vs := range req.Params {
		if strings.HasPrefix(k, "SubnetIds.") && len(vs) > 0 {
			out = append(out, vs[0])
		}
	}
	return out
}

// atoiOrZero is a tiny helper to convert numeric query params
// without panicking on empty input. Returns 0 on parse failure
// so the caller can apply its own default downstream.
func atoiOrZero(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// parseRDSTags reads Tags.Tag.N.Key / Tags.Tag.N.Value params
// from the Query-RPC form (CreateDBInstance puts user tags here)
// into a flat map. Returns nil when no tags are present so the
// JSON blob stays compact.
func parseRDSTags(req awsproto.QueryRPCRequest) map[string]string {
	out := map[string]string{}
	for k, vs := range req.Params {
		if !strings.HasPrefix(k, "Tags.Tag.") || !strings.HasSuffix(k, ".Key") {
			continue
		}
		if len(vs) == 0 {
			continue
		}
		// Tags.Tag.1.Key → Tags.Tag.1.Value
		idx := strings.TrimSuffix(strings.TrimPrefix(k, "Tags.Tag."), ".Key")
		val := req.Params.Get("Tags.Tag." + idx + ".Value")
		out[vs[0]] = val
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseRDSFilter scans Filters.Filter.N.Name / Filters.Filter.N.Values.Value.M
// params for a filter whose name matches `want` and returns its
// values. Used by DescribeDBInstances to resolve the
// dbi-resource-id lookup terraform-provider-aws issues after some
// Create/Refresh calls. Returns ("", nil) when no matching filter
// is present.
func parseRDSFilter(req awsproto.QueryRPCRequest, want string) (string, []string) {
	for k, vs := range req.Params {
		if !strings.HasPrefix(k, "Filters.Filter.") || !strings.HasSuffix(k, ".Name") {
			continue
		}
		if len(vs) == 0 || vs[0] != want {
			continue
		}
		idx := strings.TrimSuffix(strings.TrimPrefix(k, "Filters.Filter."), ".Name")
		prefix := "Filters.Filter." + idx + ".Values.Value."
		var values []string
		for vk, vv := range req.Params {
			if strings.HasPrefix(vk, prefix) && len(vv) > 0 {
				values = append(values, vv[0])
			}
		}
		return want, values
	}
	return "", nil
}

// gatherRDSStateReal emits the RDS block of /mock/state.
//
// Codex pass 4 BLOCKING #2 fix: every modeled collection is populated
// directly from a list path on the repo (was previously inferred
// from instance metadata, missing standalone groups).
func (app *Application) gatherRDSStateReal() map[string]any {
	const account = awsproto.FakeAccountID
	out := map[string]any{
		"db_instances":                []any{},
		"db_clusters":                 []any{},
		"db_subnet_groups":            []any{},
		"db_parameter_groups":         []any{},
		"db_cluster_parameter_groups": []any{},
	}
	instances, _ := app.repo.ListDBInstances(account, "")
	iOut := make([]map[string]any, 0, len(instances))
	for _, inst := range instances {
		iOut = append(iOut, map[string]any{
			"id": inst.ID, "engine": inst.Engine,
			"instance_class":      inst.InstanceClass,
			"subnet_group_name":   inst.SubnetGroupName,
			"replicate_source_db": inst.ReplicateSourceDB,
			"state":               inst.State, "region": inst.Region, "arn": inst.ARN,
		})
	}
	out["db_instances"] = iOut

	sgs, _ := app.repo.ListDBSubnetGroups(account)
	sgOut := make([]map[string]any, 0, len(sgs))
	for _, sg := range sgs {
		sgOut = append(sgOut, map[string]any{
			"name": sg.Name, "vpc_id": sg.VPCID, "subnet_ids": sg.SubnetIDs,
			"region": sg.Region, "arn": sg.ARN,
		})
	}
	out["db_subnet_groups"] = sgOut

	pgs, _ := app.repo.ListDBParameterGroups(account)
	pgOut := make([]map[string]any, 0, len(pgs))
	for _, pg := range pgs {
		pgOut = append(pgOut, map[string]any{
			"name": pg.Name, "family": pg.Family, "region": pg.Region, "arn": pg.ARN,
		})
	}
	out["db_parameter_groups"] = pgOut

	cpgs, _ := app.repo.ListDBClusterParameterGroups(account)
	cpgOut := make([]map[string]any, 0, len(cpgs))
	for _, pg := range cpgs {
		cpgOut = append(cpgOut, map[string]any{
			"name": pg.Name, "family": pg.Family, "region": pg.Region, "arn": pg.ARN,
		})
	}
	out["db_cluster_parameter_groups"] = cpgOut

	clusters, _ := app.repo.ListDBClusters(account, "")
	cOut := make([]map[string]any, 0, len(clusters))
	for _, c := range clusters {
		cOut = append(cOut, map[string]any{
			"id": c.ID, "engine": c.Engine, "engine_version": c.EngineVersion,
			"state": c.State, "region": c.Region, "arn": c.ARN,
		})
	}
	out["db_clusters"] = cOut

	return out
}
