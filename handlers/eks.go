package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/redscaresu/fakeaws/handlers/awsproto"
	"github.com/redscaresu/fakeaws/models"
	"github.com/redscaresu/fakeaws/repository"
)

// EKS handlers. Per fakeaws/PLAN.md § "Phase 4 — Containers + queues":
// EKS speaks JSON-REST (path-routed, application/json, no x-amz-target).
// Endpoint convention mirrors AWS:
//   POST   /eks/region/<region>/clusters
//   GET    /eks/region/<region>/clusters/<name>
//   DELETE /eks/region/<region>/clusters/<name>
//   POST   /eks/region/<region>/clusters/<name>/node-groups
//   GET    /eks/region/<region>/clusters/<name>/node-groups/<ng>
//   DELETE /eks/region/<region>/clusters/<name>/node-groups/<ng>
//   POST   /eks/region/<region>/clusters/<name>/addons
//   ...

func (app *Application) registerEKSRoutes(r chi.Router) {
	r.Route("/eks/region/{region}/clusters", func(r chi.Router) {
		r.Post("/", app.eksCreateCluster)
		r.Get("/", app.eksListClusters)
		r.Get("/{name}", app.eksDescribeCluster)
		r.Delete("/{name}", app.eksDeleteCluster)
		r.Post("/{name}/node-groups", app.eksCreateNodeGroup)
		r.Get("/{name}/node-groups/{ng}", app.eksDescribeNodeGroup)
		r.Delete("/{name}/node-groups/{ng}", app.eksDeleteNodeGroup)
		r.Post("/{name}/addons", app.eksCreateAddon)
		r.Get("/{name}/addons/{addon}", app.eksDescribeAddon)
		r.Delete("/{name}/addons/{addon}", app.eksDeleteAddon)
	})
}

// ----- Cluster -----

type eksCreateClusterInput struct {
	Name              string         `json:"name"`
	RoleArn           string         `json:"roleArn"`
	ResourcesVpcConfig eksVpcConfig  `json:"resourcesVpcConfig"`
	Version           string         `json:"version,omitempty"`
}

type eksVpcConfig struct {
	SubnetIds        []string `json:"subnetIds"`
	SecurityGroupIds []string `json:"securityGroupIds,omitempty"`
}

type eksClusterDescription struct {
	Name              string       `json:"name"`
	Arn               string       `json:"arn"`
	RoleArn           string       `json:"roleArn"`
	Status            string       `json:"status"`
	Version           string       `json:"version,omitempty"`
	ResourcesVpcConfig eksVpcConfig `json:"resourcesVpcConfig"`
	CreatedAt         string       `json:"createdAt"`
}

func eksClusterToDescription(c *repository.EKSCluster) eksClusterDescription {
	return eksClusterDescription{
		Name: c.Name, Arn: c.ARN, RoleArn: c.RoleARN, Status: c.Status,
		Version: c.KubernetesVersion,
		ResourcesVpcConfig: eksVpcConfig{
			SubnetIds: c.SubnetIDs, SecurityGroupIds: c.SecurityGroupIDs,
		},
		CreatedAt: c.CreatedAt,
	}
}

func (app *Application) eksCreateCluster(w http.ResponseWriter, r *http.Request) {
	region := chi.URLParam(r, "region")
	const account = awsproto.FakeAccountID
	var in eksCreateClusterInput
	if _, err := awsproto.DecodeJSONBody(r, &in); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSONREST, fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}
	if in.Name == "" || in.RoleArn == "" || len(in.ResourcesVpcConfig.SubnetIds) == 0 {
		awsproto.WriteAWSError(w, awsproto.ShapeJSONREST,
			fmt.Errorf("name, roleArn, resourcesVpcConfig.subnetIds required: %w", models.ErrConflict))
		return
	}
	c := &repository.EKSCluster{
		Name: in.Name, RoleARN: in.RoleArn,
		SubnetIDs: in.ResourcesVpcConfig.SubnetIds,
		SecurityGroupIDs: in.ResourcesVpcConfig.SecurityGroupIds,
		KubernetesVersion: in.Version,
		Status: "ACTIVE", Region: region,
		ARN: awsproto.BuildEKSClusterARN(region, in.Name),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := app.repo.CreateEKSCluster(account, c); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSONREST, err)
		return
	}
	awsproto.WriteJSONRESTResponse(w, http.StatusOK, map[string]any{
		"cluster": eksClusterToDescription(c),
	})
}

func (app *Application) eksDescribeCluster(w http.ResponseWriter, r *http.Request) {
	const account = awsproto.FakeAccountID
	c, err := app.repo.GetEKSCluster(account, chi.URLParam(r, "region"), chi.URLParam(r, "name"))
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSONREST, err)
		return
	}
	awsproto.WriteJSONRESTResponse(w, http.StatusOK, map[string]any{
		"cluster": eksClusterToDescription(c),
	})
}

func (app *Application) eksListClusters(w http.ResponseWriter, r *http.Request) {
	region := chi.URLParam(r, "region")
	const account = awsproto.FakeAccountID
	clusters, err := app.repo.ListEKSClusters(account, region)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSONREST, err)
		return
	}
	names := make([]string, 0, len(clusters))
	for _, c := range clusters {
		names = append(names, c.Name)
	}
	awsproto.WriteJSONRESTResponse(w, http.StatusOK, map[string]any{
		"clusters": names,
	})
}

func (app *Application) eksDeleteCluster(w http.ResponseWriter, r *http.Request) {
	const account = awsproto.FakeAccountID
	region := chi.URLParam(r, "region")
	name := chi.URLParam(r, "name")
	c, err := app.repo.GetEKSCluster(account, region, name)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSONREST, err)
		return
	}
	if err := app.repo.DeleteEKSCluster(account, region, name); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSONREST, err)
		return
	}
	awsproto.WriteJSONRESTResponse(w, http.StatusOK, map[string]any{
		"cluster": eksClusterToDescription(c),
	})
}

// ----- NodeGroup -----

type eksCreateNodeGroupInput struct {
	NodegroupName string                 `json:"nodegroupName"`
	NodeRole      string                 `json:"nodeRole"`
	Subnets       []string               `json:"subnets"`
	InstanceTypes []string               `json:"instanceTypes,omitempty"`
	ScalingConfig map[string]json.Number `json:"scalingConfig,omitempty"`
}

type eksNodeGroupDescription struct {
	NodegroupName string   `json:"nodegroupName"`
	ClusterName   string   `json:"clusterName"`
	NodegroupArn  string   `json:"nodegroupArn"`
	NodeRole      string   `json:"nodeRole"`
	Subnets       []string `json:"subnets"`
	InstanceTypes []string `json:"instanceTypes,omitempty"`
	Status        string   `json:"status"`
	CreatedAt     string   `json:"createdAt"`
}

func (app *Application) eksCreateNodeGroup(w http.ResponseWriter, r *http.Request) {
	region := chi.URLParam(r, "region")
	clusterName := chi.URLParam(r, "name")
	const account = awsproto.FakeAccountID
	var in eksCreateNodeGroupInput
	if _, err := awsproto.DecodeJSONBody(r, &in); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSONREST, fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}
	if in.NodegroupName == "" || in.NodeRole == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeJSONREST,
			fmt.Errorf("nodegroupName and nodeRole required: %w", models.ErrConflict))
		return
	}
	scalingJSON := "{}"
	if in.ScalingConfig != nil {
		b, _ := json.Marshal(in.ScalingConfig)
		scalingJSON = string(b)
	}
	ng := &repository.EKSNodeGroup{
		ClusterName: clusterName, Name: in.NodegroupName,
		NodeRoleARN: in.NodeRole, SubnetIDs: in.Subnets,
		InstanceTypes: in.InstanceTypes, ScalingConfig: scalingJSON,
		Status: "ACTIVE", Region: region,
		ARN: awsproto.BuildEKSNodegroupARN(region, clusterName, in.NodegroupName, "deterministic"),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := app.repo.CreateEKSNodeGroup(account, ng); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSONREST, err)
		return
	}
	awsproto.WriteJSONRESTResponse(w, http.StatusOK, map[string]any{
		"nodegroup": eksNodeGroupToDesc(ng),
	})
}

func eksNodeGroupToDesc(ng *repository.EKSNodeGroup) eksNodeGroupDescription {
	return eksNodeGroupDescription{
		NodegroupName: ng.Name, ClusterName: ng.ClusterName,
		NodegroupArn: ng.ARN, NodeRole: ng.NodeRoleARN,
		Subnets: ng.SubnetIDs, InstanceTypes: ng.InstanceTypes,
		Status: ng.Status, CreatedAt: ng.CreatedAt,
	}
}

func (app *Application) eksDescribeNodeGroup(w http.ResponseWriter, r *http.Request) {
	const account = awsproto.FakeAccountID
	ng, err := app.repo.GetEKSNodeGroup(account, chi.URLParam(r, "region"), chi.URLParam(r, "name"), chi.URLParam(r, "ng"))
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSONREST, err)
		return
	}
	awsproto.WriteJSONRESTResponse(w, http.StatusOK, map[string]any{
		"nodegroup": eksNodeGroupToDesc(ng),
	})
}

func (app *Application) eksDeleteNodeGroup(w http.ResponseWriter, r *http.Request) {
	const account = awsproto.FakeAccountID
	region := chi.URLParam(r, "region")
	clusterName := chi.URLParam(r, "name")
	ngName := chi.URLParam(r, "ng")
	ng, err := app.repo.GetEKSNodeGroup(account, region, clusterName, ngName)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSONREST, err)
		return
	}
	if err := app.repo.DeleteEKSNodeGroup(account, region, clusterName, ngName); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSONREST, err)
		return
	}
	awsproto.WriteJSONRESTResponse(w, http.StatusOK, map[string]any{
		"nodegroup": eksNodeGroupToDesc(ng),
	})
}

// ----- Addon -----

type eksCreateAddonInput struct {
	AddonName    string `json:"addonName"`
	AddonVersion string `json:"addonVersion,omitempty"`
}

type eksAddonDescription struct {
	AddonName    string `json:"addonName"`
	ClusterName  string `json:"clusterName"`
	AddonArn     string `json:"addonArn"`
	AddonVersion string `json:"addonVersion,omitempty"`
	Status       string `json:"status"`
	CreatedAt    string `json:"createdAt"`
}

func (app *Application) eksCreateAddon(w http.ResponseWriter, r *http.Request) {
	region := chi.URLParam(r, "region")
	clusterName := chi.URLParam(r, "name")
	const account = awsproto.FakeAccountID
	var in eksCreateAddonInput
	if _, err := awsproto.DecodeJSONBody(r, &in); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSONREST, fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}
	if in.AddonName == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeJSONREST,
			fmt.Errorf("addonName required: %w", models.ErrConflict))
		return
	}
	a := &repository.EKSAddon{
		ClusterName: clusterName, Name: in.AddonName, Version: in.AddonVersion,
		Status: "ACTIVE", Region: region,
		ARN: fmt.Sprintf("arn:aws:eks:%s:%s:addon/%s/%s/uuid", region, awsproto.FakeAccountID, clusterName, in.AddonName),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := app.repo.CreateEKSAddon(account, a); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSONREST, err)
		return
	}
	awsproto.WriteJSONRESTResponse(w, http.StatusOK, map[string]any{
		"addon": eksAddonToDesc(a),
	})
}

func eksAddonToDesc(a *repository.EKSAddon) eksAddonDescription {
	return eksAddonDescription{
		AddonName: a.Name, ClusterName: a.ClusterName, AddonArn: a.ARN,
		AddonVersion: a.Version, Status: a.Status, CreatedAt: a.CreatedAt,
	}
}

func (app *Application) eksDescribeAddon(w http.ResponseWriter, r *http.Request) {
	const account = awsproto.FakeAccountID
	a, err := app.repo.GetEKSAddon(account, chi.URLParam(r, "region"), chi.URLParam(r, "name"), chi.URLParam(r, "addon"))
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSONREST, err)
		return
	}
	awsproto.WriteJSONRESTResponse(w, http.StatusOK, map[string]any{
		"addon": eksAddonToDesc(a),
	})
}

func (app *Application) eksDeleteAddon(w http.ResponseWriter, r *http.Request) {
	const account = awsproto.FakeAccountID
	region := chi.URLParam(r, "region")
	clusterName := chi.URLParam(r, "name")
	addonName := chi.URLParam(r, "addon")
	a, err := app.repo.GetEKSAddon(account, region, clusterName, addonName)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSONREST, err)
		return
	}
	if err := app.repo.DeleteEKSAddon(account, region, clusterName, addonName); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSONREST, err)
		return
	}
	awsproto.WriteJSONRESTResponse(w, http.StatusOK, map[string]any{
		"addon": eksAddonToDesc(a),
	})
}

// ----- /mock/state gather -----

// gatherEKSStateReal emits the EKS block of /mock/state.
//
// Codex pass 3 BLOCKING #2 fix: clusters now also surface their
// nodegroups + addons (was previously only emitting clusters).
func (app *Application) gatherEKSStateReal() map[string]any {
	const account = awsproto.FakeAccountID
	out := map[string]any{
		"clusters":    []any{},
		"node_groups": []any{},
		"addons":      []any{},
	}
	clusters, _ := app.repo.ListEKSClusters(account, "")
	cOut := make([]map[string]any, 0, len(clusters))
	for _, c := range clusters {
		// Codex pass 15 BLOCKING #2: include security_group_ids and
		// kubernetes_version so cluster modifications surface in
		// /mock/state. Both are modeled persistent fields.
		cOut = append(cOut, map[string]any{
			"name": c.Name, "role_arn": c.RoleARN, "status": c.Status,
			"region": c.Region, "arn": c.ARN, "subnet_ids": c.SubnetIDs,
			"security_group_ids": c.SecurityGroupIDs,
			"kubernetes_version": c.KubernetesVersion,
		})
	}
	out["clusters"] = cOut
	// Codex pass 5 SUGGEST fix: use proper repository List methods
	// instead of raw nested queries. The previous implementation
	// risked deadlock under SetMaxOpenConns(1) by holding `rows`
	// open while issuing nested Get* queries on the same connection.
	ngs, _ := app.repo.ListEKSNodeGroups(account, "", "")
	ngOut := make([]map[string]any, 0, len(ngs))
	for _, ng := range ngs {
		// Codex pass 15 BLOCKING #2: include instance_types and
		// scaling_config — both define the nodegroup's operational
		// shape and were silently dropped from /mock/state.
		entry := map[string]any{
			"cluster_name": ng.ClusterName, "name": ng.Name,
			"node_role_arn":  ng.NodeRoleARN,
			"subnet_ids":     ng.SubnetIDs,
			"instance_types": ng.InstanceTypes,
			"status":         ng.Status,
			"region":         ng.Region,
			"arn":            ng.ARN,
		}
		if ng.ScalingConfig != "" {
			var sc any
			if err := json.Unmarshal([]byte(ng.ScalingConfig), &sc); err == nil {
				entry["scaling_config"] = sc
			} else {
				entry["scaling_config"] = ng.ScalingConfig
			}
		}
		ngOut = append(ngOut, entry)
	}
	addons, _ := app.repo.ListEKSAddons(account, "", "")
	addOut := make([]map[string]any, 0, len(addons))
	for _, a := range addons {
		addOut = append(addOut, map[string]any{
			"cluster_name": a.ClusterName, "name": a.Name, "version": a.Version,
			"status": a.Status, "region": a.Region, "arn": a.ARN,
		})
	}
	out["node_groups"] = ngOut
	out["addons"] = addOut
	return out
}

// ensure the strings import is used by something.
var _ = strings.HasPrefix
