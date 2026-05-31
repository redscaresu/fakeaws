package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/redscaresu/fakeaws/handlers/awsproto"
	"github.com/redscaresu/fakeaws/models"
	"github.com/redscaresu/fakeaws/repository"
)

// DynamoDB dispatcher. Per fakeaws/PLAN.md § "Phase 3 — Stateful data":
// DynamoDB speaks JSON 1.1 with X-Amz-Target headers (e.g.,
// `X-Amz-Target: DynamoDB_20120810.PutItem`). Endpoint:
// /dynamodb/region/<region>.

func (app *Application) registerDynamoDBRoutes(r chi.Router) {
	r.Post("/dynamodb/region/{region}", app.handleDynamoDB)
}

func (app *Application) handleDynamoDB(w http.ResponseWriter, r *http.Request) {
	region := chi.URLParam(r, "region")
	req, err := awsproto.ParseXAmzTarget(r)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11,
			fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}
	const account = awsproto.FakeAccountID

	switch req.Operation {
	case "CreateTable":
		app.ddbCreateTable(w, account, region, req)
	case "DescribeTable":
		app.ddbDescribeTable(w, account, region, req)
	case "DeleteTable":
		app.ddbDeleteTable(w, account, region, req)
	case "PutItem":
		app.ddbPutItem(w, account, region, req)
	case "GetItem":
		app.ddbGetItem(w, account, region, req)
	case "DeleteItem":
		app.ddbDeleteItem(w, account, region, req)
	case "UpdateItem":
		app.ddbUpdateItem(w, account, region, req)
	case "Query":
		app.ddbScanOrQuery(w, account, region, req, "Query")
	case "Scan":
		app.ddbScanOrQuery(w, account, region, req, "Scan")
	// DescribeContinuousBackups + DescribeTimeToLive are read on every
	// aws_dynamodb_table refresh by terraform-provider-aws. We don't
	// track the underlying feature state — synthesise the AWS default
	// "disabled" answer so the provider read path succeeds.
	case "DescribeContinuousBackups":
		app.ddbDescribeContinuousBackups(w, account, region, req)
	case "DescribeTimeToLive":
		app.ddbDescribeTimeToLive(w, account, region, req)
	default:
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11,
			fmt.Errorf("DynamoDB operation %q not yet implemented in fakeaws v1: %w", req.Operation, models.ErrNotFound))
	}
}

// ----- Table operations -----

type ddbCreateTableInput struct {
	TableName            string             `json:"TableName"`
	AttributeDefinitions []ddbAttributeDef  `json:"AttributeDefinitions"`
	KeySchema            []ddbKeySchemaElem `json:"KeySchema"`
	BillingMode          string             `json:"BillingMode,omitempty"`
}

type ddbAttributeDef struct {
	AttributeName string `json:"AttributeName"`
	AttributeType string `json:"AttributeType"`
}

type ddbKeySchemaElem struct {
	AttributeName string `json:"AttributeName"`
	KeyType       string `json:"KeyType"` // HASH | RANGE
}

type ddbTableDescription struct {
	TableName            string                 `json:"TableName"`
	TableStatus          string                 `json:"TableStatus"`
	AttributeDefinitions []ddbAttributeDef      `json:"AttributeDefinitions"`
	KeySchema            []ddbKeySchemaElem     `json:"KeySchema"`
	BillingModeSummary   *ddbBillingModeSummary `json:"BillingModeSummary,omitempty"`
	TableArn             string                 `json:"TableArn"`
}

type ddbBillingModeSummary struct {
	BillingMode string `json:"BillingMode"`
}

func ddbTableToDescription(t *repository.DynamoDBTable) ddbTableDescription {
	d := ddbTableDescription{
		TableName:          t.Name,
		TableStatus:        t.Status,
		TableArn:           t.ARN,
		BillingModeSummary: &ddbBillingModeSummary{BillingMode: t.BillingMode},
	}
	for _, a := range t.Attributes {
		d.AttributeDefinitions = append(d.AttributeDefinitions, ddbAttributeDef{
			AttributeName: a.Name, AttributeType: a.Type,
		})
	}
	d.KeySchema = []ddbKeySchemaElem{{AttributeName: t.HashKey, KeyType: "HASH"}}
	if t.RangeKey != "" {
		d.KeySchema = append(d.KeySchema, ddbKeySchemaElem{AttributeName: t.RangeKey, KeyType: "RANGE"})
	}
	return d
}

func (app *Application) ddbCreateTable(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in ddbCreateTableInput
	if err := json.Unmarshal(req.Body, &in); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}
	if in.TableName == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, fmt.Errorf("TableName required: %w", models.ErrConflict))
		return
	}
	hashKey, rangeKey := "", ""
	for _, ks := range in.KeySchema {
		switch ks.KeyType {
		case "HASH":
			hashKey = ks.AttributeName
		case "RANGE":
			rangeKey = ks.AttributeName
		}
	}
	if hashKey == "" {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, fmt.Errorf("KeySchema must have a HASH key: %w", models.ErrConflict))
		return
	}
	attrs := make([]repository.DynamoDBAttributeDef, 0, len(in.AttributeDefinitions))
	for _, a := range in.AttributeDefinitions {
		attrs = append(attrs, repository.DynamoDBAttributeDef{Name: a.AttributeName, Type: a.AttributeType})
	}
	billing := in.BillingMode
	if billing == "" {
		billing = "PAY_PER_REQUEST"
	}
	tab := &repository.DynamoDBTable{
		Name: in.TableName, HashKey: hashKey, RangeKey: rangeKey,
		Attributes: attrs, BillingMode: billing, Status: "ACTIVE",
		Region:    region,
		ARN:       awsproto.BuildDynamoDBTableARN(region, in.TableName),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := app.repo.CreateDynamoDBTable(account, tab); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, err)
		return
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{
		"TableDescription": ddbTableToDescription(tab),
	})
}

func (app *Application) ddbDescribeTable(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		TableName string `json:"TableName"`
	}
	if err := json.Unmarshal(req.Body, &in); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}
	tab, err := app.repo.GetDynamoDBTable(account, region, in.TableName)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, err)
		return
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{
		"Table": ddbTableToDescription(tab),
	})
}

// ddbDescribeContinuousBackups returns the AWS default "DISABLED"
// status. terraform-provider-aws reads this on every aws_dynamodb_table
// refresh to populate point_in_time_recovery state; fakeaws doesn't
// track that feature flag, so the default-disabled answer is the
// correct stand-in. Real AWS also still returns 200 + DISABLED when
// PITR was never enabled, so the wire shape matches.
func (app *Application) ddbDescribeContinuousBackups(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		TableName string `json:"TableName"`
	}
	if err := json.Unmarshal(req.Body, &in); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}
	if _, err := app.repo.GetDynamoDBTable(account, region, in.TableName); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, err)
		return
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{
		"ContinuousBackupsDescription": map[string]any{
			"ContinuousBackupsStatus": "DISABLED",
			"PointInTimeRecoveryDescription": map[string]any{
				"PointInTimeRecoveryStatus": "DISABLED",
			},
		},
	})
}

// ddbDescribeTimeToLive returns the AWS default "DISABLED" TTL status.
// Same justification as DescribeContinuousBackups — refresh-path call
// the provider always makes; we don't model the feature, default-disabled
// matches real AWS behaviour when TTL was never enabled.
func (app *Application) ddbDescribeTimeToLive(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		TableName string `json:"TableName"`
	}
	if err := json.Unmarshal(req.Body, &in); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}
	if _, err := app.repo.GetDynamoDBTable(account, region, in.TableName); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, err)
		return
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{
		"TimeToLiveDescription": map[string]any{
			"TimeToLiveStatus": "DISABLED",
		},
	})
}

func (app *Application) ddbDeleteTable(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		TableName string `json:"TableName"`
	}
	json.Unmarshal(req.Body, &in)
	tab, err := app.repo.GetDynamoDBTable(account, region, in.TableName)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, err)
		return
	}
	if err := app.repo.DeleteDynamoDBTable(account, region, in.TableName); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, err)
		return
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{
		"TableDescription": ddbTableToDescription(tab),
	})
}

// ----- Item operations -----

// extractKeyValues pulls the hash + range AttributeValue strings out
// of the canonical AWS shape: {"id": {"S": "alice"}, "ts": {"N": "1"}}.
// We coerce S/N/B values to strings for the index — that's how the
// repository layer expects them. AttributeValue maps that don't have
// one of S/N/B fall back to "" (the AWS contract requires HASH/RANGE
// keys to be S, N, or B; v1 fakeaws doesn't validate beyond that).
func extractKeyValue(av map[string]json.RawMessage) string {
	for _, t := range []string{"S", "N", "B"} {
		if raw, ok := av[t]; ok {
			var s string
			if json.Unmarshal(raw, &s) == nil {
				return s
			}
		}
	}
	return ""
}

func (app *Application) ddbPutItem(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		TableName string                                `json:"TableName"`
		Item      map[string]map[string]json.RawMessage `json:"Item"`
	}
	if err := json.Unmarshal(req.Body, &in); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}
	tab, err := app.repo.GetDynamoDBTable(account, region, in.TableName)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, err)
		return
	}
	hv := extractKeyValue(in.Item[tab.HashKey])
	rv := ""
	if tab.RangeKey != "" {
		rv = extractKeyValue(in.Item[tab.RangeKey])
	}
	itemJSON, _ := json.Marshal(in.Item)
	item := &repository.DynamoDBItem{
		TableName: in.TableName, HashValue: hv, RangeValue: rv, Item: itemJSON,
	}
	if err := app.repo.PutDynamoDBItem(account, region, item); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, err)
		return
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{})
}

func (app *Application) ddbGetItem(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		TableName string                                `json:"TableName"`
		Key       map[string]map[string]json.RawMessage `json:"Key"`
	}
	if err := json.Unmarshal(req.Body, &in); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}
	tab, err := app.repo.GetDynamoDBTable(account, region, in.TableName)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, err)
		return
	}
	hv := extractKeyValue(in.Key[tab.HashKey])
	rv := ""
	if tab.RangeKey != "" {
		rv = extractKeyValue(in.Key[tab.RangeKey])
	}
	item, err := app.repo.GetDynamoDBItem(account, region, in.TableName, hv, rv)
	if err != nil {
		// AWS contract: GetItem on missing item returns 200 with
		// no Item field, NOT a 404. Special-case ErrNotFound here.
		if items, _ := app.repo.GetDynamoDBTable(account, region, in.TableName); items != nil {
			awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{})
			return
		}
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, err)
		return
	}
	var itemMap map[string]any
	if err := json.Unmarshal(item.Item, &itemMap); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, fmt.Errorf("decode stored item: %w", err))
		return
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{"Item": itemMap})
}

func (app *Application) ddbDeleteItem(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		TableName string                                `json:"TableName"`
		Key       map[string]map[string]json.RawMessage `json:"Key"`
	}
	if err := json.Unmarshal(req.Body, &in); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}
	tab, err := app.repo.GetDynamoDBTable(account, region, in.TableName)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, err)
		return
	}
	hv := extractKeyValue(in.Key[tab.HashKey])
	rv := ""
	if tab.RangeKey != "" {
		rv = extractKeyValue(in.Key[tab.RangeKey])
	}
	// DeleteItem on missing item is a no-op success per AWS contract.
	_ = app.repo.DeleteDynamoDBItem(account, region, in.TableName, hv, rv)
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{})
}

// ddbUpdateItem at v1 implements the simplest mutation: read the
// existing item, replace it with the AttributeUpdates payload, and
// write it back. UpdateExpression / ConditionExpression are NOT
// supported — concepts.md flags them as out-of-scope at v1.
func (app *Application) ddbUpdateItem(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest) {
	var in struct {
		TableName        string                                `json:"TableName"`
		Key              map[string]map[string]json.RawMessage `json:"Key"`
		AttributeUpdates map[string]map[string]json.RawMessage `json:"AttributeUpdates"`
	}
	if err := json.Unmarshal(req.Body, &in); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}
	tab, err := app.repo.GetDynamoDBTable(account, region, in.TableName)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, err)
		return
	}
	hv := extractKeyValue(in.Key[tab.HashKey])
	rv := ""
	if tab.RangeKey != "" {
		rv = extractKeyValue(in.Key[tab.RangeKey])
	}
	// Read existing or start fresh.
	merged := map[string]map[string]json.RawMessage{}
	if existing, err := app.repo.GetDynamoDBItem(account, region, in.TableName, hv, rv); err == nil {
		_ = json.Unmarshal(existing.Item, &merged)
	}
	// Re-stamp the key.
	for k, v := range in.Key {
		merged[k] = v
	}
	// Apply AttributeUpdates (each value's "Value" sub-field is the
	// new attribute value; PUT action replaces, others ignored at v1).
	for attr, payload := range in.AttributeUpdates {
		// payload looks like {"Action": "PUT", "Value": {"S": "..."}}.
		// Pull "Value" verbatim and overwrite.
		if rawVal, ok := payload["Value"]; ok {
			var av map[string]json.RawMessage
			if json.Unmarshal(rawVal, &av) == nil {
				merged[attr] = av
			}
		}
	}
	itemJSON, _ := json.Marshal(merged)
	if err := app.repo.PutDynamoDBItem(account, region, &repository.DynamoDBItem{
		TableName: in.TableName, HashValue: hv, RangeValue: rv, Item: itemJSON,
	}); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, err)
		return
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{})
}

// ddbScanOrQuery returns every item in the table. Filter expressions
// are NOT evaluated at v1 — caller post-filters in Go. Both Query
// and Scan come back as the same full-table read at this layer.
func (app *Application) ddbScanOrQuery(w http.ResponseWriter, account, region string, req awsproto.XAmzTargetRequest, op string) {
	var in struct {
		TableName string `json:"TableName"`
	}
	if err := json.Unmarshal(req.Body, &in); err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, fmt.Errorf("%w: %v", models.ErrConflict, err))
		return
	}
	items, err := app.repo.ScanDynamoDBTable(account, region, in.TableName)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, err)
		return
	}
	out := make([]map[string]any, 0, len(items))
	for _, it := range items {
		var m map[string]any
		_ = json.Unmarshal(it.Item, &m)
		out = append(out, m)
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{
		"Items": out,
		"Count": len(out),
	})
}

// gatherDynamoDBStateReal emits the dynamodb block of /mock/state.
//
// Codex pass 7 BLOCKING #2: items collection added — the table block
// alone left mutations on persisted items invisible to /mock/state,
// breaking the "every modeled collection populated" contract.
func (app *Application) gatherDynamoDBStateReal() map[string]any {
	const account = awsproto.FakeAccountID
	out := map[string]any{
		"tables": []any{},
		"items":  []any{},
	}
	tabs, _ := app.repo.ListDynamoDBTables(account, "")
	tOut := make([]map[string]any, 0, len(tabs))
	iOut := make([]map[string]any, 0)
	for _, t := range tabs {
		tOut = append(tOut, map[string]any{
			"name": t.Name, "hash_key": t.HashKey, "range_key": t.RangeKey,
			"billing_mode": t.BillingMode, "status": t.Status,
			"region": t.Region, "arn": t.ARN,
		})
		items, _ := app.repo.ScanDynamoDBTable(account, t.Region, t.Name)
		for _, it := range items {
			iOut = append(iOut, map[string]any{
				"table_name":  t.Name,
				"region":      t.Region,
				"hash_value":  it.HashValue,
				"range_value": it.RangeValue,
				"item":        json.RawMessage(it.Item),
			})
		}
	}
	out["tables"] = tOut
	out["items"] = iOut
	return out
}
