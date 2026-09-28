package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/redscaresu/fakeaws/handlers/awsproto"
	"github.com/redscaresu/fakeaws/models"
	"github.com/redscaresu/fakeaws/repository"
)

// SSM Parameter Store dispatcher: JSON 1.1 with
// `X-Amz-Target: AmazonSSM.<Operation>` at /ssm/region/<region>. It
// models what aws_ssm_parameter (resource and data source) calls at
// hashicorp/aws 5.100.0; every other operation answers 501.

// al2023ParameterName is the read-only AWS public parameter naming the
// latest Amazon Linux 2023 AMI. It resolves to AL2023AMIID in every
// region and is never stored, so it is not listed or deletable.
const al2023ParameterName = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"

var ssmParameterTypes = []string{"String", "StringList", "SecureString"}

func (app *Application) registerSSMRoutes(r chi.Router) {
	r.Post("/ssm/region/{region}", app.handleSSM)
}

func (app *Application) handleSSM(w http.ResponseWriter, r *http.Request) {
	region := chi.URLParam(r, "region")
	req, err := awsproto.ParseXAmzTarget(r)
	if err != nil {
		ssmError(w, "ValidationException", err.Error())
		return
	}
	switch req.Operation {
	case "PutParameter":
		app.ssmPutParameter(w, region, req.Body)
	case "GetParameter":
		app.ssmGetParameter(w, region, req.Body)
	case "DescribeParameters":
		app.ssmDescribeParameters(w, region, req.Body)
	case "DeleteParameter":
		app.ssmDeleteParameter(w, region, req.Body)
	case "ListTagsForResource":
		app.ssmListTagsForResource(w, region, req.Body)
	case "AddTagsToResource", "RemoveTagsFromResource":
		app.ssmChangeTags(w, region, req.Operation, req.Body)
	default:
		writeUnimplemented(w, "POST /ssm X-Amz-Target="+req.Target)
	}
}

// ssmError writes an SSM client error. SSM answers all of them 400.
func ssmError(w http.ResponseWriter, code, message string) {
	awsproto.WriteServiceError(w, awsproto.ShapeJSON11, http.StatusBadRequest, code, message)
}

// ssmDecode unmarshals body into dst and answers ValidationException
// when it cannot.
func ssmDecode(w http.ResponseWriter, body []byte, dst any) bool {
	if err := json.Unmarshal(body, dst); err != nil {
		ssmError(w, "ValidationException", "invalid request body: "+err.Error())
		return false
	}
	return true
}

// ssmNotFound answers ParameterNotFound for err when it is ErrNotFound,
// and a generic error otherwise.
func ssmNotFound(w http.ResponseWriter, name string, err error) {
	if errors.Is(err, models.ErrNotFound) {
		ssmError(w, "ParameterNotFound", fmt.Sprintf("Parameter %s not found.", name))
		return
	}
	awsproto.WriteAWSError(w, awsproto.ShapeJSON11, err)
}

// ssmPutValidation returns the ValidationException message real SSM
// gives for a bad PutParameter, or "".
func ssmPutValidation(name, typ string, overwriteWithTags bool) string {
	lower := strings.ToLower(strings.TrimPrefix(name, "/"))
	switch {
	case name == "":
		return "Parameter name must not be empty."
	case strings.HasPrefix(lower, "aws") || strings.HasPrefix(lower, "ssm"):
		return `Parameter name: can't be prefixed with "aws" or "ssm" (case-insensitive).`
	case !slices.Contains(ssmParameterTypes, typ):
		return fmt.Sprintf("Parameter type %q must be one of %s.", typ, strings.Join(ssmParameterTypes, ", "))
	case overwriteWithTags:
		return "Invalid request: tags and overwrite can't be used together. To create a parameter with tags, please remove overwrite flag. To update tags for an existing parameter, please use AddTagsToResource or RemoveTagsFromResource."
	}
	return ""
}

// CRITICAL[ssm-put-parameter-no-overwrite-cas]: PutParameter without
// Overwrite on an existing name answers 400 ParameterAlreadyExists and
// leaves the stored parameter unchanged, atomically: of N concurrent
// puts on one new name exactly one succeeds (a single INSERT in
// repository.PutSSMParameter). Overwrite=true bumps Version. Once
// DeleteParameter succeeds, GetParameter answers ParameterNotFound.
func (app *Application) ssmPutParameter(w http.ResponseWriter, region string, body []byte) {
	var in struct {
		Name           string
		Type           string
		Value          string
		AllowedPattern string
		Description    *string
		DataType       *string
		KeyId          *string
		Tier           *string
		Overwrite      bool
		Tags           []struct{ Key, Value string }
	}
	if !ssmDecode(w, body, &in) {
		return
	}
	if msg := ssmPutValidation(in.Name, in.Type, in.Overwrite && len(in.Tags) > 0); msg != "" {
		ssmError(w, "ValidationException", msg)
		return
	}
	tags := map[string]string{}
	for _, t := range in.Tags {
		tags[t.Key] = t.Value
	}
	version, err := app.repo.PutSSMParameter(awsproto.FakeAccountID, &repository.SSMParameterPut{
		Name: in.Name, Type: in.Type, Value: in.Value, AllowedPattern: in.AllowedPattern,
		Description: in.Description, DataType: in.DataType, KeyID: in.KeyId, Tier: in.Tier,
		Tags: tags, Region: region, Now: time.Now().UTC().Format(time.RFC3339),
	}, in.Overwrite)
	if errors.Is(err, models.ErrConflict) {
		ssmError(w, "ParameterAlreadyExists", "The parameter already exists. To overwrite this value, set the overwrite option in the request to true.")
		return
	}
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, err)
		return
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{"Version": version})
}

func (app *Application) ssmGetParameter(w http.ResponseWriter, region string, body []byte) {
	var in struct{ Name string }
	if !ssmDecode(w, body, &in) {
		return
	}
	if in.Name == al2023ParameterName {
		awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{"Parameter": map[string]any{
			"ARN":  awsproto.BuildSSMParameterARN(region, "", in.Name),
			"Name": in.Name, "Type": "String", "DataType": "text",
			"Value": AL2023AMIID, "Version": 1,
		}})
		return
	}
	p, err := app.repo.GetSSMParameter(awsproto.FakeAccountID, region, in.Name)
	if err != nil {
		ssmNotFound(w, in.Name, err)
		return
	}
	// SecureString values come back as stored, WithDecryption or not.
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{"Parameter": map[string]any{
		"ARN":  awsproto.BuildSSMParameterARN(region, awsproto.FakeAccountID, p.Name),
		"Name": p.Name, "Type": p.Type, "DataType": p.DataType,
		"Value": p.Value, "Version": p.Version,
		"LastModifiedDate": secretEpoch(p.LastModified),
	}})
}

// ssmDescribeParameters answers the provider's lookup, ParameterFilters
// Key=Name Option=Equals, and an unfiltered listing, in one page. Any
// other filter is 501 rather than an unfiltered answer.
func (app *Application) ssmDescribeParameters(w http.ResponseWriter, region string, body []byte) {
	type filter struct {
		Key, Option string
		Values      []string
	}
	var in struct {
		Filters          []json.RawMessage
		ParameterFilters []filter
	}
	if !ssmDecode(w, body, &in) {
		return
	}
	for _, f := range in.ParameterFilters {
		if f.Key != "Name" || (f.Option != "" && f.Option != "Equals") {
			writeUnimplemented(w, fmt.Sprintf("POST /ssm DescribeParameters ParameterFilter Key=%s Option=%s", f.Key, f.Option))
			return
		}
	}
	if len(in.Filters) > 0 {
		writeUnimplemented(w, "POST /ssm DescribeParameters Filters")
		return
	}
	params, err := app.repo.ListSSMParameters(awsproto.FakeAccountID, region)
	if err != nil {
		awsproto.WriteAWSError(w, awsproto.ShapeJSON11, err)
		return
	}
	out := []map[string]any{}
	for _, p := range params {
		if slices.ContainsFunc(in.ParameterFilters, func(f filter) bool { return !slices.Contains(f.Values, p.Name) }) {
			continue
		}
		out = append(out, ssmParameterMetadata(region, p))
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{"Parameters": out})
}

func ssmParameterMetadata(region string, p repository.SSMParameter) map[string]any {
	m := map[string]any{
		"ARN":  awsproto.BuildSSMParameterARN(region, awsproto.FakeAccountID, p.Name),
		"Name": p.Name, "Type": p.Type, "Version": p.Version,
		"Description": p.Description, "AllowedPattern": p.AllowedPattern,
		"DataType": p.DataType, "Tier": p.Tier, "Policies": []any{},
		"LastModifiedDate": secretEpoch(p.LastModified),
	}
	if p.Type == "SecureString" {
		m["KeyId"] = p.KeyID
		if p.KeyID == "" {
			m["KeyId"] = "alias/aws/ssm"
		}
	}
	return m
}

func (app *Application) ssmDeleteParameter(w http.ResponseWriter, region string, body []byte) {
	var in struct{ Name string }
	if !ssmDecode(w, body, &in) {
		return
	}
	if err := app.repo.DeleteSSMParameter(awsproto.FakeAccountID, region, in.Name); err != nil {
		ssmNotFound(w, in.Name, err)
		return
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{})
}

// ssmTagRequest is the body of the three tagging operations. Only
// ResourceType=Parameter is modelled.
type ssmTagRequest struct {
	ResourceType, ResourceId string
	Tags                     []struct{ Key, Value string }
	TagKeys                  []string
}

// ssmDecodeTagRequest decodes a tagging request, answering 501 for a
// resource type other than Parameter.
func ssmDecodeTagRequest(w http.ResponseWriter, op string, body []byte) (ssmTagRequest, bool) {
	var in ssmTagRequest
	if !ssmDecode(w, body, &in) {
		return in, false
	}
	if in.ResourceType != "Parameter" {
		writeUnimplemented(w, "POST /ssm "+op+" ResourceType="+in.ResourceType)
		return in, false
	}
	return in, true
}

// ssmTagError answers InvalidResourceId for an unknown parameter.
func ssmTagError(w http.ResponseWriter, err error) {
	if errors.Is(err, models.ErrNotFound) {
		ssmError(w, "InvalidResourceId", "The resource ID is not valid. Verify that you entered the correct ID and try again.")
		return
	}
	awsproto.WriteAWSError(w, awsproto.ShapeJSON11, err)
}

// ssmListTagsForResource backs the provider's tag read on every
// aws_ssm_parameter refresh.
func (app *Application) ssmListTagsForResource(w http.ResponseWriter, region string, body []byte) {
	in, ok := ssmDecodeTagRequest(w, "ListTagsForResource", body)
	if !ok {
		return
	}
	p, err := app.repo.GetSSMParameter(awsproto.FakeAccountID, region, in.ResourceId)
	if err != nil {
		ssmTagError(w, err)
		return
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{"TagList": tagsAsJSONSlice(p.Tags)})
}

// ssmChangeTags backs AddTagsToResource (Tags) and RemoveTagsFromResource
// (TagKeys), which the provider calls when tags change after create.
func (app *Application) ssmChangeTags(w http.ResponseWriter, region, op string, body []byte) {
	in, ok := ssmDecodeTagRequest(w, op, body)
	if !ok {
		return
	}
	patch := map[string]any{}
	for _, t := range in.Tags {
		patch[t.Key] = t.Value
	}
	for _, k := range in.TagKeys {
		patch[k] = nil
	}
	if err := app.repo.PatchSSMParameterTags(awsproto.FakeAccountID, region, in.ResourceId, patch); err != nil {
		ssmTagError(w, err)
		return
	}
	awsproto.WriteJSON11Response(w, http.StatusOK, map[string]any{})
}

// gatherSSMStateReal emits the ssm block of /mock/state: every user
// parameter by name, type, version and region, never its value. Public
// parameters are not stored, so they never appear.
func (app *Application) gatherSSMStateReal() map[string]any {
	params, _ := app.repo.ListSSMParameters(awsproto.FakeAccountID, "")
	out := []map[string]any{}
	for _, p := range params {
		out = append(out, map[string]any{
			"name": p.Name, "type": p.Type, "version": p.Version, "region": p.Region,
		})
	}
	return map[string]any{"parameters": out}
}
