package handlers

// load_ssm.go — the SSM GetParameter loader. Only a public parameter
// loads: AWS's, under the loaded account's key so it sees it, with its
// recorded account-less ARN.

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/redscaresu/fakeaws/handlers/awsproto"
	"github.com/redscaresu/fakeaws/repository"
)

func init() {
	registerLoader(loader{
		key:      LoadKey{"ssm", "GetParameter"},
		table:    "ssm_parameters",
		typ:      "ssm-parameter",
		notFound: []string{"ParameterNotFound"},
		decode:   decodeSSMGetParameter,
		render:   renderSSMGetParameter,
	})
}

// decodeSSMGetParameter decodes a GetParameter answer's Parameter. A
// parameter that is not public is refused: aws_ssm_parameter's read also
// calls DescribeParameters and ListTagsForResource
// (terraform-provider-aws v5.100.0 internal/service/ssm/parameter.go),
// which the reader never records. A Value that is an AMI id references
// that image, which the reader never reads.
func decodeSSMGetParameter(env *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
	var body struct {
		Parameter struct {
			ARN, Name, Type, DataType, Value string
			Version                          int64
			LastModifiedDate                 json.Number
		}
	}
	if err := json.Unmarshal([]byte(ex.Body), &body); err != nil || body.Parameter.Name == "" {
		return nil, loadRefusal("the body is not a GetParameter answer naming a Parameter")
	}
	in := body.Parameter
	if !repository.IsPublicSSMParameter(in.Name) {
		return nil, loadRefusal(fmt.Sprintf("parameter %s is not public: the read never records its description, tier, allowed_pattern, key_id and tags, which aws_ssm_parameter reads through DescribeParameters and ListTagsForResource", in.Name))
	}
	if in.ARN == "" {
		return nil, loadRefusal(fmt.Sprintf("parameter %s records no ARN", in.Name))
	}
	if !ssmAccountlessARN(in.ARN, in.Name) {
		return nil, loadRefusal(fmt.Sprintf("parameter %s: ARN %s is not its account-less parameter ARN", in.Name, in.ARN))
	}
	p := &repository.SSMParameter{
		Name: in.Name, Type: in.Type, DataType: in.DataType, Value: in.Value, Version: in.Version,
		LastModified: string(in.LastModifiedDate), ARN: in.ARN, Region: env.Region, Tags: map[string]string{},
	}
	item := loadItem{loadRef: loadRef{"ssm-parameter", in.Name}, Path: "Parameter",
		write: func(tx *repository.LoadTx) error { return repository.LoadSSMParameter(tx, env.Account, p) }}
	if amiIDPattern.MatchString(in.Value) {
		item.Refs = []loadReference{{loadRef: loadRef{"image", in.Value}, Unread: true}}
	}
	return []loadItem{item}, nil
}

// ssmAccountlessARN reports whether arn is public parameter name's own
// ARN, as awsproto.BuildSSMParameterARN builds it with no account, in
// any valid region: the region may differ from the load's, as recorded.
// ssmRefMatch matches the stored ARN, so one carrying an account or
// naming another parameter would find the row.
func ssmAccountlessARN(arn, name string) bool {
	parts := strings.SplitN(arn, ":", 5)
	return len(parts) == 5 && CheckRegion(parts[3]) == nil && arn == awsproto.BuildSSMParameterARN(parts[3], "", name)
}

// renderSSMGetParameter answers GetParameter for the one stored
// parameter ids names, as the handler does.
func renderSSMGetParameter(tx *repository.LoadTx, ids []string) ([]byte, error) {
	if len(ids) != 1 {
		return nil, errors.New("GetParameter answers one parameter")
	}
	account, p, err := repository.LoadedSSMParameter(tx, ids[0])
	if err != nil {
		return nil, err
	}
	return json.Marshal(ssmGetParameterBody(account, p))
}
