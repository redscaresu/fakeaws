package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/redscaresu/fakeaws/handlers/awsproto"
	"github.com/redscaresu/fakeaws/repository"
)

// For the regression tests that make AllocateAddress and RunInstances
// derive an IP already held.
func EC2DeriveEIP(allocID string) string { return ec2DerivePublicIP(ec2EIPNet, allocID) }

func EC2DeriveAutoIP(eniID string) string { return ec2DerivePublicIP(ec2AutoIPNet, eniID) }

// For recorder_test.go's test routes, which mark a class.
var MarkClass = markClass

type RequestClass = requestClass

const ClassUnimplemented = classUnimplemented

// For recorder_test.go's check that every landed service has a protocol.
var ServiceProtocols = serviceProtocols

// For ssm_test.go's sweep of every SSM operation.
var SSMOperations = ssmOperations

// For ssm_test.go's check of the DescribeParameters ARN.
var SSMParameterMetadata = ssmParameterMetadata

// The test-only loaders, the only ones registered until the per-type
// loader files land. Each writes under the envelope's account and region.
// PutSubnet is registered first on purpose: loaders run by table, so
// PutVpc's VPC is stored before the subnet "<subnet-id> <vpc-id>" names.
// On ec2_vpcs they run in registration order: Refuse, Fail,
// QuoteFailure, Panic, then PutVpc.
//   - fakeaws-test PutSubnet reads its VPC through QueryRow and refuses,
//     naming both ids, when it is not stored; else it stores the subnet.
//   - fakeaws-test Refuse refuses its exchange with its body.
//   - fakeaws-test Fail ends the transaction as SQLite does itself on
//     SQLITE_FULL or IOERR, then fails with a plain error quoting its
//     body, as a decode error can, so a later write would commit on its
//     own.
//   - fakeaws-test QuoteFailure ends the transaction too, runs a
//     statement that fails, and returns that failure as a loadRefusal.
//     Its body picks the statement and the form: "quote" and "wrap" (%w)
//     a failed Exec; "queryrow", "query" and "scan" a QueryRow whose Scan
//     fails, a Query that fails, and a Query row whose Scan fails, each
//     quoted.
//   - fakeaws-test Panic panics with a message quoting its body.
//   - fakeaws-test PutVpc stores the VPC its body names, then runs the
//     hook HoldLoad set, inside the load's transaction. Its render reads
//     the VPCs back through Query and answers them as DescribeVpcs does.
var loadHold atomic.Pointer[func()]

// HoldLoad makes PutVpc call hold after its write, until t ends.
func HoldLoad(t *testing.T, hold func()) {
	loadHold.Store(&hold)
	t.Cleanup(func() { loadHold.Store(nil) })
}

func init() {
	registerLoader(loader{
		key:   LoadKey{"fakeaws-test", "PutSubnet"},
		table: "ec2_subnets",
		load: func(tx *repository.LoadTx, env *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
			id, vpcID, _ := strings.Cut(ex.Body, " ")
			var stored int
			err := tx.QueryRow(`SELECT 1 FROM ec2_vpcs WHERE account_id = ? AND id = ?`, env.Account, vpcID).Scan(&stored)
			if errors.Is(err, sql.ErrNoRows) {
				return nil, loadRefusal(fmt.Sprintf("subnet %s names vpc %s, which is not loaded", id, vpcID))
			}
			if err != nil {
				return nil, err
			}
			s := repository.EC2Subnet{ID: id, VPCID: vpcID, CidrBlock: "10.0.1.0/24", AvailabilityZone: env.Region + "a", Region: env.Region, State: "available"}
			data, err := json.Marshal(s)
			if err != nil {
				return nil, err
			}
			if _, err := tx.Exec(`INSERT INTO ec2_subnets (account_id, region, id, vpc_id, cidr_block, availability_zone, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?, '', ?, '')`,
				env.Account, env.Region, s.ID, s.VPCID, s.CidrBlock, s.AvailabilityZone, string(data)); err != nil {
				return nil, err
			}
			return []loadItem{{loadRef: loadRef{"subnet", s.ID}}}, nil
		},
	})
	registerLoader(loader{
		key:   LoadKey{"fakeaws-test", "Refuse"},
		table: "ec2_vpcs",
		load: func(_ *repository.LoadTx, _ *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
			return nil, loadRefusal(ex.Body)
		},
	})
	registerLoader(loader{
		key:   LoadKey{"fakeaws-test", "Fail"},
		table: "ec2_vpcs",
		load: func(tx *repository.LoadTx, _ *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
			if _, err := tx.Exec(`ROLLBACK`); err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("cannot decode %q", ex.Body)
		},
	})
	registerLoader(loader{
		key:   LoadKey{"fakeaws-test", "QuoteFailure"},
		table: "ec2_vpcs",
		load: func(tx *repository.LoadTx, _ *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
			if _, err := tx.Exec(`ROLLBACK`); err != nil {
				return nil, err
			}
			var err error
			switch ex.Body {
			case "queryrow":
				err = tx.QueryRow(`SELECT 1 FROM no_such_table`).Scan(new(int))
			case "query":
				for _, qerr := range tx.Query(`SELECT 1 FROM no_such_table`) {
					err = qerr
				}
			case "scan":
				for scan, qerr := range tx.Query(`SELECT 'not a number'`) {
					if err = qerr; err == nil {
						err = scan(new(int))
					}
				}
			default:
				_, err = tx.Exec(`INSERT INTO no_such_table VALUES (1)`)
			}
			if ex.Body == "wrap" {
				return nil, fmt.Errorf("%w: %w", loadRefusal("a refusal"), err)
			}
			return nil, loadRefusal(fmt.Sprintf("a refusal: %v", err))
		},
	})
	registerLoader(loader{
		key:   LoadKey{"fakeaws-test", "Panic"},
		table: "ec2_vpcs",
		load: func(_ *repository.LoadTx, _ *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
			panic(fmt.Sprintf("cannot decode %q", ex.Body))
		},
	})
	registerLoader(loader{
		key:   LoadKey{"fakeaws-test", "PutVpc"},
		table: "ec2_vpcs",
		load: func(tx *repository.LoadTx, env *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
			v := repository.EC2VPC{ID: ex.Body, CidrBlock: "10.0.0.0/16", Region: env.Region, State: "available"}
			data, err := json.Marshal(v)
			if err != nil {
				return nil, err
			}
			if _, err := tx.Exec(`INSERT INTO ec2_vpcs (account_id, region, id, cidr_block, arn, data, created_at) VALUES (?, ?, ?, ?, '', ?, '')`,
				env.Account, env.Region, v.ID, v.CidrBlock, string(data)); err != nil {
				return nil, err
			}
			if hold := loadHold.Load(); hold != nil {
				(*hold)()
			}
			return []loadItem{{loadRef: loadRef{"vpc", v.ID}}}, nil
		},
		render: func(tx *repository.LoadTx, ids []string) ([]byte, error) {
			args := make([]any, len(ids))
			for i, id := range ids {
				args[i] = id
			}
			out := ec2DescribeVpcsResult{VpcSet: []ec2VpcXML{}}
			for scan, err := range tx.Query(`SELECT account_id, data FROM ec2_vpcs WHERE id IN (`+strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")+`) ORDER BY id`, args...) {
				if err != nil {
					return nil, err
				}
				var account, data string
				if err := scan(&account, &data); err != nil {
					return nil, err
				}
				var v repository.EC2VPC
				if err := json.Unmarshal([]byte(data), &v); err != nil {
					return nil, err
				}
				out.VpcSet = append(out.VpcSet, ec2VpcToXML(account, &v))
			}
			rec := httptest.NewRecorder()
			awsproto.WriteEC2QueryRPCResponse(rec, "DescribeVpcs", &out)
			return rec.Body.Bytes(), nil
		},
	})
}
