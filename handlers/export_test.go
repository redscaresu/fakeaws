package handlers

import (
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

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
// On ec2_vpcs they run in registration order: Fail, then PutVpc, then
// Refuse.
//   - fakeaws-test PutSubnet stores that subnet.
//   - fakeaws-test Fail ends the transaction as SQLite does itself on
//     SQLITE_FULL or IOERR, then fails with a plain error, so a later
//     write would commit on its own.
//   - fakeaws-test PutVpc stores the VPC its body names, then runs the
//     hook HoldLoad set, inside the load's transaction.
//   - fakeaws-test Refuse refuses its exchange with its body.
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
		key:   LoadKey{"fakeaws-test", "Fail"},
		table: "ec2_vpcs",
		load: func(tx *repository.LoadTx, _ *loadEnvelope, _ *loadExchange) ([]loadItem, error) {
			if _, err := tx.Exec(`ROLLBACK`); err != nil {
				return nil, err
			}
			return nil, errors.New("disk I/O error")
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
	})
	registerLoader(loader{
		key:   LoadKey{"fakeaws-test", "Refuse"},
		table: "ec2_vpcs",
		load: func(_ *repository.LoadTx, _ *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
			return nil, loadRefusal(ex.Body)
		},
	})
}
