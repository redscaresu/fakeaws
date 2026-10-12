package handlers

import (
	"encoding/json"
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
// loader files land. fakeaws-test PutVpc stores a VPC, whose id is the
// exchange's body, under the envelope's account and region, then runs
// the hook HoldLoad set, inside the load's transaction. fakeaws-test
// PutSubnet stores the subnet "<subnet-id> <vpc-id>" names, which the
// FKs refuse unless PutVpc, registered before it, stored the VPC first.
var loadHold atomic.Pointer[func()]

// HoldLoad makes PutVpc call hold after its write, until t ends.
func HoldLoad(t *testing.T, hold func()) {
	loadHold.Store(&hold)
	t.Cleanup(func() { loadHold.Store(nil) })
}

func init() {
	registerLoader(loader{
		key: LoadKey{"fakeaws-test", "PutVpc"},
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
		key: LoadKey{"fakeaws-test", "PutSubnet"},
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
}
