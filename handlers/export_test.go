package handlers

import (
	"database/sql"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/redscaresu/fakeaws/repository"
)

// For the regression tests that make AllocateAddress and RunInstances
// derive an IP already held.
func EC2DeriveEIP(allocID string) string { return ec2DerivePublicIP(ec2EIPNet, allocID) }

func EC2DeriveAutoIP(eniID string) string { return ec2DerivePublicIP(ec2AutoIPNet, eniID) }

// For load_ec2_compute_test.go, which records each attribute a loaded
// instance references.
var InstanceReadAttributes = ec2InstanceReadAttributes

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

// The test-only loaders, registered beside the per-type loader files'
// (handlers/load_<service>.go) under the service fakeaws-test. Each writes under the envelope's account and region.
// A body is XML: one holding items has the root <Action>Response, as its
// render answers (GetVpcs's is JSON), and one holding none is a root
// element whose text the loader reads (bodyText). PutSubnet is
// registered first on purpose: loaders run by table, so PutVpc's VPC is
// stored before the subnet that names it. On ec2_vpcs they run in
// registration order: Refuse, Fail, QuoteFailure, Panic, PutVpc,
// ListVpcs, GetVpcs, GetVpc, DropField, RenderExtra, RenderPanic.
//   - fakeaws-test PutSubnet loads a subnetSet's items, each referencing
//     its VPC. Each write reads the VPC through QueryRow and refuses,
//     naming both ids, when it is not stored; else it stores the subnet.
//   - fakeaws-test Refuse refuses its exchange with its body's text.
//   - fakeaws-test Fail decodes one item, whose write ends the
//     transaction as SQLite does itself on SQLITE_FULL or IOERR, then
//     fails with a plain error quoting the body's text, as a decode error can,
//     so a later write would commit on its own.
//   - fakeaws-test QuoteFailure decodes one item too, whose write ends
//     the transaction, runs a statement that fails, and returns that
//     failure as a loadRefusal. Its body's text picks the statement and the
//     form: "quote" and "wrap" (%w) a failed Exec; "queryrow", "query"
//     and "scan" a QueryRow whose Scan fails, a Query that fails, and a
//     Query row whose Scan fails, each quoted.
//   - fakeaws-test Panic panics with a message quoting its body's text.
//   - fakeaws-test PutVpc loads a vpcSet's items, each referencing the
//     rows its refSet names, and runs the hook HoldLoad set after each
//     write, inside the load's transaction. It pages as EC2 does
//     (NextToken, nextToken), and InvalidVpcID.NotFound is a NotFound.
//     Its render reads the VPCs back through Query.
//   - fakeaws-test ListVpcs is PutVpc paging as IAM does (Marker,
//     IsTruncated); GetVpcs, PutVpc answering JSON {"Vpcs": [...]} and
//     paging as SSM does (NextToken, NextToken); GetVpc, answering one
//     JSON {"Vpc": {...}} and paging not at all.
//   - fakeaws-test DropField is PutVpc whose write drops cidrBlock;
//     RenderExtra, whose render adds an extra field; RenderPanic, whose
//     render panics quoting the ids.
//   - fakeaws-test DescribeSecurityGroups loads a securityGroupInfo's
//     items, each referencing its VPC.
var loadHold atomic.Pointer[func()]

// HoldLoad makes PutVpc call hold after its write, until t ends.
func HoldLoad(t *testing.T, hold func()) {
	loadHold.Store(&hold)
	t.Cleanup(func() { loadHold.Store(nil) })
}

// bodyText is the text of ex's body's root element: the body of an
// exchange whose loader decodes no item.
func bodyText(ex *loadExchange) string {
	var root struct {
		Text string `xml:",chardata"`
	}
	_ = xml.Unmarshal([]byte(ex.Body), &root) // the load parsed it before any loader ran
	return root.Text
}

// testVpcs is a test VPC loader's body, and its render's: GetVpc's
// holds its one VPC in Vpc.
type testVpcs struct {
	XMLName xml.Name  `json:"-"`
	Vpcs    []testVpc `xml:"vpcSet>item" json:"Vpcs,omitempty"`
	Vpc     *testVpc  `xml:"-" json:"Vpc,omitempty"`
}

// testVpc is a VPC item.
type testVpc struct {
	ID        string    `xml:"vpcId" json:"VpcId"`
	CidrBlock string    `xml:"cidrBlock" json:"CidrBlock"`
	Refs      *testRefs `xml:"refSet" json:"RefSet,omitempty"`
	Extra     string    `xml:"extra,omitempty" json:"Extra,omitempty"`
}

// testVpcRow is a VPC row's data, which DescribeVpcs reads as a
// repository.EC2VPC.
type testVpcRow struct {
	repository.EC2VPC
	Refs *testRefs `json:"refs,omitempty"`
}

// testRefs is an item's refSet, a pointer so an item with none renders
// none: encoding/xml writes refSet>item's refSet for an empty slice.
type testRefs struct {
	Refs []testRef `xml:"item" json:"Items"`
}

// testRef is a row an item references.
type testRef struct {
	Type   string `xml:"type" json:"Type"`
	ID     string `xml:"id" json:"Id"`
	Unread bool   `xml:"unread,omitempty" json:"Unread,omitempty"`
}

type testSubnets struct {
	XMLName xml.Name
	Subnets []testSubnet `xml:"subnetSet>item"`
}

// testSubnet is a subnet item, read back from its row's data, a
// repository.EC2Subnet.
type testSubnet struct {
	ID    string `xml:"subnetId" json:"subnet_id"`
	VPCID string `xml:"vpcId" json:"vpc_id"`
}

type testGroups struct {
	XMLName xml.Name
	Groups  []testGroup `xml:"securityGroupInfo>item"`
}

// testGroup is a security group item and, as JSON, its row's data.
type testGroup struct {
	ID    string `xml:"groupId" json:"group_id"`
	Name  string `xml:"groupName" json:"group_name"`
	VPCID string `xml:"vpcId" json:"vpc_id"`
}

// testRows reads the data of table's rows ids back through tx, in id
// order, each into a T.
func testRows[T any](tx *repository.LoadTx, table string, ids []string) ([]T, error) {
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	var out []T
	for scan, err := range tx.Query(`SELECT data FROM `+table+` WHERE id IN (`+strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")+`) ORDER BY id`, args...) {
		if err != nil {
			return nil, err
		}
		var data string
		if err := scan(&data); err != nil {
			return nil, err
		}
		var v T
		if err := json.Unmarshal([]byte(data), &v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// testVpcLoader is the test VPC loader on action, which pages as EC2
// does; GetVpcs and GetVpc answer JSON, and DropField, RenderExtra and
// RenderPanic each break one step.
func testVpcLoader(action string) loader {
	unmarshal, marshal, path := xml.Unmarshal, xml.Marshal, "vpcSet/item"
	switch action {
	case "GetVpcs":
		unmarshal, marshal, path = json.Unmarshal, json.Marshal, "Vpcs"
	case "GetVpc":
		unmarshal, marshal, path = json.Unmarshal, json.Marshal, "Vpc"
	}
	return loader{
		key: LoadKey{"fakeaws-test", action}, table: "ec2_vpcs", typ: "vpc",
		notFound:     []string{"InvalidVpcID.NotFound"},
		requestToken: "NextToken", responseToken: "nextToken",
		decode: func(env *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
			var body testVpcs
			if err := unmarshal([]byte(ex.Body), &body); err != nil {
				return nil, err
			}
			if body.Vpc != nil {
				body.Vpcs = []testVpc{*body.Vpc}
			}
			items := make([]loadItem, len(body.Vpcs))
			for i, v := range body.Vpcs {
				row := testVpcRow{repository.EC2VPC{ID: v.ID, CidrBlock: v.CidrBlock, Region: env.Region, State: "available"}, v.Refs}
				if action == "DropField" {
					row.CidrBlock = ""
				}
				items[i] = loadItem{loadRef: loadRef{"vpc", v.ID}, Path: path, Index: i, write: func(tx *repository.LoadTx) error {
					data, err := json.Marshal(row)
					if err != nil {
						return err
					}
					if _, err := tx.Exec(`INSERT INTO ec2_vpcs (account_id, region, id, cidr_block, arn, data, created_at) VALUES (?, ?, ?, ?, '', ?, '')`,
						env.Account, env.Region, row.ID, row.CidrBlock, string(data)); err != nil {
						return err
					}
					if hold := loadHold.Load(); hold != nil {
						(*hold)()
					}
					return nil
				}}
				if v.Refs != nil {
					for _, r := range v.Refs.Refs {
						items[i].Refs = append(items[i].Refs, loadReference{loadRef: loadRef{r.Type, r.ID}, Unread: r.Unread})
					}
				}
			}
			return items, nil
		},
		render: func(tx *repository.LoadTx, ids []string) ([]byte, error) {
			if action == "RenderPanic" {
				panic(fmt.Sprintf("cannot render %q", ids))
			}
			rows, err := testRows[testVpcRow](tx, "ec2_vpcs", ids)
			if err != nil {
				return nil, err
			}
			body := testVpcs{XMLName: xml.Name{Local: action + "Response"}, Vpcs: make([]testVpc, len(rows))}
			for i, r := range rows {
				body.Vpcs[i] = testVpc{ID: r.ID, CidrBlock: r.CidrBlock, Refs: r.Refs}
				if action == "RenderExtra" {
					body.Vpcs[i].Extra = "minted"
				}
			}
			if action == "GetVpc" && len(body.Vpcs) == 1 {
				body.Vpc, body.Vpcs = &body.Vpcs[0], nil
			}
			return marshal(body)
		},
	}
}

// renderNothing is the render of a loader whose items are never
// rendered: it decodes none, or each one's write aborts the load.
func renderNothing(*repository.LoadTx, []string) ([]byte, error) {
	return nil, errors.New("this test loader renders nothing")
}

// WithLoadIgnores replaces the registered ignore entries until t ends.
var WithLoadIgnores = withDiffIgnores

// failingItem is one item whose write runs fail.
func failingItem(fail func(tx *repository.LoadTx) error) []loadItem {
	return []loadItem{{loadRef: loadRef{"vpc", "vpc-0failing"}, write: fail}}
}

func init() {
	registerLoader(loader{
		key:   LoadKey{"fakeaws-test", "PutSubnet"},
		table: "ec2_subnets",
		decode: func(env *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
			var body testSubnets
			if err := xml.Unmarshal([]byte(ex.Body), &body); err != nil {
				return nil, err
			}
			items := make([]loadItem, len(body.Subnets))
			for i, sub := range body.Subnets {
				items[i] = loadItem{loadRef: loadRef{"subnet", sub.ID}, Path: "subnetSet/item", Index: i,
					Refs: []loadReference{{loadRef: loadRef{"vpc", sub.VPCID}}},
					write: func(tx *repository.LoadTx) error {
						var stored int
						err := tx.QueryRow(`SELECT 1 FROM ec2_vpcs WHERE account_id = ? AND id = ?`, env.Account, sub.VPCID).Scan(&stored)
						if errors.Is(err, sql.ErrNoRows) {
							return loadRefusal(fmt.Sprintf("subnet %s names vpc %s, which is not loaded", sub.ID, sub.VPCID))
						}
						if err != nil {
							return err
						}
						s := repository.EC2Subnet{ID: sub.ID, VPCID: sub.VPCID, CidrBlock: "10.0.1.0/24", AvailabilityZone: env.Region + "a", Region: env.Region, State: "available"}
						data, err := json.Marshal(s)
						if err != nil {
							return err
						}
						_, err = tx.Exec(`INSERT INTO ec2_subnets (account_id, region, id, vpc_id, cidr_block, availability_zone, arn, data, created_at) VALUES (?, ?, ?, ?, ?, ?, '', ?, '')`,
							env.Account, env.Region, s.ID, s.VPCID, s.CidrBlock, s.AvailabilityZone, string(data))
						return err
					}}
			}
			return items, nil
		},
		render: func(tx *repository.LoadTx, ids []string) ([]byte, error) {
			subnets, err := testRows[testSubnet](tx, "ec2_subnets", ids)
			if err != nil {
				return nil, err
			}
			return xml.Marshal(testSubnets{XMLName: xml.Name{Local: "PutSubnetResponse"}, Subnets: subnets})
		},
	})
	registerLoader(loader{
		key:    LoadKey{"fakeaws-test", "Refuse"},
		table:  "ec2_vpcs",
		render: renderNothing,
		decode: func(_ *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
			return nil, loadRefusal(bodyText(ex))
		},
	})
	registerLoader(loader{
		key:    LoadKey{"fakeaws-test", "Fail"},
		table:  "ec2_vpcs",
		render: renderNothing,
		decode: func(_ *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
			return failingItem(func(tx *repository.LoadTx) error {
				if _, err := tx.Exec(`ROLLBACK`); err != nil {
					return err
				}
				return fmt.Errorf("cannot decode %q", bodyText(ex))
			}), nil
		},
	})
	registerLoader(loader{
		key:    LoadKey{"fakeaws-test", "QuoteFailure"},
		table:  "ec2_vpcs",
		render: renderNothing,
		decode: func(_ *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
			return failingItem(func(tx *repository.LoadTx) error {
				if _, err := tx.Exec(`ROLLBACK`); err != nil {
					return err
				}
				var err error
				switch bodyText(ex) {
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
				if bodyText(ex) == "wrap" {
					return fmt.Errorf("%w: %w", loadRefusal("a refusal"), err)
				}
				return loadRefusal(fmt.Sprintf("a refusal: %v", err))
			}), nil
		},
	})
	registerLoader(loader{
		key:    LoadKey{"fakeaws-test", "Panic"},
		table:  "ec2_vpcs",
		render: renderNothing,
		decode: func(_ *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
			panic(fmt.Sprintf("cannot decode %q", bodyText(ex)))
		},
	})
	registerLoader(testVpcLoader("PutVpc"))
	iam := testVpcLoader("ListVpcs")
	iam.requestToken, iam.responseToken, iam.truncated = "Marker", "Marker", "IsTruncated"
	registerLoader(iam)
	ssm := testVpcLoader("GetVpcs")
	ssm.responseToken = "NextToken"
	registerLoader(ssm)
	get := testVpcLoader("GetVpc")
	get.requestToken, get.responseToken = "", ""
	registerLoader(get)
	for _, action := range []string{"DropField", "RenderExtra", "RenderPanic"} {
		registerLoader(testVpcLoader(action))
	}
	registerLoader(loader{
		key:   LoadKey{"fakeaws-test", "DescribeSecurityGroups"},
		table: "ec2_security_groups",
		typ:   "security-group",
		decode: func(env *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
			var body testGroups
			if err := xml.Unmarshal([]byte(ex.Body), &body); err != nil {
				return nil, err
			}
			items := make([]loadItem, len(body.Groups))
			for i, g := range body.Groups {
				items[i] = loadItem{loadRef: loadRef{"security-group", g.ID}, Path: "securityGroupInfo/item", Index: i,
					Refs: []loadReference{{loadRef: loadRef{"vpc", g.VPCID}}},
					write: func(tx *repository.LoadTx) error {
						data, err := json.Marshal(g)
						if err != nil {
							return err
						}
						_, err = tx.Exec(`INSERT INTO ec2_security_groups (account_id, region, id, vpc_id, group_name, description, arn, data, created_at) VALUES (?, ?, ?, ?, ?, '', '', ?, '')`,
							env.Account, env.Region, g.ID, g.VPCID, g.Name, string(data))
						return err
					}}
			}
			return items, nil
		},
		render: func(tx *repository.LoadTx, ids []string) ([]byte, error) {
			groups, err := testRows[testGroup](tx, "ec2_security_groups", ids)
			if err != nil {
				return nil, err
			}
			return xml.Marshal(testGroups{XMLName: xml.Name{Local: "DescribeSecurityGroupsResponse"}, Groups: groups})
		},
	})
}
