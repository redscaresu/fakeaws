package handlers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redscaresu/fakeaws/repository"
)

// TestRegisterLoader_Refuses: a table no reset table names would have no
// rank to run by, a second loader on one key would never run, and a
// loader missing decode or render, pairing half a page token, answering
// truncated with no token, or naming NotFound codes with no typ would
// fail open or late.
func TestRegisterLoader_Refuses(t *testing.T) {
	registered := len(loaders)
	assert.PanicsWithValue(t, `loader fakeaws-test Typo writes "ec2_vpc", which is not a reset table`, func() {
		registerLoader(loader{key: LoadKey{"fakeaws-test", "Typo"}, table: "ec2_vpc"})
	})
	assert.PanicsWithValue(t, "loader fakeaws-test PutVpc registered twice", func() {
		registerLoader(loader{key: LoadKey{"fakeaws-test", "PutVpc"}, table: "ec2_vpcs"})
	})
	decode := func(*loadEnvelope, *loadExchange) ([]loadItem, error) { return nil, nil }
	for _, tc := range []struct {
		want string
		l    loader
	}{
		{"needs both decode and render", loader{decode: decode}},
		{"needs both decode and render", loader{render: renderNothing}},
		{"pages with only one of requestToken and responseToken", loader{decode: decode, render: renderNothing, requestToken: "NextToken"}},
		{"pages with only one of requestToken and responseToken", loader{decode: decode, render: renderNothing, responseToken: "nextToken"}},
		{`answers truncated "IsTruncated" but no responseToken`, loader{decode: decode, render: renderNothing, truncated: "IsTruncated"}},
		{"has notFound codes but no typ to count them under", loader{decode: decode, render: renderNothing, notFound: []string{"InvalidVpcID.NotFound"}}},
	} {
		tc.l.key, tc.l.table = LoadKey{"fakeaws-test", "Typo"}, "ec2_vpcs"
		assert.PanicsWithValue(t, "loader fakeaws-test Typo "+tc.want, func() { registerLoader(tc.l) })
	}
	assert.Len(t, loaders, registered, "a refused loader was registered")
}

// TestLoader_RenderReadsBackThroughTheTx: inside the load's transaction,
// PutVpc's items' writes store each row under the envelope's account and
// region, and its render reads them back through LoadTx's Query.
func TestLoader_RenderReadsBackThroughTheTx(t *testing.T) {
	repo, err := repository.New(":memory:")
	require.NoError(t, err)
	defer repo.Close()
	l := loaderFor(LoadKey{"fakeaws-test", "PutVpc"})
	env := &loadEnvelope{Account: "111122223333", Region: "eu-west-1"}
	items, err := l.decode(env, &loadExchange{Body: `<PutVpcResponse><vpcSet>` +
		`<item><vpcId>vpc-0render-b</vpcId><cidrBlock>10.1.0.0/16</cidrBlock></item>` +
		`<item><vpcId>vpc-0render-a</vpcId><cidrBlock>10.0.0.0/16</cidrBlock></item>` +
		`</vpcSet></PutVpcResponse>`})
	require.NoError(t, err)

	var rendered string
	var stored []string
	require.NoError(t, repo.Load(repository.Identity{AccountID: env.Account, Region: env.Region}, func(tx *repository.LoadTx) error {
		for _, item := range items {
			if err := item.write(tx); err != nil {
				return err
			}
		}
		for scan, err := range tx.Query(`SELECT account_id, region FROM ec2_vpcs`) {
			require.NoError(t, err)
			var account, region string
			require.NoError(t, scan(&account, &region))
			stored = append(stored, account+" "+region)
		}
		body, err := l.render(tx, []string{"vpc-0render-a", "vpc-0render-b"})
		rendered = string(body)
		assert.False(t, tx.Failed())
		return err
	}))
	assert.Equal(t, []string{"111122223333 eu-west-1", "111122223333 eu-west-1"}, stored, "each row is stored under the envelope's account and region")
	assert.Equal(t, `<PutVpcResponse><vpcSet>`+
		`<item><vpcId>vpc-0render-a</vpcId><cidrBlock>10.0.0.0/16</cidrBlock></item>`+
		`<item><vpcId>vpc-0render-b</vpcId><cidrBlock>10.1.0.0/16</cidrBlock></item>`+
		`</vpcSet></PutVpcResponse>`, rendered)
}
