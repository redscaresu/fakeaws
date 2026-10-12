package handlers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redscaresu/fakeaws/repository"
)

// TestRegisterLoader_Refuses: a table no reset table names would have no
// rank to run by, and a second loader on one key would never run.
func TestRegisterLoader_Refuses(t *testing.T) {
	registered := len(loaders)
	assert.PanicsWithValue(t, `loader fakeaws-test Typo writes "ec2_vpc", which is not a reset table`, func() {
		registerLoader(loader{key: LoadKey{"fakeaws-test", "Typo"}, table: "ec2_vpc"})
	})
	assert.PanicsWithValue(t, "loader fakeaws-test PutVpc registered twice", func() {
		registerLoader(loader{key: LoadKey{"fakeaws-test", "PutVpc"}, table: "ec2_vpcs"})
	})
	assert.Len(t, loaders, registered, "a refused loader was registered")
}

// TestLoader_RenderReadsBackThroughTheTx: inside the load's transaction,
// PutVpc's render reads the rows its items' writes stored back through
// LoadTx's Query.
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
	require.NoError(t, repo.Load(repository.Identity{AccountID: env.Account, Region: env.Region}, func(tx *repository.LoadTx) error {
		for _, item := range items {
			if err := item.write(tx); err != nil {
				return err
			}
		}
		body, err := l.render(tx, []string{"vpc-0render-a", "vpc-0render-b"})
		rendered = string(body)
		assert.False(t, tx.Failed())
		return err
	}))
	assert.Equal(t, `<PutVpcResponse><vpcSet>`+
		`<item><vpcId>vpc-0render-a</vpcId><cidrBlock>10.0.0.0/16</cidrBlock></item>`+
		`<item><vpcId>vpc-0render-b</vpcId><cidrBlock>10.1.0.0/16</cidrBlock></item>`+
		`</vpcSet></PutVpcResponse>`, rendered)
}
