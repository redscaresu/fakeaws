package handlers

import (
	"slices"
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
// PutVpc's render reads the rows its load stored back through LoadTx's
// Query and answers them with DescribeVpcs's encoder.
func TestLoader_RenderReadsBackThroughTheTx(t *testing.T) {
	repo, err := repository.New(":memory:")
	require.NoError(t, err)
	defer repo.Close()
	i := slices.IndexFunc(loaders, func(l loader) bool { return l.key == LoadKey{"fakeaws-test", "PutVpc"} })
	require.GreaterOrEqual(t, i, 0)
	l := loaders[i]
	env := &loadEnvelope{Account: "111122223333", Region: "eu-west-1"}

	var rendered string
	require.NoError(t, repo.Load(repository.Identity{AccountID: env.Account, Region: env.Region}, func(tx *repository.LoadTx) error {
		for _, id := range []string{"vpc-0render-b", "vpc-0render-a"} {
			if _, err := l.load(tx, env, &loadExchange{Body: id}); err != nil {
				return err
			}
		}
		body, err := l.render(tx, []string{"vpc-0render-a", "vpc-0render-b"})
		rendered = string(body)
		assert.False(t, tx.Failed())
		return err
	}))
	assert.Contains(t, rendered, "<DescribeVpcsResponse>")
	assert.Regexp(t, `(?s)<vpcId>vpc-0render-a</vpcId>.*<vpcId>vpc-0render-b</vpcId>`, rendered)
	assert.Contains(t, rendered, "<ownerId>111122223333</ownerId>", "the row's account, read back")
}
