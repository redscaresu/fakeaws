package handlers

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
