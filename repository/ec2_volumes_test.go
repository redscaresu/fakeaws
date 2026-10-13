package repository

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTerminateVolumes: terminating i-0 deletes the volume it holds
// with deleteOnTermination true, and the volume's tags; it detaches the
// one it holds with false, which is left available, and the one it
// shares with i-1, which stays in-use attached to i-1.
func TestTerminateVolumes(t *testing.T) {
	r := setupRepo(t)
	createInstances(t, r, 2)
	attach := func(instance, deleteOnTermination string) EC2VolumeAttachment {
		return EC2VolumeAttachment{InstanceID: instance, State: "attached", DeleteOnTermination: deleteOnTermination}
	}
	for _, v := range []*EC2Volume{
		{ID: "vol-deleted", State: "in-use", Attachments: []EC2VolumeAttachment{attach("i-0", "true")}},
		{ID: "vol-kept", State: "in-use", Attachments: []EC2VolumeAttachment{attach("i-0", "false")}},
		{ID: "vol-shared", State: "in-use", Attachments: []EC2VolumeAttachment{attach("i-0", "false"), attach("i-1", "false")}},
	} {
		v.Region = testRegion
		require.NoError(t, insertVolume(r.db, testAccount, v))
	}
	require.NoError(t, r.PutTags(testAccount, testRegion, []EC2Tag{{ResourceID: "vol-deleted", ResourceType: "volume", Key: "Name", Value: "root"}}))

	_, err := r.SetInstanceState(testAccount, testRegion, "terminated", "i-0")
	require.NoError(t, err)

	vols, err := r.ListVolumes(testAccount, testRegion)
	require.NoError(t, err)
	require.Len(t, vols, 2)
	assert.Equal(t, "vol-kept", vols[0].ID)
	assert.Equal(t, "available", vols[0].State)
	assert.Empty(t, vols[0].Attachments)
	assert.Equal(t, "vol-shared", vols[1].ID)
	assert.Equal(t, "in-use", vols[1].State)
	assert.Equal(t, []EC2VolumeAttachment{attach("i-1", "false")}, vols[1].Attachments)
	tags, err := r.ListTags(testAccount, testRegion)
	require.NoError(t, err)
	assert.Empty(t, tags, "the deleted volume's tags go with it")
}
