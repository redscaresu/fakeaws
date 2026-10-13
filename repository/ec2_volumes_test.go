package repository

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// volumeStates is each stored volume's id → its state and attached
// instances.
func volumeStates(t *testing.T, r *Repository) map[string][]string {
	t.Helper()
	vols, err := r.ListVolumes(testAccount, testRegion)
	require.NoError(t, err)
	out := map[string][]string{}
	for _, v := range vols {
		out[v.ID] = []string{v.State}
		for _, a := range v.Attachments {
			out[v.ID] = append(out[v.ID], a.InstanceID)
		}
	}
	return out
}

// TestTerminateVolumes: terminating i-0 deletes the volume it alone
// holds with deleteOnTermination true, and its tags; it detaches the one
// it alone holds with false, which is left available, and the
// Multi-Attach ones it shares with i-1, which stay in-use on i-1 whatever
// i-0's flag. Terminating i-1 then deletes or leaves each of those by
// i-1's own flag.
func TestTerminateVolumes(t *testing.T) {
	r := setupRepo(t)
	createInstances(t, r, 2)
	attach := func(instance, deleteOnTermination string) EC2VolumeAttachment {
		return EC2VolumeAttachment{InstanceID: instance, State: "attached", DeleteOnTermination: deleteOnTermination}
	}
	for _, v := range []*EC2Volume{
		{ID: "vol-deleted", State: "in-use", Attachments: []EC2VolumeAttachment{attach("i-0", "true")}},
		{ID: "vol-kept", State: "in-use", Attachments: []EC2VolumeAttachment{attach("i-0", "false")}},
		{ID: "vol-shared-kept", State: "in-use", Attachments: []EC2VolumeAttachment{attach("i-0", "true"), attach("i-1", "false")}},
		{ID: "vol-shared-deleted", State: "in-use", Attachments: []EC2VolumeAttachment{attach("i-0", "false"), attach("i-1", "true")}},
	} {
		v.Region = testRegion
		require.NoError(t, insertVolume(r.db, testAccount, v))
	}
	require.NoError(t, r.PutTags(testAccount, testRegion, []EC2Tag{{ResourceID: "vol-deleted", ResourceType: "volume", Key: "Name", Value: "root"}}))

	_, err := r.SetInstanceState(testAccount, testRegion, "terminated", "i-0")
	require.NoError(t, err)
	assert.Equal(t, map[string][]string{
		"vol-kept":           {"available"},
		"vol-shared-kept":    {"in-use", "i-1"},
		"vol-shared-deleted": {"in-use", "i-1"},
	}, volumeStates(t, r))
	tags, err := r.ListTags(testAccount, testRegion)
	require.NoError(t, err)
	assert.Empty(t, tags, "the deleted volume's tags go with it")

	_, err = r.SetInstanceState(testAccount, testRegion, "terminated", "i-1")
	require.NoError(t, err)
	assert.Equal(t, map[string][]string{
		"vol-kept":        {"available"},
		"vol-shared-kept": {"available"},
	}, volumeStates(t, r))
}
