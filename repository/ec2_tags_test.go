package repository

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func tagKeys(t *testing.T, r *Repository, region string) map[string]string {
	t.Helper()
	tags, err := r.ListTags(testAccount, region)
	require.NoError(t, err)
	out := map[string]string{}
	for _, tag := range tags {
		out[tag.ResourceID+"/"+tag.Key] = tag.Value
	}
	return out
}

func TestTagsPutDeleteList(t *testing.T) {
	r := setupRepo(t)
	require.NoError(t, r.PutTags(testAccount, testRegion, []EC2Tag{
		{ResourceID: "vpc-1", ResourceType: "vpc", Key: "a", Value: "1"},
		{ResourceID: "vpc-1", ResourceType: "vpc", Key: "b", Value: "2"},
		{ResourceID: "vpc-1", ResourceType: "vpc", Key: "c", Value: "3"},
	}))
	require.NoError(t, r.PutTags(testAccount, "eu-west-1", []EC2Tag{{ResourceID: "vpc-2", ResourceType: "vpc", Key: "a", Value: "x"}}))
	require.NoError(t, r.PutTags(testAccount, testRegion, []EC2Tag{{ResourceID: "vpc-1", ResourceType: "vpc", Key: "a", Value: "1b"}}))

	assert.Equal(t, map[string]string{"vpc-1/a": "1b", "vpc-1/b": "2", "vpc-1/c": "3"}, tagKeys(t, r, testRegion), "overwrite, region scope")
	assert.Len(t, tagKeys(t, r, ""), 4, "all regions")

	wrong, right := "nope", "2"
	require.NoError(t, r.DeleteTags(testAccount, []string{"vpc-1"}, []EC2TagMatch{{Key: "a"}, {Key: "b", Value: &wrong}}))
	assert.Equal(t, map[string]string{"vpc-1/b": "2", "vpc-1/c": "3"}, tagKeys(t, r, testRegion), "key-only deletes; a mismatched value keeps the tag")
	require.NoError(t, r.DeleteTags(testAccount, []string{"vpc-1"}, []EC2TagMatch{{Key: "b", Value: &right}}))
	assert.Equal(t, map[string]string{"vpc-1/c": "3"}, tagKeys(t, r, testRegion), "matching value deletes")
	require.NoError(t, r.DeleteTags(testAccount, []string{"vpc-1", "vpc-2"}, nil))
	assert.Empty(t, tagKeys(t, r, ""), "no matches deletes every tag")
}

func TestTagsGoWithTheirResource(t *testing.T) {
	r := setupRepo(t)
	require.NoError(t, r.CreateVPC(testAccount, &EC2VPC{ID: "vpc-1", CidrBlock: "10.0.0.0/16", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"}))
	require.NoError(t, r.CreateSubnet(testAccount, &EC2Subnet{ID: "subnet-1", VPCID: "vpc-1", CidrBlock: "10.0.1.0/24", AvailabilityZone: "us-east-1a", Region: testRegion, ARN: "arn", State: "available", CreatedAt: "t"}))
	require.NoError(t, r.CreateInternetGateway(testAccount, &EC2InternetGateway{ID: "igw-1", Region: testRegion, ARN: "arn", CreatedAt: "t"}))
	for _, id := range []string{"vpc-1", "subnet-1", "igw-1"} {
		require.NoError(t, r.PutTags(testAccount, testRegion, []EC2Tag{{ResourceID: id, ResourceType: "x", Key: "Name", Value: id}}))
	}

	require.NoError(t, r.DeleteInternetGateway(testAccount, testRegion, "igw-1"))
	assert.NotContains(t, tagKeys(t, r, ""), "igw-1/Name", "direct delete")
	require.NoError(t, r.DeleteVPC(testAccount, testRegion, "vpc-1"))
	assert.Empty(t, tagKeys(t, r, ""), "VPC delete and its subnet cascade")

	require.NoError(t, r.PutTags(testAccount, testRegion, []EC2Tag{{ResourceID: "vpc-9", ResourceType: "vpc", Key: "k", Value: "v"}}))
	require.NoError(t, r.Reset())
	assert.Empty(t, tagKeys(t, r, ""), "reset")
}
