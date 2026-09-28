package repository

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/redscaresu/fakeaws/models"
)

func TestResourceTagsRoundTrip(t *testing.T) {
	r := setupRepo(t)
	const arn = "arn:aws:sqs:us-east-1:000000000000:orders"
	require.NoError(t, r.CreateSQSQueue(testAccount, &SQSQueue{Name: "orders", QueueURL: "url", ARN: arn, Region: testRegion, CreatedAt: "t"}))

	require.NoError(t, r.TagResource(testAccount, TagsSQSQueue, arn, map[string]string{"a": "1", "empty": "", "k8s.io/x:y": "z"}))
	require.NoError(t, r.TagResource(testAccount, TagsSQSQueue, arn, map[string]string{"a": "2"}))
	require.NoError(t, r.UntagResource(testAccount, TagsSQSQueue, arn, []string{"k8s.io/x:y", "absent"}))
	got, err := r.ResourceTags(testAccount, TagsSQSQueue, arn)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"a": "2", "empty": ""}, got)

	require.NoError(t, r.DeleteSQSQueue(testAccount, testRegion, "orders"))
	require.NoError(t, r.CreateSQSQueue(testAccount, &SQSQueue{Name: "orders", QueueURL: "url", ARN: arn, Region: testRegion, CreatedAt: "t"}))
	got, err = r.ResourceTags(testAccount, TagsSQSQueue, arn)
	require.NoError(t, err)
	assert.Empty(t, got, "a recreated resource does not inherit the deleted one's tags")
}

func TestResourceTagsMissingResource(t *testing.T) {
	r := setupRepo(t)
	const arn = "arn:aws:dynamodb:us-east-1:000000000000:table/none"
	assert.ErrorIs(t, r.TagResource(testAccount, TagsDynamoDBTable, arn, map[string]string{"a": "1"}), models.ErrNotFound)
	assert.ErrorIs(t, r.UntagResource(testAccount, TagsDynamoDBTable, arn, []string{"a"}), models.ErrNotFound)
	_, err := r.ResourceTags(testAccount, TagsDynamoDBTable, arn)
	assert.ErrorIs(t, err, models.ErrNotFound)
}
