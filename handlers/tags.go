package handlers

import (
	"errors"
	"maps"
	"net/url"
	"slices"

	"github.com/redscaresu/fakeaws/repository"
)

// Shared plumbing for the ARN-addressed services' tags (SQS, IAM, RDS,
// Route53, DynamoDB, EKS). EC2 keeps its own resource-id keyed store.

// queryTags reads a flattened Query-RPC <prefix>N.Key / <prefix>N.Value
// list. A missing Value is an empty one.
func queryTags(p url.Values, prefix string) map[string]string {
	out := map[string]string{}
	for _, it := range queryListItems(p, prefix) {
		out[p.Get(it+"Key")] = p.Get(it + "Value")
	}
	return out
}

// tagList renders tags as a key-ordered list of the service's tag type.
func tagList[T any](tags map[string]string, tag func(k, v string) T) []T {
	out := make([]T, 0, len(tags))
	for _, k := range slices.Sorted(maps.Keys(tags)) {
		out = append(out, tag(k, tags[k]))
	}
	return out
}

// tagCreated stores the tags of a resource a Create* call just made. If
// that fails it deletes the resource with undo, so the create is all
// or nothing.
func (app *Application) tagCreated(account string, table repository.TaggedTable, arn string, tags map[string]string, undo func() error) error {
	if len(tags) == 0 {
		return nil
	}
	if err := app.repo.TagResource(account, table, arn, tags); err != nil {
		return errors.Join(err, undo())
	}
	return nil
}
