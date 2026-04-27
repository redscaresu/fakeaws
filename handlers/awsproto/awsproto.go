// Package awsproto holds the per-protocol marshalling helpers fakeaws
// uses to translate domain operations into the wire shapes
// terraform-provider-aws expects.
//
// AWS speaks five distinct wire shapes across the nine v1 services
// (concepts.md § "Wire-format strategy"):
//
//   1. XML REST                                — S3, Route53
//   2. Query-RPC (form body, XML response)     — EC2, RDS, IAM
//   3. JSON 1.0 with x-amz-target              — SQS
//   4. JSON 1.1 with x-amz-target              — DynamoDB, SecretsManager
//   5. JSON REST                               — EKS
//
// Per-shape helpers live in their own file:
//
//   xml.go        WriteXMLResponse
//   queryrpc.go   ParseQueryRPC, WriteQueryRPCError, ec2_xmlerror et al.
//   xmltarget.go  ParseXAmzTarget
//   json.go       WriteJSONResponse, WriteJSONError, JSON-REST helpers
//   arn.go        Per-service ARN builders (BuildIAMRoleARN, etc.)
//
// The big load-bearing test in awsproto_test.go covers the full
// (wire shape × error sentinel) matrix: 5 × 4 = 20 cells minimum, per
// the S43-T2 acceptance criteria.
package awsproto

// FakeAccountID is the synthetic AWS account every fakeaws-emitted
// resource lives under. Per concepts.md "Open question 1 / Resolved":
// one synthetic account ID `000000000000` for v1; multi-account is a
// v2 problem. Tests and ARN builders reference this constant rather
// than hard-coding the literal so future multi-account work needs to
// touch one symbol, not the whole package.
const FakeAccountID = "000000000000"
