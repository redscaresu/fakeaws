package awsproto

import (
	"fmt"
	"strings"
)

// Per-service ARN builders. Real AWS ARN formats vary per service —
// IAM omits region, S3 is bucket-scoped, Route53 is global, EC2/RDS/
// EKS/SQS/DynamoDB embed region+account, SecretsManager appends a
// random 6-char suffix. There is no single uniform format, so the
// earlier "single generic builder" design was retracted in pass 6
// (concepts.md § "Resolved decisions" item 13).
//
// Builders that embed an account take it as a parameter; handlers pass
// the default account (see awsproto.go).

// BuildIAMRoleARN: arn:aws:iam::<account>:role/<name>
// IAM is global (no region segment).
func BuildIAMRoleARN(account, name string) string {
	return fmt.Sprintf("arn:aws:iam::%s:role/%s", account, name)
}

// BuildIAMPolicyARN: arn:aws:iam::<account>:policy/<name>
func BuildIAMPolicyARN(account, name string) string {
	return fmt.Sprintf("arn:aws:iam::%s:policy/%s", account, name)
}

// BuildIAMInstanceProfileARN: arn:aws:iam::<account>:instance-profile/<name>
func BuildIAMInstanceProfileARN(account, name string) string {
	return fmt.Sprintf("arn:aws:iam::%s:instance-profile/%s", account, name)
}

// BuildIAMUserARN: arn:aws:iam::<account>:user/<name>
func BuildIAMUserARN(account, name string) string {
	return fmt.Sprintf("arn:aws:iam::%s:user/%s", account, name)
}

// BuildS3BucketARN: arn:aws:s3:::<bucket>
// S3 ARNs encode neither account nor region — buckets live in a global
// namespace at the wire level, even though buckets are region-scoped.
func BuildS3BucketARN(bucket string) string {
	return fmt.Sprintf("arn:aws:s3:::%s", bucket)
}

// BuildS3ObjectARN: arn:aws:s3:::<bucket>/<key>
func BuildS3ObjectARN(bucket, key string) string {
	return fmt.Sprintf("arn:aws:s3:::%s/%s", bucket, key)
}

// BuildEC2InstanceARN: arn:aws:ec2:<region>:<account>:instance/<id>
func BuildEC2InstanceARN(region, account, id string) string {
	return fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", region, account, id)
}

// BuildEC2VPCARN: arn:aws:ec2:<region>:<account>:vpc/<id>
func BuildEC2VPCARN(region, account, id string) string {
	return fmt.Sprintf("arn:aws:ec2:%s:%s:vpc/%s", region, account, id)
}

// BuildEC2SubnetARN: arn:aws:ec2:<region>:<account>:subnet/<id>
func BuildEC2SubnetARN(region, account, id string) string {
	return fmt.Sprintf("arn:aws:ec2:%s:%s:subnet/%s", region, account, id)
}

// BuildEC2SecurityGroupARN: arn:aws:ec2:<region>:<account>:security-group/<id>
func BuildEC2SecurityGroupARN(region, account, id string) string {
	return fmt.Sprintf("arn:aws:ec2:%s:%s:security-group/%s", region, account, id)
}

// BuildEC2InternetGatewayARN: arn:aws:ec2:<region>:<account>:internet-gateway/<id>
func BuildEC2InternetGatewayARN(region, account, id string) string {
	return fmt.Sprintf("arn:aws:ec2:%s:%s:internet-gateway/%s", region, account, id)
}

// BuildEC2RouteTableARN: arn:aws:ec2:<region>:<account>:route-table/<id>
func BuildEC2RouteTableARN(region, account, id string) string {
	return fmt.Sprintf("arn:aws:ec2:%s:%s:route-table/%s", region, account, id)
}

// BuildEC2EIPARN: arn:aws:ec2:<region>:<account>:elastic-ip/<allocation-id>
// Used by /mock/state's EC2 gather (Codex pass 10 BLOCKING #2 fix). Real
// AWS doesn't surface EIP ARNs on the wire, but topology_derive_aws keys
// off the canonical resource shape.
func BuildEC2EIPARN(region, account, allocationID string) string {
	return fmt.Sprintf("arn:aws:ec2:%s:%s:elastic-ip/%s", region, account, allocationID)
}

// BuildRDSDBARN: arn:aws:rds:<region>:<account>:db:<id>
// Note: RDS uses ':' as the separator between resource-type and id,
// not '/' like most other services. Caught a real provider parse error
// in fakegcp testing that also applies here.
func BuildRDSDBARN(region, account, id string) string {
	return fmt.Sprintf("arn:aws:rds:%s:%s:db:%s", region, account, id)
}

// BuildRDSClusterARN: arn:aws:rds:<region>:<account>:cluster:<id>
func BuildRDSClusterARN(region, account, id string) string {
	return fmt.Sprintf("arn:aws:rds:%s:%s:cluster:%s", region, account, id)
}

// BuildRDSSubnetGroupARN: arn:aws:rds:<region>:<account>:subgrp:<name>
func BuildRDSSubnetGroupARN(region, account, name string) string {
	return fmt.Sprintf("arn:aws:rds:%s:%s:subgrp:%s", region, account, name)
}

// BuildRDSParameterGroupARN: arn:aws:rds:<region>:<account>:pg:<name>
func BuildRDSParameterGroupARN(region, account, name string) string {
	return fmt.Sprintf("arn:aws:rds:%s:%s:pg:%s", region, account, name)
}

// BuildRDSClusterParameterGroupARN: arn:aws:rds:<region>:<account>:cluster-pg:<name>
func BuildRDSClusterParameterGroupARN(region, account, name string) string {
	return fmt.Sprintf("arn:aws:rds:%s:%s:cluster-pg:%s", region, account, name)
}

// BuildEKSClusterARN: arn:aws:eks:<region>:<account>:cluster/<name>
func BuildEKSClusterARN(region, account, name string) string {
	return fmt.Sprintf("arn:aws:eks:%s:%s:cluster/%s", region, account, name)
}

// BuildEKSNodegroupARN: arn:aws:eks:<region>:<account>:nodegroup/<cluster>/<nodegroup>/<id>
// The trailing /<id> is a random uuid suffix that real EKS attaches; we
// pass it explicitly so callers control determinism in tests.
func BuildEKSNodegroupARN(region, account, cluster, nodegroup, id string) string {
	return fmt.Sprintf("arn:aws:eks:%s:%s:nodegroup/%s/%s/%s", region, account, cluster, nodegroup, id)
}

// BuildSQSQueueARN: arn:aws:sqs:<region>:<account>:<name>
// SQS omits the resource-type prefix entirely.
func BuildSQSQueueARN(region, account, name string) string {
	return fmt.Sprintf("arn:aws:sqs:%s:%s:%s", region, account, name)
}

// BuildSecretsManagerSecretARN: arn:aws:secretsmanager:<region>:<account>:secret:<name>-<random>
// Real Secrets Manager appends a 6-char random suffix; tests pass a
// deterministic suffix so assertions are stable.
func BuildSecretsManagerSecretARN(region, account, name, randomSuffix string) string {
	return fmt.Sprintf("arn:aws:secretsmanager:%s:%s:secret:%s-%s", region, account, name, randomSuffix)
}

// BuildDynamoDBTableARN: arn:aws:dynamodb:<region>:<account>:table/<name>
func BuildDynamoDBTableARN(region, account, name string) string {
	return fmt.Sprintf("arn:aws:dynamodb:%s:%s:table/%s", region, account, name)
}

// BuildRoute53HostedZoneARN: arn:aws:route53:::hostedzone/<id>
// Route53 is global — no region, no account.
func BuildRoute53HostedZoneARN(id string) string {
	return fmt.Sprintf("arn:aws:route53:::hostedzone/%s", id)
}

// BuildSSMParameterARN: arn:aws:ssm:<region>:<account>:parameter/<name>
// A hierarchical name's leading '/' is not doubled. AWS public
// parameters (/aws/service/...) have an empty account segment.
func BuildSSMParameterARN(region, account, name string) string {
	return fmt.Sprintf("arn:aws:ssm:%s:%s:parameter/%s", region, account, strings.TrimPrefix(name, "/"))
}

// BuildKMSKeyARN: arn:aws:kms:<region>:<account>:key/<key-id>
func BuildKMSKeyARN(region, account, keyID string) string {
	return fmt.Sprintf("arn:aws:kms:%s:%s:key/%s", region, account, keyID)
}
