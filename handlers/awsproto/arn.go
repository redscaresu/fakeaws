package awsproto

import "fmt"

// Per-service ARN builders. Real AWS ARN formats vary per service —
// IAM omits region, S3 is bucket-scoped, Route53 is global, EC2/RDS/
// EKS/SQS/DynamoDB embed region+account, SecretsManager appends a
// random 6-char suffix. There is no single uniform format, so the
// earlier "single generic builder" design was retracted in pass 6
// (concepts.md § "Resolved decisions" item 13).
//
// All builders use FakeAccountID as the account segment. Multi-account
// support is a v2 problem.

// BuildIAMRoleARN: arn:aws:iam::<account>:role/<name>
// IAM is global (no region segment).
func BuildIAMRoleARN(name string) string {
	return fmt.Sprintf("arn:aws:iam::%s:role/%s", FakeAccountID, name)
}

// BuildIAMPolicyARN: arn:aws:iam::<account>:policy/<name>
func BuildIAMPolicyARN(name string) string {
	return fmt.Sprintf("arn:aws:iam::%s:policy/%s", FakeAccountID, name)
}

// BuildIAMInstanceProfileARN: arn:aws:iam::<account>:instance-profile/<name>
func BuildIAMInstanceProfileARN(name string) string {
	return fmt.Sprintf("arn:aws:iam::%s:instance-profile/%s", FakeAccountID, name)
}

// BuildIAMUserARN: arn:aws:iam::<account>:user/<name>
func BuildIAMUserARN(name string) string {
	return fmt.Sprintf("arn:aws:iam::%s:user/%s", FakeAccountID, name)
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
func BuildEC2InstanceARN(region, id string) string {
	return fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", region, FakeAccountID, id)
}

// BuildEC2VPCARN: arn:aws:ec2:<region>:<account>:vpc/<id>
func BuildEC2VPCARN(region, id string) string {
	return fmt.Sprintf("arn:aws:ec2:%s:%s:vpc/%s", region, FakeAccountID, id)
}

// BuildEC2SubnetARN: arn:aws:ec2:<region>:<account>:subnet/<id>
func BuildEC2SubnetARN(region, id string) string {
	return fmt.Sprintf("arn:aws:ec2:%s:%s:subnet/%s", region, FakeAccountID, id)
}

// BuildEC2SecurityGroupARN: arn:aws:ec2:<region>:<account>:security-group/<id>
func BuildEC2SecurityGroupARN(region, id string) string {
	return fmt.Sprintf("arn:aws:ec2:%s:%s:security-group/%s", region, FakeAccountID, id)
}

// BuildEC2InternetGatewayARN: arn:aws:ec2:<region>:<account>:internet-gateway/<id>
func BuildEC2InternetGatewayARN(region, id string) string {
	return fmt.Sprintf("arn:aws:ec2:%s:%s:internet-gateway/%s", region, FakeAccountID, id)
}

// BuildEC2RouteTableARN: arn:aws:ec2:<region>:<account>:route-table/<id>
func BuildEC2RouteTableARN(region, id string) string {
	return fmt.Sprintf("arn:aws:ec2:%s:%s:route-table/%s", region, FakeAccountID, id)
}

// BuildRDSDBARN: arn:aws:rds:<region>:<account>:db:<id>
// Note: RDS uses ':' as the separator between resource-type and id,
// not '/' like most other services. Caught a real provider parse error
// in fakegcp testing that also applies here.
func BuildRDSDBARN(region, id string) string {
	return fmt.Sprintf("arn:aws:rds:%s:%s:db:%s", region, FakeAccountID, id)
}

// BuildRDSClusterARN: arn:aws:rds:<region>:<account>:cluster:<id>
func BuildRDSClusterARN(region, id string) string {
	return fmt.Sprintf("arn:aws:rds:%s:%s:cluster:%s", region, FakeAccountID, id)
}

// BuildRDSSubnetGroupARN: arn:aws:rds:<region>:<account>:subgrp:<name>
func BuildRDSSubnetGroupARN(region, name string) string {
	return fmt.Sprintf("arn:aws:rds:%s:%s:subgrp:%s", region, FakeAccountID, name)
}

// BuildRDSParameterGroupARN: arn:aws:rds:<region>:<account>:pg:<name>
func BuildRDSParameterGroupARN(region, name string) string {
	return fmt.Sprintf("arn:aws:rds:%s:%s:pg:%s", region, FakeAccountID, name)
}

// BuildRDSClusterParameterGroupARN: arn:aws:rds:<region>:<account>:cluster-pg:<name>
func BuildRDSClusterParameterGroupARN(region, name string) string {
	return fmt.Sprintf("arn:aws:rds:%s:%s:cluster-pg:%s", region, FakeAccountID, name)
}

// BuildEKSClusterARN: arn:aws:eks:<region>:<account>:cluster/<name>
func BuildEKSClusterARN(region, name string) string {
	return fmt.Sprintf("arn:aws:eks:%s:%s:cluster/%s", region, FakeAccountID, name)
}

// BuildEKSNodegroupARN: arn:aws:eks:<region>:<account>:nodegroup/<cluster>/<nodegroup>/<id>
// The trailing /<id> is a random uuid suffix that real EKS attaches; we
// pass it explicitly so callers control determinism in tests.
func BuildEKSNodegroupARN(region, cluster, nodegroup, id string) string {
	return fmt.Sprintf("arn:aws:eks:%s:%s:nodegroup/%s/%s/%s", region, FakeAccountID, cluster, nodegroup, id)
}

// BuildSQSQueueARN: arn:aws:sqs:<region>:<account>:<name>
// SQS omits the resource-type prefix entirely.
func BuildSQSQueueARN(region, name string) string {
	return fmt.Sprintf("arn:aws:sqs:%s:%s:%s", region, FakeAccountID, name)
}

// BuildSecretsManagerSecretARN: arn:aws:secretsmanager:<region>:<account>:secret:<name>-<random>
// Real Secrets Manager appends a 6-char random suffix; tests pass a
// deterministic suffix so assertions are stable.
func BuildSecretsManagerSecretARN(region, name, randomSuffix string) string {
	return fmt.Sprintf("arn:aws:secretsmanager:%s:%s:secret:%s-%s", region, FakeAccountID, name, randomSuffix)
}

// BuildDynamoDBTableARN: arn:aws:dynamodb:<region>:<account>:table/<name>
func BuildDynamoDBTableARN(region, name string) string {
	return fmt.Sprintf("arn:aws:dynamodb:%s:%s:table/%s", region, FakeAccountID, name)
}

// BuildRoute53HostedZoneARN: arn:aws:route53:::hostedzone/<id>
// Route53 is global — no region, no account.
func BuildRoute53HostedZoneARN(id string) string {
	return fmt.Sprintf("arn:aws:route53:::hostedzone/%s", id)
}
