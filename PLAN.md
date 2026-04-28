# fakeaws PLAN

Live design notes per phase. Concepts.md is the load-bearing
architecture doc; this file captures phase-specific design
conversations + the FK-chain analyses that gate handler ordering.

## Phase 1 — Foundation + integration (S43)

Status: COMPLETE. Notes:

- Day-1 invariant landed in S43-T1; `.gitleaks.toml` adds a custom
  strict AWS-key rule overriding gitleaks 8.x's default allowlist of
  the canonical `AKIAIOSFODNN7EXAMPLE` placeholder. Documentation
  references in `*.md` files are explicitly allowlisted (the canonical
  string is needed to document the gate itself).
- Per-service ARN builders (S43-T2) — IAM omits region; S3 + Route53
  are global; RDS uses `:` separator (not `/`); SQS omits the
  resource-type prefix entirely; Secrets Manager appends a 6-char
  random suffix. The earlier "single generic ARN format" design was
  retracted in concepts.md "Resolved decisions" item 13 because no
  uniform shape works across services.
- Repository pattern (S43-T3) — service tables append via init() to
  `registeredMigrations` + `prependResetTables`. Adding a service is
  one Go file plus the per-service handler file. SetMaxOpenConns(1)
  is mandatory for FK enforcement, not a guideline.
- IAM Query-RPC + S3 XML wire formats both proven through the
  awsproto layer (S43-T6, S43-T8). Refactor in S43-T6 swapped
  `xml.Marshal(anonymous-struct)` for `xml.NewEncoder(named-types)`
  — anonymous structs silently produce empty output.

## Phase 2 — Networking + compute (S44)

EC2 is the largest service in the v1 surface — 6 networking
resources + instance lifecycle + key pair + AMI fixtures.

### Wire format

EC2 uses Query-RPC (POST `Action=Foo&Version=2016-11-15&...`) with
XML responses. The same wire-format helpers from S43-T2
(`awsproto.ParseQueryRPC`, `awsproto.WriteQueryRPCResponse`,
`awsproto.WriteAWSError(w, ShapeQueryRPC, err)`) carry over directly
— EC2 is the second service to use the Query-RPC family after IAM.
No new wire-format work.

EC2 endpoint convention: per-region. fakeaws routes EC2 at
`/ec2/region/<region>` so chi's URLParam can pull the region from
the path. terraform-provider-aws's `endpoints { ec2 = ... }` block
points the SDK at our path-style endpoint.

### Schema (S44-T3 + S44-T6)

Two table batches — networking lands first (T3) so security/instance
FK chains compile against existing parents:

```sql
-- S44-T3: networking
ec2_vpcs              (account_id, id)               -- top-level
                      cidr_block, region, arn
ec2_subnets           (account_id, vpc_id, id)       -- child of vpc
                      cidr_block, availability_zone, region, arn
                      ON DELETE CASCADE
ec2_internet_gateways (account_id, id)               -- top-level (vpc_id nullable)
                      vpc_id (FK → ec2_vpcs.id, nullable)
                      arn
                      ON DELETE SET NULL on vpc_id (detach-on-vpc-delete)
ec2_route_tables      (account_id, vpc_id, id)       -- child of vpc
                      arn
                      ON DELETE CASCADE
ec2_route_table_associations (account_id, route_table_id, subnet_id)
                      ON DELETE CASCADE on both sides
ec2_routes            (account_id, route_table_id, destination_cidr_block)
                      gateway_id, nat_gateway_id, instance_id (each FK + nullable)
                      ON DELETE CASCADE on route_table
ec2_eips              (account_id, allocation_id)    -- top-level
                      domain ('vpc' v1-only), public_ip, network_interface_id (nullable)

-- S44-T6: compute
ec2_security_groups   (account_id, vpc_id, id)       -- child of vpc
                      ingress, egress (JSON columns), arn
                      ON DELETE CASCADE
ec2_instances         (account_id, region, id)       -- top-level
                      subnet_id (FK), ami_id, instance_type,
                      iam_instance_profile_name (FK → iam_instance_profiles, nullable),
                      vpc_security_group_ids (JSON), arn, state
                      ON DELETE RESTRICT on subnet_id (subnet-with-instances rejects delete)
ec2_key_pairs         (account_id, region, name)
                      public_key, fingerprint
ec2_amis              (account_id, region, id)       -- read-only fixture set
                      name, owner_id, virtualization_type, root_device_name
```

### FK chain (the load-bearing part)

EC2's correctness story is FK chains — getting these wrong is the
single biggest class of regression in fakegcp's pass-loop history.

```
                    ec2_vpcs
                       │
        ┌──────────────┼─────────────┐
        │              │             │
   ec2_subnets  ec2_route_tables  ec2_security_groups
        │              │
   ec2_instances  ec2_routes
                       │
                       ▼
              (gateway_id / nat / instance)
```

Plus cross-resource refs that don't fit a single parent FK:
- `ec2_instances.iam_instance_profile_name` → `iam_instance_profiles`
  (cross-service FK; uses `resolveSameAccountName` from S43-T3).
- `ec2_instances.subnet_id` is enforced by the subnet FK — but
  `ec2_instances.vpc_security_group_ids` is JSON, validated by the
  handler at create/update time.

### Subnet/VPC pairing contract (S44-T8 regression)

Per concepts.md "Standing patterns" item 4: when a caller passes
both a VPC ref and a subnet ref (e.g., RunInstances with both
`SubnetId` and `vpc_security_group_ids` referencing different VPCs),
the subnet's stored parent VPC MUST match the VPC its security
groups live in. Mismatched pair → 404. This is the load-bearing
fakegcp pass-27 finding ported to AWS.

### Route-table association is an explicit table

Per the S44-T0 pitfall — `aws_route_table_association` is a separate
resource, not a `subnet_id` on the route table. Schema reflects
this: `ec2_route_table_associations` is a 3-column join table (with
its own PK) so multiple subnets can share a route table cleanly.

### EC2 instance state machine

State machine collapsed to "always running" except where the AWS
provider expects to wait. The state column tracks
`pending → running → shutting-down → terminated`. The TerminateInstances
handler refuses transitions out of `terminated` (concepts.md
"Standing patterns" item 9 — terminal-state refusal).

### AMI fixture data

AMIs are read-only at v1. handlers/ec2_instance.go ships a
hand-curated fixture map (`ami-0abcd1234` etc.) that DescribeImages
returns. terraform-provider-aws's `data.aws_ami` is NOT supported —
scenarios use literal AMI ids per the S44-T0 pitfall.

### Endpoints (handlers split into 3 files)

- handlers/ec2_network.go (S44-T4): VPC, Subnet, InternetGateway,
  RouteTable, Route, RouteTableAssociation, EIP, NAT gateway.
- handlers/ec2_security.go (S44-T5): SecurityGroup +
  AuthorizeSecurityGroupIngress / Revoke /  AuthorizeEgress / Revoke.
- handlers/ec2_instance.go (S44-T7): RunInstances / DescribeInstances /
  ModifyInstanceAttribute / TerminateInstances, KeyPair create/describe/
  delete, AMI describe (fixture).

The EC2 dispatcher in handlers/ec2.go (single file, registered via
registerEC2Routes) parses the Query-RPC Action and dispatches to the
right per-file handler. Same pattern as IAM (handlers/iam.go) but
split because EC2's surface is too large for one file.

### What lands when

  S44-T3   ec2_network tables (vpcs, subnets, igws, route tables, eips)
  S44-T4   handlers/ec2_network.go (CRUD)
  S44-T5   handlers/ec2_security.go (SG + rules)
  S44-T6   ec2_instances + ec2_key_pairs + ec2_amis tables
  S44-T7   handlers/ec2_instance.go (RunInstances + Terminate state machine)
  S44-T8   handlers_test.go for EC2 (CRUD + FK + cascade + state)
  S44-T9   regression coverage — flips ec2 on in handlers/regression_manifest.go::LandedServices,
           lighting up tests 4 (subnet/VPC pairing), 5 (post-merge PATCH),
           6 (bare-name region), 7 (region-vs-zone), 15 (sql-column sync).
  S44-T10  scenarios/training/aws-vpc-network.yaml + aws-instance.yaml
  S44-T11  examples/working/{basic_instance,vpc_network} +
           examples/misconfigured/instance_missing_subnet +
           examples/updates/update_security_group_rules
  S44-T12  gated TestE2E_AWS_VPC + TestE2E_AWS_Instance + TestE2E_AWS_SecurityGroup;
           same PR adds 8 EC2 entries to coverage_matrix.yaml.

## Phase 3 — Stateful data (S45)

RDS and DynamoDB. Two services with very different wire formats:

- RDS speaks Query-RPC with XML responses (same family as IAM/EC2,
  Version=2014-10-31). Endpoint: per-region at `/rds/region/<region>`.
  Reuses awsproto's QueryRPC helpers — no new wire-format work.
- DynamoDB speaks JSON 1.0 with x-amz-target headers (Action via
  `X-Amz-Target: DynamoDB_20120810.<Action>`). Endpoint:
  per-region at `/dynamodb/region/<region>`. Reuses
  awsproto.ParseXAmzTarget + WriteJSONResponse from S43-T2.

### RDS schema (S45-T2)

```sql
rds_db_subnet_groups   (account_id, name)
                       region, description, subnet_ids (JSON), vpc_id, arn
                       NB: vpc_id is derived from subnet_ids at create
                       (validated to be the SAME vpc for all subnets;
                       PLAN.md S45-T0 pitfall — DBSubnetGroupNotFound
                       and "subnets must be in the same VPC" both fire
                       at this layer).
                       FK: each subnet_id must exist in ec2_subnets;
                       enforced at handler create time, not via
                       SQLite FK (SQLite can't FK into a JSON column).
rds_db_parameter_groups       (account_id, name)
                              family, description, arn
rds_db_cluster_parameter_groups (account_id, name)
                                family, description, arn
rds_db_clusters        (account_id, region, id)
                       engine, engine_version, subnet_group_name (FK),
                       cluster_parameter_group_name (FK, nullable),
                       master_username, deletion_protection, arn,
                       state ('available' v1)
                       FK: subnet_group_name → rds_db_subnet_groups.name
                       (SET NULL on subnet group delete is unsafe — RESTRICT)
rds_db_instances       (account_id, region, id)
                       engine, engine_version, instance_class,
                       subnet_group_name (FK, nullable),
                       cluster_id (FK, nullable for solo instances),
                       parameter_group_name (FK, nullable),
                       replicate_source_db (FK to rds_db_instances.id, nullable),
                       deletion_protection, skip_final_snapshot, arn,
                       state ('available' v1)
                       FK: cluster_id → rds_db_clusters.id
                       FK: replicate_source_db → rds_db_instances.id
                       Source-with-replicas delete must RESTRICT until
                       replicas are gone (S45-T0 pitfall).
```

### DynamoDB schema (S45-T4)

```sql
dynamodb_tables        (account_id, region, name)
                       hash_key, range_key (nullable),
                       attributes (JSON: [{name,type}]),
                       billing_mode ('PAY_PER_REQUEST' default at v1),
                       arn, status ('ACTIVE' v1)
dynamodb_items         (account_id, table_name, hash_value, range_value)
                       item (JSON blob — full item)
                       PRIMARY KEY (account_id, table_name, hash_value, range_value)
                       FOREIGN KEY (account_id, table_name) REFERENCES dynamodb_tables ON DELETE CASCADE
                       NB: range_value is "" (empty string) when the
                       table has no range key — keeps the PK shape
                       uniform. GSI/LSI explicitly NOT modelled at v1.
```

### State machines (collapsed)

- RDS instance / cluster: state defaults to "available" on create.
  No "creating"/"backing-up" intermediate states at v1 — handlers
  return success synchronously, mirror of fakegcp's collapsed Cloud
  SQL state machine.
- DynamoDB table: status defaults to "ACTIVE" on create.
- DeleteDBInstance with `deletion_protection=true` rejects with
  `InvalidParameterCombination` (concepts.md "Standing patterns"
  item 9).

### What lands when

  S45-T0   pitfalls (DONE — infrafactory@732bc0e)
  S45-T1   this design note (this commit)
  S45-T2   repository/rds.go (5 tables + CRUD)
  S45-T3   handlers/rds.go (Query-RPC dispatcher: instance + cluster +
           subnet_group + parameter_group + cluster_parameter_group)
  S45-T4   repository/dynamodb.go (2 tables + item PK index)
  S45-T5   handlers/dynamodb.go (table CRUD + item PutItem/GetItem/
           UpdateItem/DeleteItem/Query/Scan)
  S45-T6   handlers_test.go for RDS + DynamoDB
  S45-T7   regression coverage for RDS read-replica chain +
           DynamoDB table-state transitions
  S45-T8   scenarios/training/aws-rds.yaml + aws-dynamodb.yaml
  S45-T9   examples/working/{rds_instance,dynamodb_table} + matching
           misconfigured + updates dirs
  S45-T10  gated TestE2E_AWS_RDS + TestE2E_AWS_DynamoDB; same PR adds
           coverage_matrix.yaml entries.

## Phase 4 — Containers + queues (S46)

EKS and SQS. Two more disparate wire formats.

- **EKS** speaks JSON-REST (path-based routing, `application/json`,
  no x-amz-target). Endpoint convention: `/eks/region/<region>/...`
  matches AWS's actual REST shape (e.g., `/clusters`,
  `/clusters/{name}/node-groups`).
- **SQS** speaks JSON 1.0 with x-amz-target (post-2023 protocol
  modernization). Endpoint: `/sqs/region/<region>` with
  `X-Amz-Target: AmazonSQS.<Operation>`. queue_url returned by
  CreateQueue uses the same path-style URL.

### EKS schema (S46-T2)

```sql
eks_clusters     (account_id, region, name)
                 role_arn (FK → iam_roles.arn — cross-service handler check),
                 subnet_ids (JSON), security_group_ids (JSON),
                 status ('ACTIVE' v1), arn, kubernetes_version
eks_node_groups  (account_id, cluster_name, name)
                 node_role_arn (cross-service IAM FK),
                 subnet_ids (JSON, must be subset of cluster's),
                 status, arn, instance_types (JSON), scaling_config (JSON)
                 ON DELETE CASCADE on cluster_name
eks_addons       (account_id, cluster_name, name)
                 version, status
                 ON DELETE CASCADE on cluster_name
```

### SQS schema (S46-T4)

```sql
sqs_queues   (account_id, region, name)
             queue_url, arn, attributes (JSON)
             — attributes covers VisibilityTimeout, MessageRetentionPeriod,
               RedrivePolicy (JSON-encoded string per S46-T0 pitfall),
               FifoQueue boolean, etc.
sqs_messages (account_id, queue_arn, message_id)
             body, attributes, receipt_handle (re-issued each Receive),
             visible_after (timestamp), receive_count
             — visibility timeout collapsed: messages are immediately
               re-visible after Delete or after the timeout elapses.
             ON DELETE CASCADE on queue (re-bagging tombstone covered
             in S48 if needed)
```

### State machines (collapsed)

- EKS cluster: status defaults to "ACTIVE" on create. No "CREATING"
  intermediate state at v1.
- SQS messages: in-flight tracking is best-effort; ReceiveMessage
  bumps receive_count and re-issues a receipt_handle. DeleteMessage
  removes by receipt_handle. visibility_timeout is honoured but
  collapsed (no scheduled re-delivery — Receive returns nothing if
  no visible messages).

### What lands when

  S46-T0   pitfalls (DONE — infrafactory@c4e121e)
  S46-T1   this design note (this commit)
  S46-T2   repository/eks.go (3 tables + CRUD with cross-service IAM checks)
  S46-T3   handlers/eks.go (JSON-REST dispatcher: cluster + nodegroup + addon)
  S46-T4   repository/sqs.go (queues + messages + visibility timeout)
  S46-T5   handlers/sqs.go (JSON 1.0 + x-amz-target dispatcher)
  S46-T6   handlers_test.go for EKS + SQS
  S46-T7   regression coverage for EKS dependency chain + SQS DLQ
  S46-T8   scenarios/training/aws-eks.yaml + aws-sqs.yaml
  S46-T9   examples/working/{eks_cluster,sqs_queue} + matching
           misconfigured + updates dirs
  S46-T10  gated TestE2E_AWS_EKS + TestE2E_AWS_SQS; coverage matrix entries.

Phase 5+ design notes will be written as those phases land.
