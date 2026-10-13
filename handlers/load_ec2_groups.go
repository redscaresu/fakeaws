package handlers

// load_ec2_groups.go — the loaders of security groups and their rules:
// each group with its recorded id, owner and tags, and each rule with
// its recorded sgr- id. A group's permissions are its rules': the
// rendering diff refuses a group whose recorded ipPermissions are not
// the aggregate of its recorded rules. A loaded VPC's default group is
// the recorded one: repository.BackfillDefaultGroups mints none on a
// loaded database.

import (
	"errors"
	"fmt"

	"github.com/redscaresu/fakeaws/models"
	"github.com/redscaresu/fakeaws/repository"
)

func init() {
	registerLoader(loader{key: LoadKey{"ec2", "DescribeSecurityGroups"}, table: "ec2_security_groups",
		requestToken: "NextToken", responseToken: "nextToken",
		decode: decodeSecurityGroups, render: renderSecurityGroups})
	registerLoader(loader{key: LoadKey{"ec2", "DescribeSecurityGroupRules"}, table: "ec2_security_group_rules",
		requestToken: "NextToken", responseToken: "nextToken",
		decode: decodeSecurityGroupRules, render: renderSecurityGroupRules})
	// A rule's ARN: the rule resources and data source build arn from
	// region, account and id, and never read SecurityGroupRuleArn.
	registerIgnores(IgnoreEntry{Key: LoadKey{"ec2", "DescribeSecurityGroupRules"}, Path: "securityGroupRuleSet/item/securityGroupRuleArn",
		Cite: "terraform-provider-aws@v5.100.0/internal/service/ec2/vpc_security_group_ingress_rule.go"})
}

// decodeSecurityGroups loads each group with its tags and its recorded
// securityGroupArn, none when it holds none, refusing one whose VPC no
// exchange loaded. Its permissions load from its rules. No creation
// time: the answer holds none.
func decodeSecurityGroups(env *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
	var body ec2DescribeSecurityGroupsResult
	if err := decodeEC2(ex, &body); err != nil {
		return nil, err
	}
	items := make([]loadItem, len(body.SecurityGroupSet))
	for i, x := range body.SecurityGroupSet {
		sg := &repository.EC2SecurityGroup{ID: x.GroupId, VPCID: x.VpcId, GroupName: x.GroupName, Description: x.GroupDesc,
			Region: env.Region, OwnerID: x.OwnerId, ARN: x.SecurityGroupArn}
		ref := loadRef{"security-group", x.GroupId}
		items[i] = loadItem{loadRef: ref, Path: "securityGroupInfo/item", Index: i,
			write: ec2Write(env, ec2TagsFromXML(ref, x.TagSet), func(tx *repository.LoadTx) error {
				err := tx.PutSecurityGroup(env.Account, sg)
				if errors.Is(err, models.ErrNotFound) {
					return loadRefusal(fmt.Sprintf("security-group %s names vpc %s, which no exchange loaded", sg.ID, sg.VPCID))
				}
				return err
			})}
	}
	return items, nil
}

func renderSecurityGroups(tx *repository.LoadTx, ids []string) ([]byte, error) {
	out := ec2DescribeSecurityGroupsResult{SecurityGroupSet: []ec2SecurityGroupXML{}}
	for _, id := range ids {
		sg, err := tx.SecurityGroup(id)
		if err != nil {
			return nil, err
		}
		rules, err := tx.SecurityGroupRules(id)
		if err != nil {
			return nil, err
		}
		tags, err := ec2TagSet(tx, id)
		if err != nil {
			return nil, err
		}
		x := ec2SecurityGroupToXML(sg, tags)
		x.IpPermissions, x.IpPermsEgress = sgPermissions(rules)
		out.SecurityGroupSet = append(out.SecurityGroupSet, x)
	}
	return ec2Body("DescribeSecurityGroups", &out), nil
}

// decodeSecurityGroupRules loads each rule with its tags after its
// group's rules recorded before it, refusing one whose group did not
// load (no exchange held it, or its own load was refused) and one
// repeating the source another rule of its permission holds. An all-traffic rule (ip protocol -1) is stored with ports 0,
// which terraform-provider-aws's revoke of it sends; both Describes
// answer it as recorded whatever its ports.
func decodeSecurityGroupRules(env *loadEnvelope, ex *loadExchange) ([]loadItem, error) {
	var body ec2DescribeSecurityGroupRulesResult
	if err := decodeEC2(ex, &body); err != nil {
		return nil, err
	}
	items := make([]loadItem, len(body.Rules))
	for i, x := range body.Rules {
		rule := repository.EC2SecurityGroupRule{
			ID: x.SecurityGroupRuleId, GroupID: x.GroupId, GroupOwnerID: x.GroupOwnerId, IsEgress: x.IsEgress,
			IPProtocol: x.IpProtocol, FromPort: x.FromPort, ToPort: x.ToPort,
			CidrIPv4: x.CidrIpv4, CidrIPv6: x.CidrIpv6, PrefixListID: x.PrefixListId, Description: x.Description,
		}
		if g := x.ReferencedGroupInfo; g != nil {
			rule.ReferencedGroupID, rule.ReferencedUserID = g.GroupId, g.UserId
		}
		if rule.IPProtocol == ec2AllProtocols {
			rule.FromPort, rule.ToPort = 0, 0
		}
		ref := loadRef{"security-group-rule", x.SecurityGroupRuleId}
		items[i] = loadItem{loadRef: ref, Path: "securityGroupRuleSet/item", Index: i, Refs: sgRuleRefs(env.Account, rule),
			write: ec2Write(env, ec2TagsFromXML(ref, x.TagSet), func(tx *repository.LoadTx) error {
				err := tx.PutSecurityGroupRule(env.Account, env.Region, rule)
				switch {
				case errors.Is(err, models.ErrNotFound):
					return loadRefusal(fmt.Sprintf("security-group-rule %s names security-group %s, which did not load", rule.ID, rule.GroupID))
				case errors.Is(err, repository.ErrSourceHeld):
					return loadRefusal(fmt.Sprintf("security-group-rule %s repeats a source another rule of security-group %s holds", rule.ID, rule.GroupID))
				}
				return err
			})}
	}
	return items, nil
}

// sgRuleRefs is the row rule's source names: a group of account (its
// userId account or none), which must be loaded; or another account's
// group or a prefix list, which the reader never reads, named
// unresolved.
func sgRuleRefs(account string, rule repository.EC2SecurityGroupRule) []loadReference {
	switch {
	case rule.ReferencedGroupID != "":
		other := rule.ReferencedUserID != "" && rule.ReferencedUserID != account
		return []loadReference{{loadRef: loadRef{"security-group", rule.ReferencedGroupID}, Unread: other}}
	case rule.PrefixListID != "":
		return []loadReference{{loadRef: loadRef{"prefix-list", rule.PrefixListID}, Unread: true}}
	}
	return nil
}

func renderSecurityGroupRules(tx *repository.LoadTx, ids []string) ([]byte, error) {
	var out ec2DescribeSecurityGroupRulesResult
	for _, id := range ids {
		r, err := tx.SecurityGroupRule(id)
		if err != nil {
			return nil, err
		}
		x := ec2SecurityGroupRuleToXML(r)
		if x.TagSet, err = ec2TagSet(tx, id); err != nil {
			return nil, err
		}
		out.Rules = append(out.Rules, x)
	}
	return ec2Body("DescribeSecurityGroupRules", &out), nil
}
