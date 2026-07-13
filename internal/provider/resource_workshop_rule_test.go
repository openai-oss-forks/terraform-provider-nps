// Copyright 2025 North Pole Security, Inc.
package provider

import (
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"google.golang.org/protobuf/types/known/timestamppb"

	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

func TestFilterManagedRulesExcludesRemoveTombstones(t *testing.T) {
	active := apipb.Rule_builder{RuleId: "active", Policy: apipb.Policy_ALLOWLIST}.Build()
	tombstone := apipb.Rule_builder{RuleId: "removed", Policy: apipb.Policy_REMOVE}.Build()

	got := filterManagedRules([]*apipb.Rule{nil, tombstone, active})
	if len(got) != 1 || got[0].GetRuleId() != "active" {
		t.Fatalf("filterManagedRules() = %v, want only active rule", got)
	}
}

func TestSelectManagedRulePrefersNewestActiveLogicalMatch(t *testing.T) {
	data := RuleResourceModel{
		Id:         types.StringValue("old-id"),
		Identifier: types.StringValue("C0DEXRM001"),
		RuleType:   types.StringValue("TEAMID"),
		Tag:        types.StringValue("validation"),
	}
	tombstone := apipb.Rule_builder{
		RuleId:     "old-id",
		Identifier: "C0DEXRM001",
		RuleType:   apipb.RuleType_TEAMID,
		Policy:     apipb.Policy_REMOVE,
		Tag:        "validation",
		CreatedAt:  timestamppb.New(time.Unix(300, 0)),
	}.Build()
	oldActive := apipb.Rule_builder{
		RuleId:     "older-active-id",
		Id:         453,
		Identifier: "C0DEXRM001",
		RuleType:   apipb.RuleType_TEAMID,
		Policy:     apipb.Policy_ALLOWLIST,
		Tag:        "validation",
		CreatedAt:  timestamppb.New(time.Unix(100, 0)),
	}.Build()
	newActive := apipb.Rule_builder{
		RuleId:     "new-active-id",
		Id:         454,
		Identifier: "C0DEXRM001",
		RuleType:   apipb.RuleType_TEAMID,
		Policy:     apipb.Policy_BLOCKLIST,
		Tag:        "validation",
		CreatedAt:  timestamppb.New(time.Unix(200, 0)),
	}.Build()

	got := selectManagedRule(data, []*apipb.Rule{tombstone, oldActive, newActive})
	if got == nil || got.GetRuleId() != "new-active-id" {
		t.Fatalf("selected rule = %v, want newest active logical match", got)
	}
}

func TestSelectManagedRuleTreatsRemoveTombstoneAsAbsent(t *testing.T) {
	data := RuleResourceModel{Id: types.StringValue("removed-id")}
	tombstone := apipb.Rule_builder{
		RuleId: "removed-id",
		Policy: apipb.Policy_REMOVE,
	}.Build()

	if got := selectManagedRule(data, []*apipb.Rule{tombstone}); got != nil {
		t.Fatalf("selected tombstone %v, want nil", got)
	}
}

func TestSelectManagedRuleFallsBackToExactActiveIDForImport(t *testing.T) {
	data := RuleResourceModel{Id: types.StringValue("imported-id")}
	other := apipb.Rule_builder{RuleId: "other-id", Policy: apipb.Policy_ALLOWLIST}.Build()
	imported := apipb.Rule_builder{RuleId: "imported-id", Policy: apipb.Policy_BLOCKLIST}.Build()

	got := selectManagedRule(data, []*apipb.Rule{other, imported})
	if got == nil || got.GetRuleId() != "imported-id" {
		t.Fatalf("selected rule = %v, want exact imported-id", got)
	}
}

func TestSelectManagedRuleBreaksEqualTimestampTieByNumericID(t *testing.T) {
	data := RuleResourceModel{
		Id:         types.StringValue("old-id"),
		Identifier: types.StringValue("C0DEXRM002"),
		RuleType:   types.StringValue("TEAMID"),
		Tag:        types.StringValue("validation"),
	}
	createdAt := timestamppb.New(time.Unix(100, 0))
	oldRule := apipb.Rule_builder{
		RuleId:     "old-id",
		Id:         453,
		Identifier: "C0DEXRM002",
		RuleType:   apipb.RuleType_TEAMID,
		Policy:     apipb.Policy_ALLOWLIST,
		Tag:        "validation",
		CreatedAt:  createdAt,
	}.Build()
	newRule := apipb.Rule_builder{
		RuleId:     "new-id",
		Id:         454,
		Identifier: "C0DEXRM002",
		RuleType:   apipb.RuleType_TEAMID,
		Policy:     apipb.Policy_ALLOWLIST,
		Tag:        "validation",
		CreatedAt:  createdAt,
	}.Build()

	got := selectManagedRule(data, []*apipb.Rule{oldRule, newRule})
	if got == nil || got.GetRuleId() != "new-id" {
		t.Fatalf("selected rule = %v, want highest numeric ID", got)
	}
}

func TestSelectManagedRulePrefersTimestampedCandidateRegardlessOfInputOrder(t *testing.T) {
	data := RuleResourceModel{
		Id:         types.StringValue("old-id"),
		Identifier: types.StringValue("C0DEXRM003"),
		RuleType:   types.StringValue("TEAMID"),
		Tag:        types.StringValue("validation"),
	}
	timestamped := apipb.Rule_builder{
		RuleId:     "timestamped-id",
		Id:         453,
		Identifier: "C0DEXRM003",
		RuleType:   apipb.RuleType_TEAMID,
		Policy:     apipb.Policy_ALLOWLIST,
		Tag:        "validation",
		CreatedAt:  timestamppb.New(time.Unix(100, 0)),
	}.Build()
	untimestamped := apipb.Rule_builder{
		RuleId:     "untimestamped-id",
		Id:         454,
		Identifier: "C0DEXRM003",
		RuleType:   apipb.RuleType_TEAMID,
		Policy:     apipb.Policy_ALLOWLIST,
		Tag:        "validation",
	}.Build()

	for _, rules := range [][]*apipb.Rule{
		{timestamped, untimestamped},
		{untimestamped, timestamped},
	} {
		got := selectManagedRule(data, rules)
		if got == nil || got.GetRuleId() != "timestamped-id" {
			t.Fatalf("selected rule = %v, want timestamped-id for input order %v", got, rules)
		}
	}
}

func TestAccWorkshopRule(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccExampleRuleResourceConfigGlobal("yes", "platform:com.apple.yes", "SIGNINGID", "BLOCKLIST", "block yes"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "identifier", "platform:com.apple.yes"),
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "rule_type", "SIGNINGID"),
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "policy", "BLOCKLIST"),
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "comment", "block yes"),
				),
			},
			{
				Config: testAccRuleResourceConfigWithTag("yes", "platform:com.apple.yes", "SIGNINGID", "BLOCKLIST", "rule-test-tag", ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "identifier", "platform:com.apple.yes"),
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "rule_type", "SIGNINGID"),
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "policy", "BLOCKLIST"),
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "tag", "rule-test-tag"),
				),
			},
			{
				Config: testAccExampleRuleResourceConfigGlobal("yes", "platform:com.apple.yes", "SIGNINGID", "BLOCKLIST", ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "identifier", "platform:com.apple.yes"),
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "rule_type", "SIGNINGID"),
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "policy", "BLOCKLIST"),
					resource.TestCheckResourceAttr("nps_workshop_rule.yes", "tag", "global"),
				),
			},
			// ImportState testing
			{
				ResourceName:            "nps_workshop_rule.yes",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"comment"},
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccExampleRuleResourceConfigGlobal(name, identifier, ruleType, policy, comment string) string {
	return fmt.Sprintf(`
provider "nps" {
  endpoint = "localhost:8080"
}

resource "nps_workshop_rule" %[1]q {
  identifier = %[2]q
  rule_type  = %[3]q
  policy     = %[4]q
	tag        = %[5]q
	comment    = %[6]q
	block_reason = %[7]q
}
`, name, identifier, ruleType, policy, "global", comment, "BLOCK_REASON_POLICY")
}

func testAccRuleResourceConfigWithTag(name, identifier, ruleType, policy, tag, comment string) string {
	return fmt.Sprintf(`
provider "nps" {
  endpoint = "localhost:8080"
}

resource "nps_workshop_tag" %[5]q {
  name = %[5]q
}

resource "nps_workshop_rule" %[1]q {
  identifier = %[2]q
  rule_type  = %[3]q
  policy     = %[4]q
  tag        = nps_workshop_tag.%[5]s.name
  comment    = %[6]q
  block_reason = %[7]q
}
`, name, identifier, ruleType, policy, tag, comment, "BLOCK_REASON_POLICY")
}
