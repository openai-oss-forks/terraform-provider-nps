// Copyright 2025 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"
	"testing"

	frameworkresource "github.com/hashicorp/terraform-plugin-framework/resource"
	frameworkschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	apipb "buf.build/gen/go/northpolesec/workshop-api/protocolbuffers/go/workshop/v1"
)

func TestRuleBlockReasonIsOptionalAndComputed(t *testing.T) {
	var resp frameworkresource.SchemaResponse
	(&RuleResource{}).Schema(context.Background(), frameworkresource.SchemaRequest{}, &resp)

	attr, ok := resp.Schema.Attributes["block_reason"].(frameworkschema.StringAttribute)
	if !ok {
		t.Fatalf("block_reason schema type = %T, want schema.StringAttribute", resp.Schema.Attributes["block_reason"])
	}
	if !attr.Optional || !attr.Computed {
		t.Fatalf("block_reason Optional=%v Computed=%v, want both true", attr.Optional, attr.Computed)
	}
}

func TestApplyRuleBlockReason(t *testing.T) {
	rule := apipb.Rule_builder{}.Build()
	applyRuleBlockReason(rule, types.StringValue("BLOCK_REASON_MALICIOUS"))
	if got := rule.GetBlockReason(); got != apipb.Rule_BLOCK_REASON_MALICIOUS {
		t.Fatalf("block reason = %s, want BLOCK_REASON_MALICIOUS", got)
	}

	rule = apipb.Rule_builder{}.Build()
	applyRuleBlockReason(rule, types.StringNull())
	if got := rule.GetBlockReason(); got != apipb.Rule_BLOCK_REASON_UNSPECIFIED {
		t.Fatalf("null block reason = %s, want BLOCK_REASON_UNSPECIFIED", got)
	}
}

func TestPlannedRuleBlockReason(t *testing.T) {
	tests := []struct {
		name       string
		policy     types.String
		configured types.String
		want       types.String
	}{
		{
			name:       "blocking default",
			policy:     types.StringValue("BLOCKLIST"),
			configured: types.StringNull(),
			want:       types.StringValue("BLOCK_REASON_POLICY"),
		},
		{
			name:       "silent blocking default",
			policy:     types.StringValue("SILENT_BLOCKLIST"),
			configured: types.StringNull(),
			want:       types.StringValue("BLOCK_REASON_POLICY"),
		},
		{
			name:       "non-blocking clear",
			policy:     types.StringValue("ALLOWLIST"),
			configured: types.StringNull(),
			want:       types.StringNull(),
		},
		{
			name:       "explicit malicious",
			policy:     types.StringValue("BLOCKLIST"),
			configured: types.StringValue("BLOCK_REASON_MALICIOUS"),
			want:       types.StringValue("BLOCK_REASON_MALICIOUS"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := plannedRuleBlockReason(tt.policy, tt.configured); !got.Equal(tt.want) {
				t.Fatalf("planned block reason = %s, want %s", got, tt.want)
			}
		})
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
