// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestConfiguredDeletePackageExecutionRulesDefaultsFalse(t *testing.T) {
	if configuredDeletePackageExecutionRules(types.BoolNull()) {
		t.Fatal("null provider setting should default to false")
	}
	if !configuredDeletePackageExecutionRules(types.BoolValue(true)) {
		t.Fatal("explicit true provider setting should be preserved")
	}
}

func TestPackageRuleDeleteRequestUsesProviderSetting(t *testing.T) {
	for _, deleteChildren := range []bool{false, true} {
		req := packageRuleDeleteRequest(42, deleteChildren)
		if got := req.GetRuleId(); got != 42 {
			t.Fatalf("rule ID = %d, want 42", got)
		}
		if got := req.GetDeleteExecutionRules(); got != deleteChildren {
			t.Fatalf("DeleteExecutionRules = %v, want %v", got, deleteChildren)
		}
	}
}

func TestAccPackageRule(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccPackageRuleResourceConfig("wget", "global"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_workshop_package_rule.test", "name", "wget"),
					resource.TestCheckResourceAttr("nps_workshop_package_rule.test", "tag", "global"),
					resource.TestCheckResourceAttr("nps_workshop_package_rule.test", "source", "PACKAGE_SOURCE_HOMEBREW"),
					resource.TestCheckResourceAttr("nps_workshop_package_rule.test", "policy", "ALLOWLIST"),
					resource.TestCheckResourceAttr("nps_workshop_package_rule.test", "rule_type", "SIGNINGID"),
				),
			},
			// ImportState testing
			{
				ResourceName:      "nps_workshop_package_rule.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccPackageRuleResourceConfig(name string, tag string) string {
	return fmt.Sprintf(`
provider "nps" {
  endpoint = "localhost:8080"
}

resource "nps_workshop_package_rule" "test" {
  name      = %[1]q
  tag       = %[2]q
  source    = "PACKAGE_SOURCE_HOMEBREW"
  policy    = "ALLOWLIST"
  rule_type = "SIGNINGID"
}
`, name, tag)
}
