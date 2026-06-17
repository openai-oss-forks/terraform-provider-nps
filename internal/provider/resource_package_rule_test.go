// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccPackageRule(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccPackageRuleResourceConfig("wget", "global", ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_workshop_package_rule.test", "name", "wget"),
					resource.TestCheckResourceAttr("nps_workshop_package_rule.test", "tag", "global"),
					resource.TestCheckResourceAttr("nps_workshop_package_rule.test", "source", "PACKAGE_SOURCE_HOMEBREW"),
					resource.TestCheckResourceAttr("nps_workshop_package_rule.test", "policy", "ALLOWLIST"),
					resource.TestCheckResourceAttr("nps_workshop_package_rule.test", "rule_type", "SIGNINGID"),
				),
			},
			// Update testing exercises CreatePackageRule's upsert behavior.
			{
				Config: testAccPackageRuleResourceConfig("wget", "global", "^1\\."),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_workshop_package_rule.test", "version_regexp", "^1\\."),
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

func testAccPackageRuleResourceConfig(name string, tag string, versionRegexp string) string {
	return fmt.Sprintf(`
provider "nps" {
  endpoint = "localhost:8080"
}

resource "nps_workshop_package_rule" "test" {
  name           = %[1]q
  tag            = %[2]q
  source         = "PACKAGE_SOURCE_HOMEBREW"
  policy         = "ALLOWLIST"
  rule_type      = "SIGNINGID"
  version_regexp = %[3]q
}
`, name, tag, versionRegexp)
}
