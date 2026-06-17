// Copyright 2025 North Pole Security, Inc.
package provider

import (
	"context"
	"fmt"
	"testing"

	frameworkresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestFileAccessRuleResourceAllowsMutableIdentity(t *testing.T) {
	var resp frameworkresource.MetadataResponse
	(&FileAccessRuleResource{}).Metadata(context.Background(), frameworkresource.MetadataRequest{}, &resp)
	if !resp.ResourceBehavior.MutableIdentity {
		t.Fatal("FileAccessRuleResource must allow Workshop to return a new identity during upsert")
	}
}

func TestAccFileAccessRule(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: testAccFileAccessRuleResourceConfig("TestRule1", "global", "/tmp/"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_workshop_file_access_rule.test", "name", "TestRule1"),
					resource.TestCheckResourceAttr("nps_workshop_file_access_rule.test", "tag", "global"),
					resource.TestCheckResourceAttr("nps_workshop_file_access_rule.test", "rule_type", "PathsWithAllowedProcesses"),
					resource.TestCheckResourceAttr("nps_workshop_file_access_rule.test", "allow_read_access", "true"),
					resource.TestCheckResourceAttr("nps_workshop_file_access_rule.test", "block_violations", "false"),
				),
			},
			{
				Config: testAccFileAccessRuleResourceConfig("TestRule1", "global", "/var/tmp/"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("nps_workshop_file_access_rule.test", "path_prefixes.0", "/var/tmp/"),
				),
			},
			// ImportState testing
			{
				ResourceName:      "nps_workshop_file_access_rule.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func testAccFileAccessRuleResourceConfig(name string, tag string, pathPrefix string) string {
	return fmt.Sprintf(`
provider "nps" {
  endpoint = "localhost:8080"
}

resource "nps_workshop_file_access_rule" "test" {
  name              = %[1]q
  tag               = %[2]q
  rule_type         = "PathsWithAllowedProcesses"
  allow_read_access = true
  block_violations  = false

  path_prefixes = [
    %[3]q,
  ]

  process_binary_paths = [
    "/usr/bin/test",
  ]
}
`, name, tag, pathPrefix)
}
