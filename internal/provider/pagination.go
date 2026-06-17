// Copyright 2026 North Pole Security, Inc.
package provider

import "fmt"

const (
	listPageSize = 1000
	maxListPages = 10000
)

// collectPages walks a one-based Workshop pagination API. The fetch callback
// normalizes API-specific page and response types into a common shape.
func collectPages[T any](fetch func(page int) (items []T, more bool, err error)) ([]T, error) {
	var all []T
	for page := 1; page <= maxListPages; page++ {
		items, more, err := fetch(page)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
		if !more {
			return all, nil
		}
		if len(items) == 0 {
			return nil, fmt.Errorf("pagination returned more=true with an empty page %d", page)
		}
	}
	return nil, fmt.Errorf("pagination exceeded %d pages", maxListPages)
}
