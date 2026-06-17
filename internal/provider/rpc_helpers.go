// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	listPageSize = 1000
	maxListPages = 10000
)

// isNotFound reports whether err is a gRPC NotFound response. Delete methods
// use this to make retries and out-of-band deletion idempotent.
func isNotFound(err error) bool {
	return status.Code(err) == codes.NotFound
}

// isDeleteNoOp recognizes server responses that mean the requested object is
// already non-actionable. Workshop reports stale file-access rule IDs as
// InvalidArgument with "rule is superseded" after a successful upsert.
func isDeleteNoOp(err error) bool {
	if isNotFound(err) {
		return true
	}
	return status.Code(err) == codes.InvalidArgument && strings.Contains(status.Convert(err).Message(), "rule is superseded")
}

// collectPages walks a one-based Workshop pagination API. The fetch callback
// normalizes the API-specific page and response types into a common shape.
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
