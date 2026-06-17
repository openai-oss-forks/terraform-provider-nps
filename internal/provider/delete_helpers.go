// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// isDeleteNoOp reports whether a delete error means the remote object is
// already non-actionable. Workshop reports stale file-access rule IDs as
// InvalidArgument with "rule is superseded" after a successful upsert.
func isDeleteNoOp(err error) bool {
	if status.Code(err) == codes.NotFound {
		return true
	}
	return status.Code(err) == codes.InvalidArgument && strings.Contains(status.Convert(err).Message(), "rule is superseded")
}
