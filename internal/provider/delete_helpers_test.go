// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestIsDeleteNoOp(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "not found", err: status.Error(codes.NotFound, "gone"), want: true},
		{name: "superseded rule", err: status.Error(codes.InvalidArgument, "invalid argument: rule is superseded"), want: true},
		{name: "unrelated invalid argument", err: status.Error(codes.InvalidArgument, "bad input"), want: false},
		{name: "permission denied", err: status.Error(codes.PermissionDenied, "no"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDeleteNoOp(tt.err); got != tt.want {
				t.Fatalf("isDeleteNoOp(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
