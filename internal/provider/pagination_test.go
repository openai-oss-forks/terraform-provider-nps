// Copyright 2026 North Pole Security, Inc.
package provider

import (
	"errors"
	"reflect"
	"testing"
)

func TestCollectPages(t *testing.T) {
	t.Parallel()

	pages := map[int][]int{1: {1, 2}, 2: {3}}
	got, err := collectPages(func(page int) ([]int, bool, error) {
		items := pages[page]
		return items, page == 1, nil
	})
	if err != nil {
		t.Fatalf("collectPages returned an error: %v", err)
	}
	if want := []int{1, 2, 3}; !reflect.DeepEqual(got, want) {
		t.Fatalf("collectPages = %v, want %v", got, want)
	}
}

func TestCollectPagesRejectsEmptyContinuation(t *testing.T) {
	t.Parallel()

	_, err := collectPages(func(page int) ([]int, bool, error) {
		return nil, true, nil
	})
	if err == nil {
		t.Fatal("expected an error for more=true with an empty page")
	}
}

func TestCollectPagesReturnsFetchError(t *testing.T) {
	t.Parallel()

	want := errors.New("boom")
	_, err := collectPages(func(page int) ([]int, bool, error) {
		return nil, false, want
	})
	if !errors.Is(err, want) {
		t.Fatalf("collectPages error = %v, want %v", err, want)
	}
}
