package main

import "testing"

func TestFindDuplicateMappingIndex_AddDuplicate(t *testing.T) {
	mappings := []Mapping{
		{From: "/api/*", To: "http://backend-a/*"},
		{From: "/static/*", To: "http://backend-static/*"},
	}

	idx, err := findDuplicateMappingIndex(mappings, Mapping{From: "/api/*", To: "http://backend-a/*"}, -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if idx != 0 {
		t.Fatalf("expected duplicate at index 0, got %d", idx)
	}
}

func TestFindDuplicateMappingIndex_AddUnique(t *testing.T) {
	mappings := []Mapping{
		{From: "/api/*", To: "http://backend-a/*"},
	}

	idx, err := findDuplicateMappingIndex(mappings, Mapping{From: "/api/v2/*", To: "http://backend-a/*"}, -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if idx != -1 {
		t.Fatalf("expected no duplicate, got index %d", idx)
	}
}

func TestFindDuplicateMappingIndex_EditIgnoreCurrentIndex(t *testing.T) {
	mappings := []Mapping{
		{From: "/api/*", To: "http://backend-a/*"},
		{From: "/static/*", To: "http://backend-static/*"},
	}

	idx, err := findDuplicateMappingIndex(mappings, Mapping{From: "/api/*", To: "http://backend-a/*"}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if idx != -1 {
		t.Fatalf("expected no duplicate when ignoring self, got %d", idx)
	}
}

func TestFindDuplicateMappingIndex_EditConflictWithOtherEntry(t *testing.T) {
	mappings := []Mapping{
		{From: "/api/*", To: "http://backend-a/*"},
		{From: "/static/*", To: "http://backend-static/*"},
	}

	idx, err := findDuplicateMappingIndex(mappings, Mapping{From: "/static/*", To: "http://backend-static/*"}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if idx != 1 {
		t.Fatalf("expected duplicate at index 1, got %d", idx)
	}
}

func TestFindDuplicateMappingIndex_MapKeyOrderStillDuplicate(t *testing.T) {
	fromA := map[string]interface{}{}
	fromA["url"] = "https://example.com/*"
	fromA["method"] = "GET"

	fromB := map[string]interface{}{}
	fromB["method"] = "GET"
	fromB["url"] = "https://example.com/*"

	mappings := []Mapping{
		{From: fromA, To: "http://backend/*"},
	}

	idx, err := findDuplicateMappingIndex(mappings, Mapping{From: fromB, To: "http://backend/*"}, -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if idx != 0 {
		t.Fatalf("expected duplicate at index 0, got %d", idx)
	}
}
