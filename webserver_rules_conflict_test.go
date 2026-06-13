package main

import (
	"aps/config"
	"testing"
)

func TestFindConflictingFromEntry_AddConflictDifferentTo(t *testing.T) {
	mappings := []config.Mapping{
		{From: "/api/*", To: "http://backend-a/*"},
	}

	idx, from, err := findConflictingFromEntry(mappings, config.Mapping{From: "/api/*", To: "http://backend-b/*"}, -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if idx != 0 {
		t.Fatalf("expected conflict index 0, got %d", idx)
	}
	if from != "/api/*" {
		t.Fatalf("expected conflict from '/api/*', got %q", from)
	}
}

func TestFindConflictingFromEntry_AddUnique(t *testing.T) {
	mappings := []config.Mapping{
		{From: "/api/*", To: "http://backend-a/*"},
	}

	idx, from, err := findConflictingFromEntry(mappings, config.Mapping{From: "/v2/*", To: "http://backend-a/*"}, -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if idx != -1 {
		t.Fatalf("expected no conflict index, got %d", idx)
	}
	if from != "" {
		t.Fatalf("expected empty conflict from, got %q", from)
	}
}

func TestFindConflictingFromEntry_AnyEntryOverlapTriggersConflict(t *testing.T) {
	mappings := []config.Mapping{
		{From: "/api/*", To: "http://backend-a/*"},
	}

	idx, from, err := findConflictingFromEntry(mappings, config.Mapping{
		From: []string{"/v2/*", "/api/*"},
		To:   "http://backend-b/*",
	}, -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if idx != 0 {
		t.Fatalf("expected conflict index 0, got %d", idx)
	}
	if from != "/api/*" {
		t.Fatalf("expected conflict from '/api/*', got %q", from)
	}
}

func TestFindConflictingFromEntry_EditIgnoreCurrentIndex(t *testing.T) {
	mappings := []config.Mapping{
		{From: "/api/*", To: "http://backend-a/*"},
		{From: "/static/*", To: "http://backend-static/*"},
	}

	idx, from, err := findConflictingFromEntry(mappings, config.Mapping{From: "/api/*", To: "http://backend-a/*"}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if idx != -1 {
		t.Fatalf("expected no conflict when ignoring self, got %d", idx)
	}
	if from != "" {
		t.Fatalf("expected empty conflict from, got %q", from)
	}
}

func TestFindConflictingFromEntry_EditConflictWithOtherEntry(t *testing.T) {
	mappings := []config.Mapping{
		{From: "/api/*", To: "http://backend-a/*"},
		{From: "/static/*", To: "http://backend-static/*"},
	}

	idx, from, err := findConflictingFromEntry(mappings, config.Mapping{From: "/static/*", To: "http://backend-a/*"}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if idx != 1 {
		t.Fatalf("expected conflict index 1, got %d", idx)
	}
	if from != "/static/*" {
		t.Fatalf("expected conflict from '/static/*', got %q", from)
	}
}

func TestFindConflictingFromEntry_ObjectUrlsConflict(t *testing.T) {
	mappings := []config.Mapping{
		{
			From: map[string]interface{}{
				"url": []interface{}{"https://a.example/*", "https://b.example/*"},
			},
			To: "http://backend-a/*",
		},
	}

	idx, from, err := findConflictingFromEntry(mappings, config.Mapping{
		From: map[string]interface{}{
			"url": []interface{}{"https://x.example/*", "https://b.example/*"},
		},
		To: "http://backend-b/*",
	}, -1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if idx != 0 {
		t.Fatalf("expected conflict index 0, got %d", idx)
	}
	if from != "https://b.example/*" {
		t.Fatalf("expected conflict from 'https://b.example/*', got %q", from)
	}
}
