package main

import "testing"

func TestBuildWeightedTopKRoutesFromGraph(t *testing.T) {
	routes := []RouteDescriptor{
		{
			RouteID:          "r1",
			SourceNode:       "A",
			DestinationNode:  "C",
			Hops:             []string{"A", "X", "C"},
			ReliabilityScore: 0.98,
			LatencyMs:        20,
			Metadata:         map[string]string{"loss_pct": "0.1", "jitter_ms": "2"},
			ExpiresAt:        4102444800, // 2100-01-01
		},
		{
			RouteID:          "r2",
			SourceNode:       "A",
			DestinationNode:  "C",
			Hops:             []string{"A", "B", "C"},
			ReliabilityScore: 0.90,
			LatencyMs:        10,
			Metadata:         map[string]string{"loss_pct": "20", "jitter_ms": "1"},
			ExpiresAt:        4102444800,
		},
		{
			RouteID:          "r3",
			SourceNode:       "A",
			DestinationNode:  "C",
			Hops:             []string{"A", "D", "C"},
			ReliabilityScore: 0.95,
			LatencyMs:        18,
			Metadata:         map[string]string{"loss_pct": "1.0", "jitter_ms": "2"},
			ExpiresAt:        4102444800,
		},
	}

	top := buildWeightedTopKRoutesFromGraph(routes, "A", "C", 8, 3, 120)
	if len(top) == 0 {
		t.Fatal("expected at least one route")
	}
	if len(top) > 3 {
		t.Fatalf("expected topK <= 3, got %d", len(top))
	}
	if len(top[0].Hops) < 2 || top[0].Hops[0] != "A" || top[0].Hops[len(top[0].Hops)-1] != "C" {
		t.Fatalf("unexpected top route hops: %#v", top[0].Hops)
	}
}

func TestAssignTopCandidatePrioritiesByUniqueRoute(t *testing.T) {
	candidates := []PathCandidate{
		{RouteID: "r1", Hops: []string{"A", "B", "C"}, Transport: "ice"},
		{RouteID: "r1", Hops: []string{"A", "B", "C"}, Transport: "tcp"},
		{RouteID: "r2", Hops: []string{"A", "D", "C"}, Transport: "ice"},
		{RouteID: "r2", Hops: []string{"A", "D", "C"}, Transport: "tcp"},
		{RouteID: "r3", Hops: []string{"A", "E", "C"}, Transport: "quic"},
		{RouteID: "relay", IsRelay: true, Transport: "relay"},
	}
	assignTopCandidatePriorities(candidates)

	if candidates[0].Priority != 1 || candidates[1].Priority != 1 {
		t.Fatalf("expected same route r1 to share priority 1, got %d/%d", candidates[0].Priority, candidates[1].Priority)
	}
	if candidates[2].Priority != 2 || candidates[3].Priority != 2 {
		t.Fatalf("expected same route r2 to share priority 2, got %d/%d", candidates[2].Priority, candidates[3].Priority)
	}
	if candidates[4].Priority != 3 {
		t.Fatalf("expected route r3 to be priority 3, got %d", candidates[4].Priority)
	}
	if candidates[5].Priority != 0 {
		t.Fatalf("expected relay candidate to have no priority, got %d", candidates[5].Priority)
	}
}
