package main

import "testing"

func TestGridHopPlanPayloadRoundTrip(t *testing.T) {
	payload := buildGridHopPlanPayload([]string{"  hop-a ", "", "hop-b"})
	hops := parseGridHopPlanPayload(payload)
	if len(hops) != 2 || hops[0] != "hop-a" || hops[1] != "hop-b" {
		t.Fatalf("unexpected hops after round trip: %#v", hops)
	}
}

func TestGridHopPlanPayloadEmpty(t *testing.T) {
	payload := buildGridHopPlanPayload([]string{"", " "})
	if payload != nil {
		t.Fatalf("expected nil payload for empty hops, got %q", string(payload))
	}
	hops := parseGridHopPlanPayload(nil)
	if len(hops) != 0 {
		t.Fatalf("expected no hops for nil payload, got %#v", hops)
	}
}

func TestGridHopPlanPayloadWithICE(t *testing.T) {
	payload := buildGridHopPlanPayloadWithICE([]string{"hop-a", "hop-b"}, []string{"203.0.113.10:443", "203.0.113.10:443", "198.51.100.8:3478"})
	hops := parseGridHopPlanPayload(payload)
	if len(hops) != 2 || hops[0] != "hop-a" || hops[1] != "hop-b" {
		t.Fatalf("unexpected hops: %#v", hops)
	}
	ice := parseGridHopPlanICECandidates(payload)
	if len(ice) != 2 {
		t.Fatalf("expected deduped ice candidates, got %#v", ice)
	}
}
