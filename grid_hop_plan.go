package main

import (
	"encoding/json"
	"strings"
)

type gridHopPlan struct {
	Hops          []string `json:"hops,omitempty"`
	ICECandidates []string `json:"ice_candidates,omitempty"`
}

func buildGridHopPlanPayload(hops []string) []byte {
	return buildGridHopPlanPayloadWithICE(hops, nil)
}

func buildGridHopPlanPayloadWithICE(hops []string, iceCandidates []string) []byte {
	normalized := make([]string, 0, len(hops))
	for _, hop := range hops {
		h := strings.TrimSpace(hop)
		if h == "" {
			continue
		}
		normalized = append(normalized, h)
	}
	normalizedICE := make([]string, 0, len(iceCandidates))
	seenICE := make(map[string]struct{}, len(iceCandidates))
	for _, candidate := range iceCandidates {
		c := strings.TrimSpace(candidate)
		if c == "" {
			continue
		}
		if _, exists := seenICE[c]; exists {
			continue
		}
		seenICE[c] = struct{}{}
		normalizedICE = append(normalizedICE, c)
	}
	if len(normalized) == 0 && len(normalizedICE) == 0 {
		return nil
	}
	payload, err := json.Marshal(gridHopPlan{Hops: normalized, ICECandidates: normalizedICE})
	if err != nil {
		return nil
	}
	return payload
}

func parseGridHopPlanPayload(payload []byte) []string {
	if len(payload) == 0 {
		return nil
	}
	var plan gridHopPlan
	if err := json.Unmarshal(payload, &plan); err != nil {
		return nil
	}
	if len(plan.Hops) == 0 {
		return nil
	}
	out := make([]string, 0, len(plan.Hops))
	for _, hop := range plan.Hops {
		h := strings.TrimSpace(hop)
		if h == "" {
			continue
		}
		out = append(out, h)
	}
	return out
}

func parseGridHopPlanICECandidates(payload []byte) []string {
	if len(payload) == 0 {
		return nil
	}
	var plan gridHopPlan
	if err := json.Unmarshal(payload, &plan); err != nil {
		return nil
	}
	if len(plan.ICECandidates) == 0 {
		return nil
	}
	out := make([]string, 0, len(plan.ICECandidates))
	seen := make(map[string]struct{}, len(plan.ICECandidates))
	for _, candidate := range plan.ICECandidates {
		c := strings.TrimSpace(candidate)
		if c == "" {
			continue
		}
		if _, exists := seen[c]; exists {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}
