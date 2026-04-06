package main

import "strings"

// localGatewayNodeAliases returns normalized local node identifiers in priority order.
// Priority: runtime gateway node id (normally CID) -> CID -> endpointName.
func localGatewayNodeAliases() []string {
	seen := make(map[string]struct{}, 3)
	out := make([]string, 0, 3)
	add := func(raw string) {
		nodeID := normalizeGatewayNodeID(raw)
		if nodeID == "" {
			return
		}
		if _, exists := seen[nodeID]; exists {
			return
		}
		seen[nodeID] = struct{}{}
		out = append(out, nodeID)
	}
	add(currentGatewayNodeID())
	add(GetEffectiveConfigID())
	add(GetEffectiveEndpointName())
	return out
}

func localPrimaryGatewayNodeID() string {
	aliases := localGatewayNodeAliases()
	if len(aliases) == 0 {
		return ""
	}
	return aliases[0]
}

func isLocalGatewayNodeID(target string) bool {
	target = normalizeGatewayNodeID(strings.TrimSpace(target))
	if target == "" {
		return false
	}
	for _, alias := range localGatewayNodeAliases() {
		if alias == target {
			return true
		}
	}
	return false
}

