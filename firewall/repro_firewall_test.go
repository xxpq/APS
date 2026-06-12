package main

import (
	"testing"

	"aps/asn"
)

func TestFirewallBypassRepro(t *testing.T) {
	// 1. Setup Mock ASN Cache
	cache := asn.NewASNCacheForTest(1000)
	asn.GlobalASNCache = cache

	// 2. Populate Cache with the problematic IP data
	// Log: [80.75.212.125][DE-Hesse-Frankfurt]
	// Based on asn_cache.go:
	// Country = province (Hesse)
	// CountryCode = DE
	// State = province (Hesse)
	// City = Frankfurt
	ip := "80.75.212.125"
	geo := &asn.IPGeolocation{
		IP: ip,
		Location: &asn.LocationInfo{
			Country:     "Hesse",
			CountryCode: "DE",
			State:       "Hesse",
			City:        "Frankfurt",
			Latitude:    0,
			Longitude:   0,
		},
	}
	cache.InjectMemoryForTest(ip, geo)

	// 3. Define Firewall Rule (china_only)
	rule := &FirewallRule{
		Allow: &FilterRules{
			Regions: []string{"CN"},
		},
	}
	// Parse rule (though regions don't need parsing, good to be consistent)
	ParseFirewallRule(rule)

	// 4. Check Firewall
	allowed := CheckFirewall(ip, rule)

	// 5. Assert
	if allowed {
		t.Errorf("Firewall allowed IP %s despite china_only rule", ip)
	} else {
		t.Logf("Firewall correctly blocked IP %s", ip)
	}
}

func TestMatchesRegion(t *testing.T) {
	// matchesRegion(regionSpec, countryCode, countryName, stateName)

	// Case 1: CN vs DE
	if matchesRegion("CN", "DE", "Hesse", "Hesse") {
		t.Error("matchesRegion('CN', 'DE', 'Hesse', 'Hesse') returned true, expected false")
	}

	// Case 2: CN vs CN
	if !matchesRegion("CN", "CN", "China", "Beijing") {
		t.Error("matchesRegion('CN', 'CN', 'China', 'Beijing') returned false, expected true")
	}
}
