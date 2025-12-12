package main

import (
	"net"
	"testing"
)

func TestParseFirewallRule(t *testing.T) {
	rule := &FirewallRule{
		Block: []string{"125.67.61.66/8"},
	}

	if err := ParseFirewallRule(rule); err != nil {
		t.Fatalf("ParseFirewallRule failed: %v", err)
	}

	if len(rule.blockRules) != 1 {
		t.Fatalf("Expected 1 block rule, got %d", len(rule.blockRules))
	}

	if rule.blockRules[0].ruleType != "cidr" {
		t.Errorf("Expected rule type 'cidr', got '%s'", rule.blockRules[0].ruleType)
	}
}

func TestCheckFirewall(t *testing.T) {
	rule := &FirewallRule{
		Block: []string{"125.67.61.66/8"},
	}
	ParseFirewallRule(rule)

	ipToTest := "125.67.61.66:59372"
	
	// CheckFirewall splits host/port
	ip, _, _ := net.SplitHostPort(ipToTest)
	parsedIP := net.ParseIP(ip)
	
	t.Logf("Testing IP: %s (Parsed: %v)", ip, parsedIP)

	if CheckFirewall(ipToTest, rule) {
		t.Errorf("CheckFirewall allowed blocked IP %s", ipToTest)
	} else {
		t.Logf("CheckFirewall correctly blocked IP %s", ipToTest)
	}
}

func TestCheckFirewallCIDR(t *testing.T) {
	// 125.0.0.0/8 includes 125.67.61.66
	rule := &FirewallRule{
		Block: []string{"125.0.0.0/8"},
	}
	ParseFirewallRule(rule)

	ipToTest := "125.67.61.66:59372"
	
	if CheckFirewall(ipToTest, rule) {
		t.Errorf("CheckFirewall allowed blocked IP %s with CIDR 125.0.0.0/8", ipToTest)
	} else {
		t.Logf("CheckFirewall correctly blocked IP %s with CIDR 125.0.0.0/8", ipToTest)
	}
}

func TestParseIPAddress(t *testing.T) {
	// The user provided "125.67.61.66/8". This is a non-canonical CIDR.
	// net.ParseCIDR usually returns the masked network.
	// Let's see what happens.
	addr := "125.67.61.66/8"
	_, ipnet, err := net.ParseCIDR(addr)
	if err != nil {
		t.Fatalf("net.ParseCIDR failed for %s: %v", addr, err)
	}
	t.Logf("Parsed CIDR: %v", ipnet)
	
	testIP := net.ParseIP("125.67.61.66")
	if !ipnet.Contains(testIP) {
		t.Errorf("CIDR %v does not contain %v", ipnet, testIP)
	}
}
