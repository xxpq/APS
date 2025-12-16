package main

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
)

// FirewallRule defines a firewall rule with allow and block lists
type FirewallRule struct {
	Allow             []string `json:"allow,omitempty"`             // Whitelist - if set, only these IPs can access
	Block             []string `json:"block,omitempty"`             // Blacklist - if set, these IPs are denied
	LogLevel          *int     `json:"logLevel,omitempty"`          // 日志等级: 0=不记录, 1=基本请求, 2=完整请求
	LogRetentionHours *int     `json:"logRetentionHours,omitempty"` // 日志保留时长(小时)

	// Parsed internal structures for efficient matching
	allowRules []*ipRule
	blockRules []*ipRule
}

// ipRule represents a parsed IP rule (CIDR, single IP, or range)
type ipRule struct {
	ruleType   string // "cidr", "single", "range"
	cidr       *net.IPNet
	ip         net.IP
	rangeStart net.IP
	rangeEnd   net.IP
}

// ParseFirewallRule parses a firewall rule and prepares it for matching
func ParseFirewallRule(rule *FirewallRule) error {
	if rule == nil {
		return nil
	}

	// Parse allow rules
	if len(rule.Allow) > 0 {
		rule.allowRules = make([]*ipRule, 0, len(rule.Allow))
		for _, addr := range rule.Allow {
			ipRules, err := parseIPAddress(addr)
			if err != nil {
				log.Printf("[FIREWALL] Warning: failed to parse allow rule '%s': %v", addr, err)
				continue
			}
			rule.allowRules = append(rule.allowRules, ipRules...)
		}
		log.Printf("[FIREWALL] Parsed %d allow rules from %d entries", len(rule.allowRules), len(rule.Allow))
	}

	// Parse block rules
	if len(rule.Block) > 0 {
		rule.blockRules = make([]*ipRule, 0, len(rule.Block))
		for _, addr := range rule.Block {
			ipRules, err := parseIPAddress(addr)
			if err != nil {
				log.Printf("[FIREWALL] Warning: failed to parse block rule '%s': %v", addr, err)
				continue
			}
			rule.blockRules = append(rule.blockRules, ipRules...)
		}
		log.Printf("[FIREWALL] Parsed %d block rules from %d entries", len(rule.blockRules), len(rule.Block))
	}

	return nil
}

// parseIPAddress parses various IP address formats and returns ipRule(s)
// Supports:
// - CIDR: 111.32.1.0/24
// - Single IP: 192.111.133.1
// - Short range: 192.111.231.175-178 (last octet only)
// - Full range: 192.111.231.111-192.111.232.11
func parseIPAddress(addr string) ([]*ipRule, error) {
	addr = strings.TrimSpace(addr)

	// Check for CIDR notation
	if strings.Contains(addr, "/") {
		_, ipNet, err := net.ParseCIDR(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR: %w", err)
		}
		return []*ipRule{{
			ruleType: "cidr",
			cidr:     ipNet,
		}}, nil
	}

	// Check for IP range
	if strings.Contains(addr, "-") {
		return parseIPRange(addr)
	}

	// Single IP address
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", addr)
	}
	return []*ipRule{{
		ruleType: "single",
		ip:       ip,
	}}, nil
}

// parseIPRange parses IP range formats
// Short format: 192.111.231.175-178 (last octet only)
// Full format: 192.111.231.111-192.111.232.11
func parseIPRange(addr string) ([]*ipRule, error) {
	parts := strings.Split(addr, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid range format: %s", addr)
	}

	startStr := strings.TrimSpace(parts[0])
	endStr := strings.TrimSpace(parts[1])

	// Parse start IP
	startIP := net.ParseIP(startStr)
	if startIP == nil {
		return nil, fmt.Errorf("invalid start IP: %s", startStr)
	}

	// Convert to IPv4 if needed
	if ipv4 := startIP.To4(); ipv4 != nil {
		startIP = ipv4
	}

	var endIP net.IP

	// Check if end is a full IP or just a number
	if strings.Contains(endStr, ".") {
		// Full IP format
		endIP = net.ParseIP(endStr)
		if endIP == nil {
			return nil, fmt.Errorf("invalid end IP: %s", endStr)
		}
		if ipv4 := endIP.To4(); ipv4 != nil {
			endIP = ipv4
		}
	} else {
		// Short format - just the last octet
		lastOctet, err := strconv.Atoi(endStr)
		if err != nil || lastOctet < 0 || lastOctet > 255 {
			return nil, fmt.Errorf("invalid last octet in range: %s", endStr)
		}

		// Construct end IP by replacing last octet
		endIP = make(net.IP, len(startIP))
		copy(endIP, startIP)
		if len(endIP) == 4 {
			endIP[3] = byte(lastOctet)
		} else if len(endIP) == 16 {
			endIP[15] = byte(lastOctet)
		}
	}

	return []*ipRule{{
		ruleType:   "range",
		rangeStart: startIP,
		rangeEnd:   endIP,
	}}, nil
}

// CheckFirewall checks if an IP address is allowed or blocked by the firewall rule
// Returns true if the connection should be allowed, false if it should be blocked
func CheckFirewall(clientIP string, rule *FirewallRule) bool {
	if rule == nil {
		return true // No firewall rule, allow all
	}

	// Extract IP address from "ip:port" format
	ip, _, err := net.SplitHostPort(clientIP)
	if err != nil {
		// If it's not in "ip:port" format, use it directly
		ip = clientIP
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		log.Printf("[FIREWALL] Warning: invalid IP address format: %s", clientIP)
		return true // Don't block on parsing errors
	}

	// Convert to IPv4 if needed
	if ipv4 := parsedIP.To4(); ipv4 != nil {
		parsedIP = ipv4
	}

	// Whitelist mode: if allow rules exist, only allow IPs in the allow list
	if len(rule.allowRules) > 0 {
		for _, allowRule := range rule.allowRules {
			if matchIPRule(parsedIP, allowRule) {
				DebugLog("[FIREWALL] IP %s allowed by whitelist rule", ip)
				return true
			}
		}
		DebugLog("[FIREWALL] IP %s blocked by whitelist (not in allow list)", ip)
		return false
	}

	// Blacklist mode: if block rules exist, block IPs in the block list
	if len(rule.blockRules) > 0 {
		for _, blockRule := range rule.blockRules {
			if matchIPRule(parsedIP, blockRule) {
				DebugLog("[FIREWALL] IP %s blocked by blacklist rule", ip)
				return false
			}
		}
		DebugLog("[FIREWALL] IP %s allowed (not in block list)", ip)
		return true
	}

	// No rules defined, allow by default
	return true
}

// matchIPRule checks if an IP matches a specific rule
func matchIPRule(ip net.IP, rule *ipRule) bool {
	switch rule.ruleType {
	case "cidr":
		return rule.cidr.Contains(ip)
	case "single":
		return ip.Equal(rule.ip)
	case "range":
		return ipInRange(ip, rule.rangeStart, rule.rangeEnd)
	}
	return false
}

// ipInRange checks if an IP is within a range [start, end]
func ipInRange(ip, start, end net.IP) bool {
	// Ensure all IPs are the same length
	if len(ip) != len(start) || len(ip) != len(end) {
		return false
	}

	// Check if ip >= start
	if compareIP(ip, start) < 0 {
		return false
	}

	// Check if ip <= end
	if compareIP(ip, end) > 0 {
		return false
	}

	return true
}

// compareIP compares two IP addresses
// Returns -1 if a < b, 0 if a == b, 1 if a > b
func compareIP(a, b net.IP) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// GetFirewallRule retrieves a firewall rule by name from the config
func GetFirewallRule(config *Config, ruleName string) *FirewallRule {
	if config == nil || config.Firewalls == nil {
		return nil
	}

	config.mu.RLock()
	defer config.mu.RUnlock()

	rule, exists := config.Firewalls[ruleName]
	if !exists {
		return nil
	}

	return rule
}
