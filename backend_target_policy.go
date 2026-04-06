package main

import (
	"net"
	"net/url"
	"strings"
)

// shouldUseInsecureBackendMode decides whether backend TLS verification should be disabled.
// Priority:
// 1) Explicit mapping config (insecure=true/false) always wins.
// 2) For mapping targets that are https/wss and point to internal IPs, default to insecure=true.
func shouldUseInsecureBackendMode(toConfig *EndpointConfig, rawTargetURL string) bool {
	if toConfig == nil {
		return false
	}
	if toConfig.Insecure != nil {
		return *toConfig.Insecure
	}
	return isInternalTLSBackendTarget(rawTargetURL)
}

func isInternalTLSBackendTarget(rawTargetURL string) bool {
	parsed, err := url.Parse(strings.TrimSpace(rawTargetURL))
	if err != nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(parsed.Scheme)) {
	case "https", "wss":
	default:
		return false
	}

	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}
