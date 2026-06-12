package security

import (
	"net"
	"net/url"
	"strings"
)

// EndpointConfigProjection is a minimal projection of the project's main
// EndpointConfig containing only the field the backend target policy needs to
// read. It is constructed by the main package (see main.shouldUseInsecureBackendMode)
// so this package does not have to import main's EndpointConfig.
type EndpointConfigProjection struct {
	// Insecure, when non-nil, decides whether backend TLS verification should
	// be disabled. nil means "no explicit preference" and the heuristic for
	// internal TLS targets applies.
	Insecure *bool
}

// ShouldUseInsecureBackendMode decides whether backend TLS verification should
// be disabled.
// Priority:
// 1) Explicit mapping config (insecure=true/false) always wins.
// 2) For mapping targets that are https/wss and point to internal IPs, default to insecure=true.
func ShouldUseInsecureBackendMode(toConfig *EndpointConfigProjection, rawTargetURL string) bool {
	if toConfig == nil {
		return false
	}
	if toConfig.Insecure != nil {
		return *toConfig.Insecure
	}
	return IsInternalTLSBackendTarget(rawTargetURL)
}

// IsInternalTLSBackendTarget reports whether the given URL targets a TLS
// endpoint on a private/loopback/link-local IP, which is a strong signal that
// the certificate cannot be validated against a public CA.
func IsInternalTLSBackendTarget(rawTargetURL string) bool {
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
