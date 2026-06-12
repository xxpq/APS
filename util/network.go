package util

import (
	"net"
	"net/http"
	"strings"
)

// extractIPFromAddr extracts IP from a RemoteAddr string (e.g., "1.2.3.4:1234" -> "1.2.3.4")
func ExtractIPFromAddr(addr string) string {
	if addr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// getClientIP extracts the real client IP from an HTTP request, considering X-Forwarded-For
func GetClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip
			}
		}
	}
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return xrip
	}
	return ExtractIPFromAddr(r.RemoteAddr)
}

// getScheme returns the request scheme (http or https)
func GetScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return strings.ToLower(proto)
	}
	return "http"
}
