package httpx

import (
	"net"
	"net/http"
	"strings"
)

// GetClientIP returns the originating client IP, preferring
// X-Forwarded-For, then X-Real-IP, and finally r.RemoteAddr.
func GetClientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0]
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}

// ExtractIPFromAddr extracts the host portion of a "host:port" string
// (e.g., "1.2.3.4:1234" -> "1.2.3.4"). Falls back to the input string
// if it cannot be split.
func ExtractIPFromAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
