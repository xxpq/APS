// Package httpx holds the HTTP-related helpers that were previously
// scattered across root main's utils.go. Stage 9.3 split utils.go into
// this sub-package plus aps/util/crypto so non-main packages (and the
// future aps/proxy) can reuse them without depending on root main.
package httpx

import (
	"net/http"
	"strings"
)

// skipHeaders is the set of hop-by-hop / proxy-sensitive headers that
// CopyHeaders must NOT propagate when relaying a request.
var skipHeaders = map[string]struct{}{
	"Host":                {},
	"Connection":          {},
	"Proxy-Connection":    {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

// CopyHeaders copies src into dst, skipping hop-by-hop headers and
// WebSocket-specific ones. Used when relaying a client request to an
// upstream backend.
func CopyHeaders(dst, src http.Header) {
	for key, values := range src {
		if _, skip := skipHeaders[key]; skip {
			continue
		}
		if strings.HasPrefix(key, "Sec-Websocket-") {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

// SetCorsHeaders writes a permissive CORS policy to h.
func SetCorsHeaders(h http.Header) {
	h.Set("Origin", "*")
	h.Set("Timing-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Vary", "Etag, Save-Data, Accept-Encoding")
	h.Set("Access-Control-Allow-Headers", "*")
	h.Set("Access-Control-Allow-Methods", "*")
	h.Set("Access-Control-Allow-Credentials", "true")
	h.Set("Access-Control-Expose-Headers", "*")
	h.Set("Access-Control-Request-Method", "*")
	h.Set("Access-Control-Request-Headers", "*")
	h.Set("Cross-Origin-Opener-Policy", "cross-origin")
	h.Set("Cross-Origin-Resource-Policy", "cross-origin")
}

// GetScheme returns "https" or "http" based on the request's TLS state
// and X-Forwarded-Proto header (in that order).
func GetScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if scheme := r.Header.Get("X-Forwarded-Proto"); scheme != "" {
		return scheme
	}
	return "http"
}
