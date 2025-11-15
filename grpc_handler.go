package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// handleGRPC handles gRPC requests by forwarding them to the appropriate backend.
func (p *MapRemoteProxy) handleGRPC(w http.ResponseWriter, r *http.Request) {
	p.stats.IncTotalRequests()
	p.stats.IncActiveConnections()
	defer p.stats.DecActiveConnections()

	originalURL := p.buildOriginalURL(r)
	log.Printf("[GRPC] Handling gRPC request for %s", originalURL)

	// Use the existing mapping logic to find the target backend and the specific mapping rule
	targetURL, matched, mapping := p.mapRequest(r)
	if !matched {
		log.Printf("[GRPC] No mapping found for %s", originalURL)
		http.Error(w, "No mapping found for gRPC request", http.StatusBadGateway)
		return
	}

	target, err := url.Parse(targetURL)
	if err != nil {
		log.Printf("[GRPC] Error parsing target URL %s: %v", targetURL, err)
		http.Error(w, "Invalid target URL", http.StatusInternalServerError)
		return
	}

	log.Printf("[GRPC] %s -> %s (Matched by rule: %s)", originalURL, targetURL, mapping.GetFromURL())

	// Create a reverse proxy to forward the gRPC request
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.URL.Path = target.Path // The full path is determined by mapRequest
			req.Host = target.Host

			// Apply gRPC metadata modifications if specified in the mapping
			if mapping != nil {
				fromConfig := mapping.GetFromConfig()
				if fromConfig != nil && fromConfig.GRPC != nil && len(fromConfig.GRPC.Metadata) > 0 {
					log.Printf("[GRPC METADATA] Applying metadata modifications for %s", originalURL)
					for key, value := range fromConfig.GRPC.Metadata {
						if value == nil {
							// If value is null, remove the metadata entry
							req.Header.Del(key)
							log.Printf("[GRPC METADATA] Removing metadata: %s", key)
						} else {
							// Otherwise, set the metadata value.
							switch v := value.(type) {
							case string:
								req.Header.Set(key, v)
								log.Printf("[GRPC METADATA] Setting metadata: %s -> %s", key, v)
							case []interface{}:
								// For multiple values, clear existing ones and add all new ones.
								req.Header.Del(key)
								for _, item := range v {
									if strItem, ok := item.(string); ok {
										req.Header.Add(key, strItem)
									}
								}
								log.Printf("[GRPC METADATA] Setting multi-value metadata: %s -> %v", key, v)
							default:
								// Fallback for other types, e.g. numbers
								strValue := fmt.Sprintf("%v", v)
								req.Header.Set(key, strValue)
								log.Printf("[GRPC METADATA] Setting metadata (coerced): %s -> %s", key, strValue)
							}
						}
					}
				}
			}
		},
		Transport: p.client.Transport, // Reuse the main transport
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			log.Printf("[GRPC] Proxy error: %v", err)
			rw.WriteHeader(http.StatusBadGateway)
		},
	}

	// Forward the request
	proxy.ServeHTTP(w, r)
}