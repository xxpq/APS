package main

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// routeCacheEntry represents a cached route match result
type routeCacheEntry struct {
	finalURL       string
	mapping        *Mapping
	matchedFromURL string
	expireAt       time.Time
}

// routeCache provides thread-safe caching for route matches
type routeCache struct {
	mu      sync.RWMutex
	entries map[string]*routeCacheEntry
	ttl     time.Duration
}

// Global route cache with 3-minute TTL
var globalRouteCache = &routeCache{
	entries: make(map[string]*routeCacheEntry),
	ttl:     3 * time.Minute,
}

// get retrieves a cached entry if it exists and hasn't expired
func (c *routeCache) get(key string) (*routeCacheEntry, bool) {
	c.mu.RLock()
	entry, exists := c.entries[key]
	c.mu.RUnlock()

	if !exists {
		return nil, false
	}

	if time.Now().After(entry.expireAt) {
		// Entry expired, remove it
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return nil, false
	}

	return entry, true
}

// set stores a cache entry
func (c *routeCache) set(key string, finalURL string, mapping *Mapping, matchedFromURL string) {
	c.mu.Lock()
	c.entries[key] = &routeCacheEntry{
		finalURL:       finalURL,
		mapping:        mapping,
		matchedFromURL: matchedFromURL,
		expireAt:       time.Now().Add(c.ttl),
	}
	c.mu.Unlock()
}

// clear removes all cache entries (called on config reload)
func (c *routeCache) clear() {
	c.mu.Lock()
	c.entries = make(map[string]*routeCacheEntry)
	c.mu.Unlock()
}

// cleanup removes expired entries (can be called periodically)
func (c *routeCache) cleanup() {
	c.mu.Lock()
	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.expireAt) {
			delete(c.entries, key)
		}
	}
	c.mu.Unlock()
}

// size returns the number of entries in the cache
func (c *routeCache) size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

func (p *MapRemoteProxy) mapRequest(r *http.Request) (string, bool, *Mapping, string) {
	originalURL := p.buildOriginalURL(r)

	// Build cache key: serverName|originalURL|method
	// Method is included because same URL with different methods may match different rules
	cacheKey := p.serverName + "|" + originalURL + "|" + r.Method

	// Check cache first
	if cached, found := globalRouteCache.get(cacheKey); found {
		return cached.finalURL, true, cached.mapping, cached.matchedFromURL
	}

	// Cache miss - perform full matching
	mappings := p.config.GetMappings()

	var bestMatch *Mapping
	var bestScore = -1
	var finalURL string
	var matchedFromURL string

	for i := range mappings {
		mapping := &mappings[i]

		score, newURL, fromURL := p.calculateMatchScore(mapping, r, originalURL)

		if score > bestScore {
			bestScore = score
			bestMatch = mapping
			finalURL = newURL
			matchedFromURL = fromURL
		}
	}

	if bestMatch != nil {
		// Cache the successful match
		globalRouteCache.set(cacheKey, finalURL, bestMatch, matchedFromURL)
		return finalURL, true, bestMatch, matchedFromURL
	}

	return originalURL, false, nil, ""
}

func (p *MapRemoteProxy) calculateMatchScore(mapping *Mapping, r *http.Request, originalURL string) (int, string, string) {
	// Check if the mapping is for the current server
	isForThisServer := false
	for _, name := range mapping.serverNames {
		if name == p.serverName {
			isForThisServer = true
			break
		}
	}
	if !isForThisServer {
		return -1, "", ""
	}

	fromConfig := mapping.GetFromConfig()
	if fromConfig == nil {
		return -1, "", ""
	}

	for _, fromURL := range fromConfig.URLs {
		// Base URL match
		matched, newURL := p.matchAndReplace(originalURL, fromURL, mapping.GetToURL())
		if !matched {
			continue
		}

		score := 1 // Base score for URL match

		// Method match
		if fromConfig.Method != nil {
			if fromConfig.MatchesMethod(r.Method) {
				score += 10
			} else {
				return -1, "", "" // Method is specified but does not match
			}
		}

		// Header match
		if len(fromConfig.Headers) > 0 {
			for key, value := range fromConfig.Headers {
				if r.Header.Get(key) != "" && (value == nil || r.Header.Get(key) == value) {
					score++
				}
			}
		}

		// Query string match
		if len(fromConfig.QueryString) > 0 {
			queryParams := r.URL.Query()
			for key, value := range fromConfig.QueryString {
				if queryParams.Get(key) != "" && (value == nil || queryParams.Get(key) == value.(string)) {
					score++
				}
			}
		}

		// gRPC match
		if fromConfig.GRPC != nil {
			service, method, ok := parseGRPCPath(r.URL.Path)
			if !ok {
				// This rule requires a gRPC match, but the path is not a valid gRPC path.
				return -1, "", ""
			}

			grpcMatch := true
			// Service match
			if fromConfig.GRPC.Service != "" {
				if fromConfig.GRPC.Service == service {
					score += 20 // High score for service match
				} else {
					grpcMatch = false
				}
			}

			// Method match
			if fromConfig.GRPC.Method != "" {
				if fromConfig.GRPC.Method == method {
					score += 10 // Additional score for method match
				} else {
					grpcMatch = false
				}
			}

			if !grpcMatch {
				return -1, "", "" // gRPC service/method specified but does not match
			}

			// Metadata (Header) match for gRPC
			if len(fromConfig.GRPC.Metadata) > 0 {
				for key, value := range fromConfig.GRPC.Metadata {
					// gRPC metadata keys are case-insensitive, like HTTP headers.
					// The http.Request.Header handles this for us.
					if r.Header.Get(key) != "" && (value == nil || r.Header.Get(key) == value) {
						score++
					}
				}
			}
		}
		return score, newURL, fromURL
	}

	return -1, "", ""
}

func (p *MapRemoteProxy) matchAndReplace(originalURL, fromPattern, toPattern string) (bool, string) {
	DebugLog("[DEBUG] Trying to match: %s with pattern: %s", originalURL, fromPattern)

	if matched, newURL := p.tryRegexMatch(originalURL, fromPattern, toPattern); matched {
		return true, newURL
	}

	parsedOriginal, err := url.Parse(originalURL)
	if err != nil {
		DebugLog("[DEBUG] Failed to parse original URL: %v", err)
		return false, originalURL
	}

	parsedFrom, err := url.Parse(fromPattern)
	if err != nil {
		DebugLog("[DEBUG] Failed to parse from pattern: %v", err)
		return false, originalURL
	}

	DebugLog("[DEBUG] Original - Scheme: %s, Host: %s, Path: %s",
		parsedOriginal.Scheme, parsedOriginal.Host, parsedOriginal.Path)
	DebugLog("[DEBUG] Pattern  - Scheme: %s, Host: %s, Path: %s",
		parsedFrom.Scheme, parsedFrom.Host, parsedFrom.Path)

	// Scheme match
	schemeMatch := false
	switch parsedFrom.Scheme {
	case "*":
		schemeMatch = true
	case "ws":
		schemeMatch = (parsedOriginal.Scheme == "http")
	case "wss":
		schemeMatch = (parsedOriginal.Scheme == "https")
	default:
		schemeMatch = (parsedOriginal.Scheme == parsedFrom.Scheme)
	}

	if !schemeMatch {
		DebugLog("[DEBUG] Scheme mismatch: original=%s, pattern=%s", parsedOriginal.Scheme, parsedFrom.Scheme)
		return false, originalURL
	}

	if parsedOriginal.Host != parsedFrom.Host {
		DebugLog("[DEBUG] Host mismatch: %s != %s", parsedOriginal.Host, parsedFrom.Host)
		return false, originalURL
	}

	fromPath := parsedFrom.Path
	originalPath := parsedOriginal.Path

	if originalPath == "" {
		originalPath = "/"
	}

	if strings.HasSuffix(fromPath, "*") {
		fromPathPrefix := strings.TrimSuffix(fromPath, "*")

		if fromPathPrefix == "" || fromPathPrefix == "/" {
			DebugLog("[DEBUG] Root wildcard match - matches any path")
		} else {
			DebugLog("[DEBUG] Wildcard match - checking if %s starts with %s", originalPath, fromPathPrefix)
		}

		if fromPathPrefix == "" || fromPathPrefix == "/" || strings.HasPrefix(originalPath, fromPathPrefix) {
			toPath := strings.TrimSuffix(toPattern, "*")

			parsedTo, err := url.Parse(toPath)
			if err != nil {
				return false, originalURL
			}

			var remainingPath string
			if fromPathPrefix == "" || fromPathPrefix == "/" {
				if originalPath == "/" {
					remainingPath = ""
				} else {
					remainingPath = originalPath
				}
			} else {
				remainingPath = strings.TrimPrefix(originalPath, fromPathPrefix)
			}

			newPath := parsedTo.Path
			if strings.HasSuffix(newPath, "/") && strings.HasPrefix(remainingPath, "/") {
				newPath = strings.TrimSuffix(newPath, "/")
			}
			newPath = newPath + remainingPath

			newURL := url.URL{
				Scheme:   parsedTo.Scheme,
				Host:     parsedTo.Host,
				Path:     newPath,
				RawQuery: parsedOriginal.RawQuery,
				Fragment: parsedOriginal.Fragment,
			}

			DebugLog("[DEBUG] ✓ Wildcard matched! New URL: %s", newURL.String())
			return true, newURL.String()
		}
	} else {
		DebugLog("[DEBUG] Exact match - checking if %s == %s", originalPath, fromPath)
		if originalPath == fromPath || (originalPath == "/" && fromPath == "") || (originalPath == "" && fromPath == "/") {
			parsedTo, err := url.Parse(toPattern)
			if err != nil {
				return false, originalURL
			}

			newURL := url.URL{
				Scheme:   parsedTo.Scheme,
				Host:     parsedTo.Host,
				Path:     parsedTo.Path,
				RawQuery: parsedOriginal.RawQuery,
				Fragment: parsedOriginal.Fragment,
			}

			DebugLog("[DEBUG] ✓ Exact matched! New URL: %s", newURL.String())
			return true, newURL.String()
		}
	}

	DebugLog("[DEBUG] ✗ No match")
	return false, originalURL
}

func (p *MapRemoteProxy) tryRegexMatch(originalURL, fromPattern, toPattern string) (bool, string) {
	if !strings.Contains(fromPattern, "(") && !strings.Contains(fromPattern, "[") &&
		!strings.Contains(fromPattern, "{") && !strings.Contains(fromPattern, "^") &&
		!strings.Contains(fromPattern, "$") && !strings.Contains(fromPattern, "|") {
		return false, originalURL
	}

	re, err := regexp.Compile(fromPattern)
	if err != nil {
		DebugLog("[DEBUG] Not a valid regex pattern: %v", err)
		return false, originalURL
	}

	if !re.MatchString(originalURL) {
		return false, originalURL
	}

	newURL := re.ReplaceAllString(originalURL, toPattern)
	DebugLog("[DEBUG] ✓ Regex matched! %s -> %s", originalURL, newURL)
	return true, newURL
}

// parseGRPCPath extracts the service and method from a gRPC URL path.
// The format is expected to be /package.Service/Method.
// It returns (service, method, ok).
func parseGRPCPath(path string) (string, string, bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}
