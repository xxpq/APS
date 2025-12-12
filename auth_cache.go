package main

import (
	"sync"
	"time"
)

// AuthCacheEntry represents a cached authentication result
type AuthCacheEntry struct {
	Body      string // Response body from auth service
	ExpiresAt time.Time
}

// AuthCache manages the authentication cache
type AuthCache struct {
	mu    sync.RWMutex
	cache map[string]*AuthCacheEntry
}

// Global instance
var globalAuthCache = &AuthCache{
	cache: make(map[string]*AuthCacheEntry),
}

// GetAuthCache returns the global auth cache instance
func GetAuthCache() *AuthCache {
	return globalAuthCache
}

// GenerateCacheKey generates a cache key from token and request path
// Key format: SHA256(token + ":" + method + ":" + host + ":" + path)
// However, the prompt says "token + path".
// And for revocation "revoke?token=xxx", we need to be able to find entries by token.
// If we hash, we can't easily find all entries for a token without scanning or a secondary index.
// Given the requirement to revoke by token, and assuming "token" is the primary identifier,
// we will use a key structure that allows us to filter.
// Or we just store: key = token + "|" + path.
// When revoking 'token', we iterate and delete all keys starting with 'token|'.
func (ac *AuthCache) GenerateCacheKey(token, method, host, path string) string {
	// Simple concatenation. Token can be long, but it's the prefix for revocation.
	return token + "|" + method + "|" + host + "|" + path
}

// Get retrieves a cached entry
func (ac *AuthCache) Get(key string) (string, bool) {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	entry, ok := ac.cache[key]
	if !ok {
		return "", false
	}

	if time.Now().After(entry.ExpiresAt) {
		// Lazy expiration cleanup could be here, or just return false
		// We'll leave cleanup to a dedicated routine or just let it sit until overwritten/revoked for simplicity in this MVP
		return "", false
	}

	return entry.Body, true
}

// Set adds or updates a cache entry
func (ac *AuthCache) Set(key string, body string, ttl time.Duration) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	ac.cache[key] = &AuthCacheEntry{
		Body:      body,
		ExpiresAt: time.Now().Add(ttl),
	}
}

// RevokeByToken removes all entries associated with a specific token
func (ac *AuthCache) RevokeByToken(token string) int {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	if token == "*" {
		count := len(ac.cache)
		ac.cache = make(map[string]*AuthCacheEntry)
		return count
	}

	count := 0
	prefix := token + "|"
	for key := range ac.cache {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			delete(ac.cache, key)
			count++
		}
	}
	return count
}

// GetInfoByToken retrieves all cached path validations for a token
func (ac *AuthCache) GetInfoByToken(token string) map[string]interface{} {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	result := make(map[string]interface{})
	prefix := token + "|"

	now := time.Now()

	for key, entry := range ac.cache {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			if now.After(entry.ExpiresAt) {
				continue
			}
			// Extract context (method|host|path) from key
			context := key[len(prefix):]
			result[context] = map[string]interface{}{
				"body":      entry.Body,
				"expiresIn": int(time.Until(entry.ExpiresAt).Seconds()),
			}
		}
	}
	return result
}

// CleanupExpired removes expired entries
func (ac *AuthCache) CleanupExpired() {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	now := time.Now()
	for key, entry := range ac.cache {
		if now.After(entry.ExpiresAt) {
			delete(ac.cache, key)
		}
	}
}

func init() {
	// Start background cleanup
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		for range ticker.C {
			GetAuthCache().CleanupExpired()
		}
	}()
}
