package main

import (
	"sync"
	"time"
)

// AuthCacheEntry represents a cached authentication result
type AuthCacheEntry struct {
	Body      string // Response body from auth service
	Hash      string // MD5(Base64(CanonicalJSON(Body)))
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
func (ac *AuthCache) GenerateCacheKey(token, method, host, path string) string {
	return token + "|" + method + "|" + host + "|" + path
}

// Get retrieves a cached entry if it is not expired
func (ac *AuthCache) Get(key string) (string, string, bool) {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	entry, ok := ac.cache[key]
	if !ok {
		return "", "", false
	}

	if time.Now().After(entry.ExpiresAt) {
		return "", "", false
	}

	return entry.Body, entry.Hash, true
}

// GetStale retrieves a cached entry even if it is expired, along with its hash
func (ac *AuthCache) GetStale(key string) (string, string, bool) {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	entry, ok := ac.cache[key]
	if !ok {
		return "", "", false
	}

	return entry.Body, entry.Hash, true
}

// Set adds or updates a cache entry
func (ac *AuthCache) Set(key string, body string, hash string, ttl time.Duration) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	ac.cache[key] = &AuthCacheEntry{
		Body:      body,
		Hash:      hash,
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
