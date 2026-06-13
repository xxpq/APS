// Package proxy holds the outbound proxy manager used by mapping routing.
//
// Stage 9.2 moved *ProxyManager from root main into this sub-package so
// aps/proxy can be reused by Stage 9.5 (the reverse-proxy core). The
// Manager implements the aps/config.ProxyResolver interface (via
// GetRandomProxy) and is wired into aps/config.NewProxyManagerFn by
// root main's init() so the config processor can construct it.
package proxy

import (
	"bufio"
	"context"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Manager manages the proxy configuration for outbound requests.
type Manager struct {
	proxyConfig interface{} // Original config: string, []string, or nil
	proxyList   []string    // Resolved proxy list
	mu          sync.RWMutex
	updateTimer *time.Timer
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewManager creates a new proxy manager and resolves the initial list.
func NewManager(proxyConfig interface{}) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	pm := &Manager{
		proxyConfig: proxyConfig,
		proxyList:   make([]string, 0),
		ctx:         ctx,
		cancel:      cancel,
	}
	pm.loadProxies()
	return pm
}

// loadProxies loads the proxy list from the configured source.
func (pm *Manager) loadProxies() {
	if pm.proxyConfig == nil {
		return
	}

	// Case 1: string
	if strValue, ok := pm.proxyConfig.(string); ok {
		pm.handleStringProxy(strValue)
		return
	}

	// Case 2: []interface{}
	if arrValue, ok := pm.proxyConfig.([]interface{}); ok {
		proxies := make([]string, 0)
		for _, item := range arrValue {
			if str, ok := item.(string); ok {
				proxies = append(proxies, strings.TrimSpace(str))
			}
		}
		pm.mu.Lock()
		pm.proxyList = proxies
		pm.mu.Unlock()
		log.Printf("[PROXY MANAGER] Loaded %d proxies from array", len(proxies))
		return
	}

	// Case 3: []string
	if arrValue, ok := pm.proxyConfig.([]string); ok {
		proxies := make([]string, 0)
		for _, str := range arrValue {
			proxies = append(proxies, strings.TrimSpace(str))
		}
		pm.mu.Lock()
		pm.proxyList = proxies
		pm.mu.Unlock()
		log.Printf("[PROXY MANAGER] Loaded %d proxies from string array", len(proxies))
		return
	}
}

// handleStringProxy dispatches based on whether the string is a remote URL,
// a local file path, or a single proxy URI.
func (pm *Manager) handleStringProxy(proxyStr string) {
	proxyStr = strings.TrimSpace(proxyStr)

	// Check for remote URL config
	if strings.HasPrefix(proxyStr, "http://") || strings.HasPrefix(proxyStr, "https://") {
		if parsed, err := url.Parse(proxyStr); err == nil {
			path := parsed.Path
			if strings.HasSuffix(path, ".json") || strings.HasSuffix(path, ".txt") {
				log.Printf("[PROXY MANAGER] Detected remote proxy config: %s", proxyStr)
				pm.loadRemoteProxies(proxyStr)
				pm.startAutoUpdate(proxyStr)
				return
			}
		}
		pm.mu.Lock()
		pm.proxyList = []string{proxyStr}
		pm.mu.Unlock()
		log.Printf("[PROXY MANAGER] Loaded 1 proxy from string: %s", MaskURL(proxyStr))
		return
	}

	// Check for local file path
	if _, err := os.Stat(proxyStr); err == nil {
		log.Printf("[PROXY MANAGER] Detected local proxy file: %s", proxyStr)
		pm.loadLocalProxies(proxyStr)
		return
	}

	// Otherwise treat as a single proxy URI
	pm.mu.Lock()
	pm.proxyList = []string{proxyStr}
	pm.mu.Unlock()
	log.Printf("[PROXY MANAGER] Loaded 1 proxy from string: %s", MaskURL(proxyStr))
}

// loadLocalProxies reads the proxy list from a local file.
func (pm *Manager) loadLocalProxies(filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("[PROXY MANAGER] Error opening local proxy file %s: %v", filePath, err)
		return
	}
	defer file.Close()

	proxies := make([]string, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			proxies = append(proxies, line)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[PROXY MANAGER] Error reading local proxy file %s: %v", filePath, err)
		return
	}

	pm.mu.Lock()
	pm.proxyList = proxies
	pm.mu.Unlock()
	log.Printf("[PROXY MANAGER] Loaded %d proxies from local file: %s", len(proxies), filePath)
}

// loadRemoteProxies fetches the proxy list from a remote URL.
func (pm *Manager) loadRemoteProxies(remoteURL string) {
	resp, err := http.Get(remoteURL)
	if err != nil {
		log.Printf("[PROXY MANAGER] Error fetching remote proxy config from %s: %v", remoteURL, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[PROXY MANAGER] Remote proxy config returned status %d from %s", resp.StatusCode, remoteURL)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[PROXY MANAGER] Error reading remote proxy config from %s: %v", remoteURL, err)
		return
	}

	proxies := make([]string, 0)
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			proxies = append(proxies, line)
		}
	}

	pm.mu.Lock()
	pm.proxyList = proxies
	pm.mu.Unlock()
	log.Printf("[PROXY MANAGER] Loaded %d proxies from remote URL: %s", len(proxies), remoteURL)
}

// startAutoUpdate schedules periodic reloads every 5 minutes.
func (pm *Manager) startAutoUpdate(remoteURL string) {
	if pm.updateTimer != nil {
		pm.updateTimer.Stop()
	}

	pm.updateTimer = time.AfterFunc(5*time.Minute, func() {
		select {
		case <-pm.ctx.Done():
			return
		default:
			log.Printf("[PROXY MANAGER] Auto-updating proxies from %s", remoteURL)
			pm.loadRemoteProxies(remoteURL)
			pm.startAutoUpdate(remoteURL)
		}
	})

	log.Printf("[PROXY MANAGER] Scheduled auto-update every 5 minutes for %s", remoteURL)
}

// GetRandomProxy returns a random proxy URL from the list.
func (pm *Manager) GetRandomProxy() string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if len(pm.proxyList) == 0 {
		return ""
	}
	if len(pm.proxyList) == 1 {
		return pm.proxyList[0]
	}
	index := rand.Intn(len(pm.proxyList))
	proxyURL := pm.proxyList[index]
	log.Printf("[PROXY] Selected proxy [%d/%d]: %s", index+1, len(pm.proxyList), MaskURL(proxyURL))
	return proxyURL
}

// Close stops the auto-update timer and cancels the context.
func (pm *Manager) Close() {
	if pm.cancel != nil {
		pm.cancel()
	}
	if pm.updateTimer != nil {
		pm.updateTimer.Stop()
	}
}

// MaskURL masks the password portion of a proxy URL for safe log output.
func MaskURL(proxyURL string) string {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return proxyURL
	}
	if parsed.User != nil {
		username := parsed.User.Username()
		if password, ok := parsed.User.Password(); ok {
			maskedPassword := "***"
			if len(password) > 3 {
				maskedPassword = password[:2] + "***"
			}
			parsed.User = url.UserPassword(username, maskedPassword)
		}
	}
	return parsed.String()
}
