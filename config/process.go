package config

import (
	"encoding/json"
	"errors"
	"log"
	"net/url"
	"os"
	"strings"

	"aps/firewall"
	"aps/security"
)

// NewProxyManagerFn is a factory used by processConfig to resolve a
// mapping's outbound proxy list into a ProxyResolver. The root main
// package injects its *ProxyManager (see config.go) at init time so
// aps/config stays free of any concrete proxy-manager dependency.
// Stage 9.2 will move the proxy manager into aps/proxy, after which
// the factory can be wired directly without going through root.
var NewProxyManagerFn func(urls []string) ProxyResolver

// LoadConfig reads the JSON file, processes it, and returns the config.
// It does NOT set the global debug flag — that lives in root main because
// util.IsDebugMode is the canonical source (Stage 8 cleanup).
func LoadConfig(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var cfg Config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, err
	}

	if err := processConfig(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// processConfig resolves mappings, validates firewall rules, and applies
// KDF settings to the loaded config.
func processConfig(cfg *Config) error {
	validMappings := make([]Mapping, 0, len(cfg.Mappings))
	for i := range cfg.Mappings {
		mapping := &cfg.Mappings[i]

		if mapping.From == nil {
			log.Printf("Warning: mapping %d skipped - 'from' field is required", i+1)
			continue
		}
		fromConfig, err := parseEndpointConfig(mapping.From)
		if err != nil {
			log.Printf("Warning: mapping %d skipped - failed to parse 'from': %v", i+1, err)
			continue
		}
		if fromConfig == nil || len(fromConfig.URLs) == 0 {
			log.Printf("Warning: mapping %d skipped - 'from' URL is empty", i+1)
			continue
		}
		mapping.FromConfig = fromConfig

		if mapping.To == nil {
			log.Printf("Warning: mapping %d skipped - 'to' field is required", i+1)
			continue
		}
		toConfig, err := parseEndpointConfig(mapping.To)
		if err != nil {
			log.Printf("Warning: mapping %d skipped - failed to parse 'to': %v", i+1, err)
			continue
		}
		if toConfig == nil || (len(toConfig.URLs) == 0 && toConfig.URL == "") {
			log.Printf("Warning: mapping %d skipped - 'to' URL is empty", i+1)
			continue
		}
		mapping.ToConfig = toConfig

		mapping.ServerNames = ParseStringOrArray(mapping.Servers)
		if len(mapping.ServerNames) == 0 {
			isRawMapping := false
			if len(fromConfig.URLs) > 0 {
				firstURL := fromConfig.URLs[0]
				if strings.HasPrefix(firstURL, "tcp://") || strings.HasPrefix(firstURL, "tcps://") ||
					strings.HasPrefix(firstURL, "udp://") {
					isRawMapping = true
				}
			}

			if !isRawMapping {
				for name := range cfg.Servers {
					if serverConfig, ok := cfg.Servers[name]; ok {
						if serverConfig.Type == ServerTypeHTTP || serverConfig.Type == ServerTypeHTTPUDP {
							mapping.ServerNames = append(mapping.ServerNames, name)
						}
					}
				}
				if len(mapping.ServerNames) == 0 {
					log.Printf("Warning: mapping %d skipped - 'servers' is not specified and no HTTP/HTTPS servers are defined", i+1)
					continue
				}
			}
		} else {
			for _, name := range mapping.ServerNames {
				if _, ok := cfg.Servers[name]; !ok {
					log.Printf("Warning: mapping %d skipped - server name '%s' not found in servers config", i+1, name)
					continue
				}
			}
		}

		if mapping.Via != nil {
			proxySource := mapping.Via.Proxies
			if fromConfig.Proxy != nil {
				proxySource = fromConfig.Proxy
			}
			mapping.ProxyNames = ParseStringOrArray(proxySource)

			if len(mapping.ProxyNames) > 0 {
				var allProxies []string
				for _, name := range mapping.ProxyNames {
					if proxyConfig, ok := cfg.Proxies[name]; ok {
						allProxies = append(allProxies, proxyConfig.URLs...)
					} else {
						allProxies = append(allProxies, name)
					}
				}
				if len(allProxies) > 0 && NewProxyManagerFn != nil {
					mapping.ResolvedProxy = NewProxyManagerFn(allProxies)
				}
			}

			mapping.EndpointNames = ParseStringOrArray(mapping.Via.Endpoints)
			mapping.TunnelNames = ParseStringOrArray(mapping.Via.Tunnels)
		}

		validMappings = append(validMappings, *mapping)
	}

	cfg.Mappings = validMappings
	log.Printf("Loaded %d valid mapping rules (filtered from %d total)", len(validMappings), len(cfg.Mappings))

	if cfg.Firewalls != nil {
		for name, rule := range cfg.Firewalls {
			if err := firewall.ParseFirewallRule(rule); err != nil {
				log.Printf("[FIREWALL] Warning: failed to parse firewall rule '%s': %v", name, err)
			} else {
				log.Printf("[FIREWALL] Loaded firewall rule '%s'", name)
			}
		}
	}

	kdfTunnels := make(map[string]*security.TunnelKDFConfig)
	for name, t := range cfg.Tunnels {
		if t == nil {
			continue
		}
		kdfTunnels[name] = &security.TunnelKDFConfig{
			KDFVersion: t.KDFVersion,
			KDFSalt:    stringPtr(t.KDFSalt),
		}
	}
	if err := security.EnsureTunnelKDFSettings(kdfTunnels); err != nil {
		return err
	}

	return nil
}

// Reload re-reads the config file and atomically swaps fields.
func (c *Config) Reload(filename string) (map[string]*ListenConfig, error) {
	c.mu.RLock()
	oldServers := make(map[string]*ListenConfig)
	for name, cfg := range c.Servers {
		configCopy := ListenConfig{
			Port:               cfg.Port,
			Type:               cfg.Type,
			Key:                cfg.Key,
			Cert:               cfg.Cert,
			Endpoints:          cfg.Endpoints,
			Tunnels:            cfg.Tunnels,
			Firewall:           cfg.Firewall,
			ConnectionPolicies: cfg.ConnectionPolicies,
			TrafficPolicies:    cfg.TrafficPolicies,
		}
		if cfg.Public != nil {
			v := *cfg.Public
			configCopy.Public = &v
		}
		if cfg.Panel != nil {
			v := *cfg.Panel
			configCopy.Panel = &v
		}
		if cfg.LogLevel != nil {
			v := *cfg.LogLevel
			configCopy.LogLevel = &v
		}
		if cfg.LogRetentionHours != nil {
			v := *cfg.LogRetentionHours
			configCopy.LogRetentionHours = &v
		}
		if cfg.Auth != nil {
			authCopy := *cfg.Auth
			configCopy.Auth = &authCopy
		}
		oldServers[name] = &configCopy
	}
	c.mu.RUnlock()

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var newConfig Config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&newConfig); err != nil {
		return nil, err
	}

	if err := processConfig(&newConfig); err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.Servers = newConfig.Servers
	c.Proxies = newConfig.Proxies
	c.Tunnels = newConfig.Tunnels
	c.P12s = newConfig.P12s
	c.Scripting = newConfig.Scripting
	c.Mappings = newConfig.Mappings
	c.Auth = newConfig.Auth
	c.Debug = newConfig.Debug
	c.Firewalls = newConfig.Firewalls
	c.mu.Unlock()

	log.Printf("Configuration reloaded: %d valid mapping rules", len(newConfig.Mappings))
	for _, mapping := range c.Mappings {
		log.Printf("  Rule: %s -> %s on servers: %v", mapping.GetFromURL(), mapping.GetToURL(), mapping.ServerNames)
	}
	if len(newConfig.Firewalls) > 0 {
		log.Printf("Firewall rules reloaded: %d rule groups", len(newConfig.Firewalls))
		for name := range newConfig.Firewalls {
			log.Printf("  Firewall: %s", name)
		}
	}

	return oldServers, nil
}

// GetMappings returns a snapshot copy of the mappings slice.
func (c *Config) GetMappings() []Mapping {
	c.mu.RLock()
	defer c.mu.RUnlock()
	mappings := make([]Mapping, len(c.Mappings))
	copy(mappings, c.Mappings)
	return mappings
}

// parseEndpointConfig decodes the "from"/"to" interface{} into a
// concrete *EndpointConfig. Accepts string, []string, or full object.
func parseEndpointConfig(data interface{}) (*EndpointConfig, error) {
	if data == nil {
		return nil, nil
	}

	if str, ok := data.(string); ok {
		str = strings.TrimSpace(str)
		str = strings.Trim(str, "`")
		epc := &EndpointConfig{
			URLs: []string{str},
		}
		if u, err := url.Parse(str); err == nil {
			epc.ParsedURLs = append(epc.ParsedURLs, u)
		}
		return epc, nil
	}

	if arr, ok := data.([]interface{}); ok {
		var urls []string
		for _, item := range arr {
			if str, ok := item.(string); ok {
				urls = append(urls, str)
			}
		}
		if len(urls) > 0 {
			epc := &EndpointConfig{URLs: urls}
			for _, uStr := range urls {
				if u, err := url.Parse(uStr); err == nil {
					epc.ParsedURLs = append(epc.ParsedURLs, u)
				}
			}
			return epc, nil
		}
	}
	if arr, ok := data.([]string); ok {
		epc := &EndpointConfig{URLs: arr}
		for _, uStr := range arr {
			if u, err := url.Parse(uStr); err == nil {
				epc.ParsedURLs = append(epc.ParsedURLs, u)
			}
		}
		return epc, nil
	}

	if mapData, ok := data.(map[string]interface{}); ok {
		jsonBytes, err := json.Marshal(mapData)
		if err != nil {
			return nil, err
		}
		var epc EndpointConfig
		if err := json.Unmarshal(jsonBytes, &epc); err != nil {
			return nil, err
		}
		if urlData, ok := mapData["url"]; ok {
			if str, ok := urlData.(string); ok {
				epc.URLs = append(epc.URLs, str)
			} else if arr, ok := urlData.([]interface{}); ok {
				for _, item := range arr {
					if str, ok := item.(string); ok {
						epc.URLs = append(epc.URLs, str)
					}
				}
			} else if arr, ok := urlData.([]string); ok {
				epc.URLs = append(epc.URLs, arr...)
			}
		}
		if epc.URL != "" {
			epc.URLs = append(epc.URLs, epc.URL)
		}
		// Dedupe
		keys := make(map[string]bool)
		var list []string
		for _, entry := range epc.URLs {
			if _, value := keys[entry]; !value {
				keys[entry] = true
				list = append(list, entry)
			}
		}
		epc.URLs = list
		epc.URL = ""

		for _, uStr := range epc.URLs {
			if u, err := url.Parse(uStr); err == nil {
				epc.ParsedURLs = append(epc.ParsedURLs, u)
			}
		}
		return &epc, nil
	}

	return nil, errors.New("invalid endpoint config format")
}
