// Package config holds the configuration types for the APS reverse proxy.
//
// Stage 9.1a extracted these types from the root `package main` so that
// non-main sub-packages (aps/proxy, aps/handler, aps/transport, etc.) can
// import them without depending on `package main` (which Go forbids).
//
// Root main retains Go type aliases (`type Config = config.Config` and
// friends) so existing call-sites that reference the bare names compile
// unchanged.
package config

import (
	"encoding/json"
	"math"
	"math/rand"
	"net/url"
	"strings"
	"sync"
	"time"

	"aps/firewall"
	"aps/stats"
)

// Server Types
const (
	ServerTypeTCP     = 1
	ServerTypeHTTP    = 2
	ServerTypeUDP     = 3
	ServerTypeTCPUDP  = 4
	ServerTypeHTTPUDP = 5
	ServerTypeHTTP3   = 6 // Reserved
)

// ProxyResolver is the contract that Mapping.ResolvedProxy must satisfy.
// It is implemented by *ProxyManager (Stage 9.2 will live in aps/proxy).
// Using an interface here lets aps/config stay free of any dependency on
// the concrete proxy manager, which would otherwise create a cycle.
type ProxyResolver interface {
	GetRandomProxy() string
}

// Config is the top-level configuration loaded from config.json.
type Config struct {
	Debug             *bool                          `json:"debug,omitempty"`             // Debug mode toggle
	LogLevel          *int                           `json:"logLevel,omitempty"`          // Log level: 0=none, 1=basic, 2=full (with body/header)
	LogRetentionHours *int                           `json:"logRetentionHours,omitempty"` // Log retention in hours, default 24
	Servers           map[string]*ListenConfig       `json:"servers"`
	Proxies           map[string]*ProxyConfig        `json:"proxies,omitempty"`
	Tunnels           map[string]*TunnelConfig       `json:"tunnels,omitempty"`
	Endpoints         map[string]*EndpointConfig_APS `json:"endpoints,omitempty"` // Endpoint configurations
	Mirrors           map[string][]string            `json:"mirrors,omitempty"`   // Mirror groups
	Auth              *AuthConfig                    `json:"auth,omitempty"`
	AuthProviders     map[string]*AuthProviderConfig `json:"authProviders,omitempty"` // Third-party auth providers
	P12s              map[string]*P12Config          `json:"p12s,omitempty"`
	Scripting         *ScriptingConfig               `json:"scripting,omitempty"`
	StaticCache       *StaticCacheConfig             `json:"static_cache,omitempty"` // Static cache config
	Firewalls         map[string]*firewall.FirewallRule `json:"firewalls,omitempty"` // Firewall rule groups
	Mappings          []Mapping                      `json:"mappings"`
	Version           int64                          `json:"version,omitempty"` // Config version (concurrency edit detection)
	RateLimitRules    map[string]*stats.RateLimitRule `json:"rateLimitRules,omitempty"`
	mu                sync.RWMutex
}

// Public lock helpers so callers outside aps/config can coordinate
// access without depending on the unexported mu field. See
// ServerManager.StartAll in main.go for an example.
func (c *Config) RLock()   { c.mu.RLock() }
func (c *Config) RUnlock() { c.mu.RUnlock() }
func (c *Config) Lock()    { c.mu.Lock() }
func (c *Config) Unlock()  { c.mu.Unlock() }

// ListenConfig describes one server entry (port + protocol).
type ListenConfig struct {
	Port              int         `json:"port"`
	Type              int         `json:"type,omitempty"`  // 1=TCP, 2=HTTP, 3=UDP, 4=TCP+UDP, 5=HTTP+UDP
	Cert              interface{} `json:"cert,omitempty"`  // string ("auto") or CertFiles
	Key               string      `json:"key,omitempty"`
	Auth              *ServerAuth `json:"auth,omitempty"`
	LogLevel          *int        `json:"logLevel,omitempty"`
	LogRetentionHours *int        `json:"logRetentionHours,omitempty"`
	Endpoints         interface{} `json:"endpoints,omitempty"` // string or []string
	Tunnels           interface{} `json:"tunnels,omitempty"`   // string or []string
	Public            *bool       `json:"public,omitempty"`    // true: 0.0.0.0:port, false: 127.0.0.1:port (default true)
	Panel             *bool       `json:"panel,omitempty"`     // true: register /.api & /.admin
	TunnelMTLS        *bool       `json:"tunnelMTLS,omitempty"`
	TunnelMTLSCA      string      `json:"tunnelMTLSCA,omitempty"`
	Firewall          string      `json:"firewall,omitempty"`
	RateLimitRules    []string    `json:"rateLimitRules,omitempty"`
	ConnectionPolicies
	TrafficPolicies
}

// ServerAuth restricts which users/groups may use this server.
type ServerAuth struct {
	Users  []string `json:"users,omitempty"`
	Groups []string `json:"groups,omitempty"`
}

// CertFiles references PEM cert + key files.
type CertFiles struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

// UnmarshalJSON handles the "auto"/"acme" magic string and a flat int port.
func (lc *ListenConfig) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as an int first
	var port int
	if err := json.Unmarshal(data, &port); err == nil {
		lc.Port = port
		// Defaults when only port is provided
		t := true
		lc.Public = &t
		return nil
	}

	// Otherwise unmarshal as object
	type Alias ListenConfig
	var obj Alias
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	*lc = ListenConfig(obj)

	// Apply defaults
	if lc.Public == nil {
		t := true
		lc.Public = &t
	}
	if lc.Type == 0 {
		lc.Type = ServerTypeHTTP
	}

	if certStr, ok := obj.Cert.(string); ok {
		if certStr != "auto" && certStr != "acme" {
			return errInvalidCertString
		}
		lc.Cert = certStr
	} else if certMap, ok := obj.Cert.(map[string]interface{}); ok {
		files := CertFiles{}
		if c, ok := certMap["cert"].(string); ok {
			files.Cert = c
		}
		if k, ok := certMap["key"].(string); ok {
			files.Key = k
		}
		lc.Cert = files
	} else if obj.Cert != nil {
		return errInvalidCertField
	}

	return nil
}

// ViaConfig selects how to route a mapping (proxies, tunnels, endpoints).
type ViaConfig struct {
	Proxies   interface{} `json:"proxies,omitempty"`
	Tunnels   interface{} `json:"tunnels,omitempty"`
	Endpoints interface{} `json:"endpoints,omitempty"`
}

// RuleAuth specifies which users/groups/proxy a Mapping requires.
type RuleAuth struct {
	Users        []string `json:"users,omitempty"`
	Groups       []string `json:"groups,omitempty"`
	AuthProvider string   `json:"authProvider,omitempty"`
	AuthUrl      string   `json:"authUrl,omitempty"`
	LoginUrl     string   `json:"loginUrl,omitempty"`
	AuthLevel    *int     `json:"authLevel,omitempty"`
}

// Mapping is a single proxy rule.
type Mapping struct {
	From              interface{} `json:"from"` // string or EndpointConfig object
	To                interface{} `json:"to"`   // string or EndpointConfig object
	Via               *ViaConfig  `json:"via,omitempty"`
	Servers           interface{} `json:"servers,omitempty"`
	Cc                []string    `json:"cc,omitempty"`
	P12               string      `json:"p12,omitempty"`
	Auth              *RuleAuth   `json:"auth,omitempty"`
	LogLevel          *int        `json:"logLevel,omitempty"`
	LogRetentionHours *int        `json:"logRetentionHours,omitempty"`
	Firewall          string      `json:"firewall,omitempty"`
	RateLimitRules    []string    `json:"rateLimitRules,omitempty"`
	ConnectionPolicies
	TrafficPolicies

	// Resolved internal fields
	FromConfig    *EndpointConfig
	ToConfig      *EndpointConfig
	ServerNames   []string
	ProxyNames    []string
	EndpointNames []string
	TunnelNames   []string
	ResolvedProxy ProxyResolver
}

// GetFromURL returns the source URL string.
func (m *Mapping) GetFromURL() string {
	if m.FromConfig != nil {
		if len(m.FromConfig.URLs) > 0 {
			return m.FromConfig.URLs[0]
		}
		return m.FromConfig.URL
	}
	if str, ok := m.From.(string); ok {
		return str
	}
	return ""
}

// GetToURL returns the destination URL string.
func (m *Mapping) GetToURL() string {
	if m.ToConfig != nil {
		if len(m.ToConfig.URLs) > 0 {
			return m.ToConfig.URLs[0]
		}
		return m.ToConfig.URL
	}
	if str, ok := m.To.(string); ok {
		return str
	}
	return ""
}

// GetFromConfig returns the resolved From EndpointConfig.
func (m *Mapping) GetFromConfig() *EndpointConfig {
	return m.FromConfig
}

// GetToConfig returns the resolved To EndpointConfig.
func (m *Mapping) GetToConfig() *EndpointConfig {
	return m.ToConfig
}

// ConnectionPolicies holds timeouts, concurrency, and quality settings.
type ConnectionPolicies struct {
	Timeout     *int     `json:"timeout,omitempty"`
	IdleTimeout *int     `json:"idleTimeout,omitempty"`
	MaxThread   *int     `json:"maxThread,omitempty"`
	Quality     *float64 `json:"quality,omitempty"`
}

// TrafficPolicies holds rate limit and quota settings.
type TrafficPolicies struct {
	RateLimit    *string `json:"rateLimit,omitempty"`
	TrafficQuota *string `json:"trafficQuota,omitempty"`
	RequestQuota *int64  `json:"requestQuota,omitempty"`
}

// User is one auth identity.
type User struct {
	Password          string      `json:"password"`
	Admin             bool        `json:"admin,omitempty"`
	Token             string      `json:"token,omitempty"`
	Groups            []string    `json:"groups,omitempty"`
	LogLevel          *int        `json:"logLevel,omitempty"`
	LogRetentionHours *int        `json:"logRetentionHours,omitempty"`
	Endpoint          interface{} `json:"endpoint,omitempty"`
	Tunnel            interface{} `json:"tunnel,omitempty"`
	RateLimitRules    []string    `json:"rateLimitRules,omitempty"`
	ConnectionPolicies
	TrafficPolicies
}

// Group is a named set of users that share settings.
type Group struct {
	Users             []string    `json:"users,omitempty"`
	LogLevel          *int        `json:"logLevel,omitempty"`
	LogRetentionHours *int        `json:"logRetentionHours,omitempty"`
	Endpoint          interface{} `json:"endpoint,omitempty"`
	Tunnel            interface{} `json:"tunnel,omitempty"`
	ConnectionPolicies
	TrafficPolicies
}

// AuthConfig groups Users and Groups.
type AuthConfig struct {
	Users  map[string]*User  `json:"users,omitempty"`
	Groups map[string]*Group `json:"groups,omitempty"`
}

// TokenLocation specifies where a token can be found or sent.
type TokenLocation struct {
	Header      string `json:"header,omitempty"`
	Cookie      string `json:"cookie,omitempty"`
	QueryString string `json:"querystring,omitempty"`
}

// AuthProviderConfig configures a third-party auth backend.
type AuthProviderConfig struct {
	URL         string         `json:"url"`
	LoginUrl    string         `json:"loginUrl,omitempty"`
	Level       int            `json:"level"`
	TokenSource *TokenLocation `json:"tokenSource,omitempty"`
	TokenDest   *TokenLocation `json:"tokenDest,omitempty"`
}

// ProxyConfig configures an outbound proxy.
type ProxyConfig struct {
	URLs              []string `json:"urls"`
	LogLevel          *int     `json:"logLevel,omitempty"`
	LogRetentionHours *int     `json:"logRetentionHours,omitempty"`
	ConnectionPolicies
	TrafficPolicies
}

// UnmarshalJSON handles three shapes: string, []string, or full object.
func (pc *ProxyConfig) UnmarshalJSON(data []byte) error {
	var singleURL string
	if err := json.Unmarshal(data, &singleURL); err == nil {
		pc.URLs = []string{singleURL}
		return nil
	}
	var urls []string
	if err := json.Unmarshal(data, &urls); err == nil {
		pc.URLs = urls
		return nil
	}
	type Alias ProxyConfig
	var obj Alias
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	*pc = ProxyConfig(obj)
	return nil
}

// TunnelConfig configures one named tunnel.
type TunnelConfig struct {
	Servers           []string  `json:"servers"`
	Password          string    `json:"password,omitempty"`
	KDFVersion        string    `json:"kdfVersion,omitempty"`
	KDFSalt           string    `json:"kdfSalt,omitempty"`
	Auth              *RuleAuth `json:"auth,omitempty"`
	LogLevel          *int      `json:"logLevel,omitempty"`
	LogRetentionHours *int      `json:"logRetentionHours,omitempty"`
	TrafficPolicies
}

// ScriptingConfig configures external script interpreters.
type ScriptingConfig struct {
	PythonPath string `json:"pythonPath,omitempty"`
	NodePath   string `json:"nodePath,omitempty"`
}

// P12Config references a PKCS#12 client cert.
type P12Config struct {
	Path     string `json:"path,omitempty"`
	Password string `json:"password,omitempty"`
}

// StaticCacheConfig configures the static file cache.
type StaticCacheConfig struct {
	Enabled            bool            `json:"enabled"`
	CacheDir           string          `json:"cache_dir,omitempty"`
	TTL                int             `json:"ttl,omitempty"`
	FileType           []string        `json:"file_type,omitempty"`
	MaxFileSizeMB      int             `json:"max_file_size_mb,omitempty"`
	SizeLimit          *CacheSizeLimit `json:"size_limit,omitempty"`
	StreamingThreshold int             `json:"streaming_threshold_mb,omitempty"`
	EnableEncryption   *bool           `json:"enable_encryption,omitempty"`
	EnableCompression  *bool           `json:"enable_compression,omitempty"`
}

// CacheSizeLimit specifies memory and disk cache caps.
type CacheSizeLimit struct {
	Mem  string `json:"mem,omitempty"`
	Disk string `json:"disk,omitempty"`
}

// GRPCConfig defines rules to match/modify gRPC requests.
type GRPCConfig struct {
	Service    string                 `json:"service,omitempty"`
	Method     string                 `json:"method,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	RestToGrpc *RestToGrpcConfig      `json:"rest_to_grpc,omitempty"`
}

// RestToGrpcConfig defines REST-to-gRPC translation rules.
type RestToGrpcConfig struct {
	RequestBodyMapping map[string]string `json:"request_body_mapping,omitempty"`
}

// WebSocketMessageConfig defines a rule for matching/modifying a single message.
type WebSocketMessageConfig struct {
	Match   string            `json:"match,omitempty"`
	Replace map[string]string `json:"replace,omitempty"`
	Log     bool              `json:"log,omitempty"`
	Drop    bool              `json:"drop,omitempty"`
}

// WebSocketConfig configures WebSocket message interception.
type WebSocketConfig struct {
	InterceptClientMessages []WebSocketMessageConfig `json:"intercept_client_messages,omitempty"`
	InterceptServerMessages []WebSocketMessageConfig `json:"intercept_server_messages,omitempty"`
}

// EndpointConfig describes a single endpoint (URL + headers + gRPC + WebSocket rules).
type EndpointConfig struct {
	URL         string                 `json:"url,omitempty"`
	URLs        []string               `json:"urls,omitempty"`
	Method      interface{}            `json:"method,omitempty"`
	Headers     map[string]interface{} `json:"headers,omitempty"`
	QueryString map[string]interface{} `json:"querystring,omitempty"`
	Proxy       interface{}            `json:"proxy,omitempty"`
	Match       string                 `json:"match,omitempty"`
	Replace     map[string]string      `json:"replace,omitempty"`
	GRPC        *GRPCConfig            `json:"grpc,omitempty"`
	WebSocket   *WebSocketConfig       `json:"websocket,omitempty"`
	Script      string                 `json:"script,omitempty"`
	IPs         interface{}            `json:"ips,omitempty"`
	Insecure    *bool                  `json:"insecure,omitempty"`

	// Pre-parsed for performance
	ParsedURLs []*url.URL `json:"-"`
}

// GetHeader returns a header value plus flags. Random pick for array values.
func (ec *EndpointConfig) GetHeader(key string) (string, bool, bool) {
	if ec.Headers == nil {
		return "", false, false
	}
	value, exists := ec.Headers[key]
	if !exists {
		return "", false, false
	}
	if value == nil {
		return "", true, true
	}
	if strValue, ok := value.(string); ok {
		return strValue, true, false
	}
	if arrValue, ok := value.([]interface{}); ok && len(arrValue) > 0 {
		randomIndex := rand.Intn(len(arrValue))
		if strValue, ok := arrValue[randomIndex].(string); ok {
			if strings.EqualFold(key, "Authorization") {
				logRandomAuth(randomIndex, len(arrValue), MaskToken(strValue))
			}
			return strValue, true, false
		}
	}
	if arrValue, ok := value.([]string); ok && len(arrValue) > 0 {
		randomIndex := rand.Intn(len(arrValue))
		if strings.EqualFold(key, "Authorization") {
			logRandomAuth(randomIndex, len(arrValue), MaskToken(arrValue[randomIndex]))
		}
		return arrValue[randomIndex], true, false
	}
	return "", false, false
}

// GetAllHeaders returns the full header map (Authorization randomly picked).
func (ec *EndpointConfig) GetAllHeaders() (map[string]string, []string) {
	result := make(map[string]string)
	toRemove := make([]string, 0)
	if ec.Headers == nil {
		return result, toRemove
	}
	for key := range ec.Headers {
		if value, exists, shouldRemove := ec.GetHeader(key); exists {
			if shouldRemove {
				toRemove = append(toRemove, key)
			} else {
				result[key] = value
			}
		}
	}
	return result, toRemove
}

// GetIPs parses the IPs field (string or []string).
func (ec *EndpointConfig) GetIPs() []string {
	if ec.IPs == nil {
		return nil
	}
	return ParseStringOrArray(ec.IPs)
}

// GetQueryString returns the resolved query-string parameter map.
func (ec *EndpointConfig) GetQueryString() (map[string]string, []string) {
	result := make(map[string]string)
	toRemove := make([]string, 0)
	if ec.QueryString == nil {
		return result, toRemove
	}
	for key, value := range ec.QueryString {
		if value == nil {
			toRemove = append(toRemove, key)
			continue
		}
		if strValue, ok := value.(string); ok {
			result[key] = strValue
		}
	}
	return result, toRemove
}

// MatchesMethod returns true if the request method matches the configured method.
func (ec *EndpointConfig) MatchesMethod(requestMethod string) bool {
	if ec.Method == nil {
		return true
	}
	if strMethod, ok := ec.Method.(string); ok {
		return strings.EqualFold(strMethod, requestMethod)
	}
	if arrMethod, ok := ec.Method.([]interface{}); ok {
		for _, method := range arrMethod {
			if strMethod, ok := method.(string); ok {
				if strings.EqualFold(strMethod, requestMethod) {
					return true
				}
			}
		}
		return false
	}
	if arrMethod, ok := ec.Method.([]string); ok {
		for _, method := range arrMethod {
			if strings.EqualFold(method, requestMethod) {
				return true
			}
		}
		return false
	}
	return true
}

// FinalPolicies is the resolved set of connection policies.
type FinalPolicies struct {
	Timeout     time.Duration
	IdleTimeout time.Duration
	MaxThread   int
	Quality     float64
}

// ResolvePolicies picks the tightest (smallest) value across all levels.
func (c *Config) ResolvePolicies(server *ListenConfig, mapping *Mapping, user *User, username string) FinalPolicies {
	final := FinalPolicies{
		Timeout:     10 * time.Minute,
		IdleTimeout: 100 * time.Second,
		MaxThread:   math.MaxInt32,
		Quality:     1.0,
	}
	policies := []*ConnectionPolicies{&server.ConnectionPolicies}
	if mapping != nil {
		policies = append(policies, &mapping.ConnectionPolicies)
	}
	if user != nil {
		policies = append(policies, &user.ConnectionPolicies)
		if c.Auth != nil && c.Auth.Groups != nil {
			for _, groupName := range user.Groups {
				if group, ok := c.Auth.Groups[groupName]; ok {
					policies = append(policies, &group.ConnectionPolicies)
				}
			}
		}
	}
	for _, p := range policies {
		if p.Timeout != nil {
			timeout := time.Duration(*p.Timeout) * time.Second
			if timeout < final.Timeout {
				final.Timeout = timeout
			}
		}
		if p.IdleTimeout != nil {
			idleTimeout := time.Duration(*p.IdleTimeout) * time.Second
			if idleTimeout < final.IdleTimeout {
				final.IdleTimeout = idleTimeout
			}
		}
		if p.MaxThread != nil && *p.MaxThread > 0 {
			if *p.MaxThread < final.MaxThread {
				final.MaxThread = *p.MaxThread
			}
		}
		if p.Quality != nil {
			if *p.Quality < final.Quality {
				final.Quality = *p.Quality
			}
		}
	}
	if final.MaxThread == math.MaxInt32 {
		final.MaxThread = 0
	}
	return final
}

// ResolveTrafficPolicies returns the tightest rate limit plus per-source quota maps.
func (c *Config) ResolveTrafficPolicies(server *ListenConfig, mapping *Mapping, tunnel *TunnelConfig, proxy *ProxyConfig, user *User, username string) (string, map[string]string, map[string]int64, error) {
	trafficQuotas := make(map[string]string)
	requestQuotas := make(map[string]int64)
	var rateLimits []string

	policies := []TrafficPolicies{}
	sourceKeys := []string{}

	if server != nil {
		policies = append(policies, server.TrafficPolicies)
		for name, s := range c.Servers {
			if s == server {
				sourceKeys = append(sourceKeys, "server:"+name)
				break
			}
		}
	}
	if mapping != nil {
		policies = append(policies, mapping.TrafficPolicies)
		sourceKeys = append(sourceKeys, "mapping:"+mapping.GetFromURL())
	}
	if tunnel != nil {
		policies = append(policies, tunnel.TrafficPolicies)
		for name, t := range c.Tunnels {
			if t == tunnel {
				sourceKeys = append(sourceKeys, "tunnel:"+name)
				break
			}
		}
	}
	if proxy != nil {
		policies = append(policies, proxy.TrafficPolicies)
		for name, p := range c.Proxies {
			if p == proxy {
				sourceKeys = append(sourceKeys, "proxy:"+name)
				break
			}
		}
	}
	if user != nil {
		policies = append(policies, user.TrafficPolicies)
		sourceKeys = append(sourceKeys, "user:"+username)
		if c.Auth != nil && c.Auth.Groups != nil {
			for _, groupName := range user.Groups {
				if group, ok := c.Auth.Groups[groupName]; ok {
					policies = append(policies, group.TrafficPolicies)
					sourceKeys = append(sourceKeys, "group:"+groupName)
				}
			}
		}
	}

	for i, p := range policies {
		if p.RateLimit != nil {
			rateLimits = append(rateLimits, *p.RateLimit)
		}
		if p.TrafficQuota != nil {
			if i < len(sourceKeys) {
				trafficQuotas[sourceKeys[i]] = *p.TrafficQuota
			}
		}
		if p.RequestQuota != nil {
			if i < len(sourceKeys) {
				requestQuotas[sourceKeys[i]] = *p.RequestQuota
			}
		}
	}

	minRateLimit, err := minRate(rateLimits)
	if err != nil {
		return "", nil, nil, err
	}
	return minRateLimit, trafficQuotas, requestQuotas, nil
}

// ParseStringOrArray accepts string or []string and returns []string.
func ParseStringOrArray(data interface{}) []string {
	if data == nil {
		return nil
	}
	if str, ok := data.(string); ok {
		return []string{str}
	}
	if arr, ok := data.([]interface{}); ok {
		var result []string
		for _, item := range arr {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}
	if arr, ok := data.([]string); ok {
		return arr
	}
	return nil
}

// minRate finds the lowest rate from a slice of rate strings.
func minRate(rates []string) (string, error) {
	if len(rates) == 0 {
		return "", nil
	}
	var minBps float64 = math.MaxFloat64
	minRateStr := ""
	for _, rateStr := range rates {
		bps, err := parseRateLimit(rateStr)
		if err != nil {
			return "", err
		}
		if bps > 0 && bps < minBps {
			minBps = bps
			minRateStr = rateStr
		}
	}
	return minRateStr, nil
}

// parseRateLimit converts "10mbps" / "1gbps" etc. to bytes per second.
func parseRateLimit(rateStr string) (float64, error) {
	if rateStr == "" {
		return 0, nil
	}
	rateStr = strings.ToLower(strings.TrimSpace(rateStr))
	var multiplier float64
	if strings.HasSuffix(rateStr, "kbps") {
		multiplier = 1024 / 8
		rateStr = strings.TrimSuffix(rateStr, "kbps")
	} else if strings.HasSuffix(rateStr, "mbps") {
		multiplier = 1024 * 1024 / 8
		rateStr = strings.TrimSuffix(rateStr, "mbps")
	} else if strings.HasSuffix(rateStr, "gbps") {
		multiplier = 1024 * 1024 * 1024 / 8
		rateStr = strings.TrimSuffix(rateStr, "gbps")
	} else {
		return 0, errInvalidRateUnit
	}
	val, err := parseRateFloat(rateStr)
	if err != nil {
		return 0, err
	}
	return val * multiplier, nil
}

// MaskToken hides part of a token for safe log output.
func MaskToken(token string) string {
	if len(token) <= 20 {
		return token[:minInt(5, len(token))] + "***"
	}
	return token[:10] + "***" + token[len(token)-5:]
}

// stringPtr returns a pointer to s (used by processConfig and other code).
func stringPtr(s string) *string { return &s }

// logRandomAuth writes a debug log when a random Authorization value is picked.
func logRandomAuth(index, total int, masked string) {
	logPrintf("[RANDOM AUTH] Selected Authorization [%d/%d]: %s", index+1, total, masked)
}

// minInt returns the smaller of a and b.
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
