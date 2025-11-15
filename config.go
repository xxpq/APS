package main

import (
	"encoding/json"
	"errors"
	"log"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"
)

func init() {
	// 初始化随机数生成器
	rand.Seed(time.Now().UnixNano())
}

type Config struct {
	Servers  map[string]*ListenConfig    `json:"servers"`
	Proxies  map[string]interface{}      `json:"proxies"`
	Tunnels  map[string]*TunnelConfig    `json:"tunnels,omitempty"`
	Auth     *AuthConfig                 `json:"auth,omitempty"`
	P12s     map[string]*P12Config       `json:"p12s,omitempty"`
	Mappings []Mapping                   `json:"mappings"`
	mu       sync.RWMutex
}

type TunnelConfig struct {
	Servers  []string `json:"servers"`
	Password string   `json:"password,omitempty"` // AES key for encryption
}

type P12Config struct {
	Path     string `json:"path"`
	Password string `json:"password"`
}

type AuthConfig struct {
	Users  map[string]*User  `json:"users"`
	Groups map[string]*Group `json:"groups"`
}

// ConnectionPolicies defines policies for timeouts, concurrency, and network simulation.
type ConnectionPolicies struct {
	Timeout     *int     `json:"timeout,omitempty"`     // in seconds, default 10 minutes
	IdleTimeout *int     `json:"idleTimeout,omitempty"` // in seconds, default 100 seconds
	MaxThread   *int     `json:"maxThread,omitempty"`   // concurrency limit
	Quality     *float64 `json:"quality,omitempty"`     // 0.0 to 1.0, network quality simulation
}

type User struct {
	Password string      `json:"password"`
	Groups   []string    `json:"groups,omitempty"`
	Dump     string      `json:"dump,omitempty"`
	Endpoint interface{} `json:"endpoint,omitempty"` // string or []string
	Tunnel   interface{} `json:"tunnel,omitempty"`   // string or []string
	ConnectionPolicies
}

type Group struct {
	Users    []string    `json:"users"`
	Dump     string      `json:"dump,omitempty"`
	Endpoint interface{} `json:"endpoint,omitempty"` // string or []string
	Tunnel   interface{} `json:"tunnel,omitempty"`   // string or []string
	ConnectionPolicies
}

// EndpointConfig 用于配置请求或响应的详细信息
type EndpointConfig struct {
	URL         string                 `json:"url"`
	Method      interface{}            `json:"method,omitempty"`      // 支持 string 或 []string，限制 HTTP 方法
	Headers     map[string]interface{} `json:"headers,omitempty"`     // 支持 string 或 []string，null 表示移除
	QueryString map[string]interface{} `json:"querystring,omitempty"` // 支持 string，null 表示移除
	Proxy       interface{}            `json:"proxy,omitempty"`       // 支持 string、[]string、本地文件路径或远程 URL
	Match       string                 `json:"match,omitempty"`
	Replace     map[string]string      `json:"replace,omitempty"`
}

// GetHeader 获取 header 值，如果是数组则随机选择一个
// 返回 (value, exists, shouldRemove)
func (ec *EndpointConfig) GetHeader(key string) (string, bool, bool) {
	if ec.Headers == nil {
		return "", false, false
	}

	value, exists := ec.Headers[key]
	if !exists {
		return "", false, false
	}

	// 如果是 nil，表示要移除这个 header
	if value == nil {
		return "", true, true
	}

	// 如果是字符串，直接返回
	if strValue, ok := value.(string); ok {
		return strValue, true, false
	}

	// 如果是数组，随机选择一个
	if arrValue, ok := value.([]interface{}); ok && len(arrValue) > 0 {
		randomIndex := rand.Intn(len(arrValue))
		if strValue, ok := arrValue[randomIndex].(string); ok {
			if strings.EqualFold(key, "Authorization") {
				log.Printf("[RANDOM AUTH] Selected Authorization [%d/%d]: %s", randomIndex+1, len(arrValue), maskToken(strValue))
			}
			return strValue, true, false
		}
	}

	// 如果是字符串数组（从 JSON 解析来的）
	if arrValue, ok := value.([]string); ok && len(arrValue) > 0 {
		randomIndex := rand.Intn(len(arrValue))
		if strings.EqualFold(key, "Authorization") {
			log.Printf("[RANDOM AUTH] Selected Authorization [%d/%d]: %s", randomIndex+1, len(arrValue), maskToken(arrValue[randomIndex]))
		}
		return arrValue[randomIndex], true, false
	}

	return "", false, false
}

// GetAllHeaders 获取所有 headers，Authorization 会随机选择
// 返回 (headers, headersToRemove)
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

// GetQueryString 获取要修改的查询参数
// 返回 (params, paramsToRemove)
func (ec *EndpointConfig) GetQueryString() (map[string]string, []string) {
	result := make(map[string]string)
	toRemove := make([]string, 0)

	if ec.QueryString == nil {
		return result, toRemove
	}

	for key, value := range ec.QueryString {
		// 如果是 nil，表示要移除这个参数
		if value == nil {
			toRemove = append(toRemove, key)
			continue
		}

		// 如果是字符串，添加到结果中
		if strValue, ok := value.(string); ok {
			result[key] = strValue
		}
	}

	return result, toRemove
}

// MatchesMethod 检查请求方法是否匹配配置
func (ec *EndpointConfig) MatchesMethod(requestMethod string) bool {
	// 如果没有配置 method，匹配所有请求方法
	if ec.Method == nil {
		return true
	}

	// 如果是字符串，直接比较
	if strMethod, ok := ec.Method.(string); ok {
		return strings.EqualFold(strMethod, requestMethod)
	}

	// 如果是数组，检查是否在数组中
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

	// 如果是字符串数组（从 JSON 解析来的）
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

// maskToken 遮蔽 token 的部分内容用于日志输出
func maskToken(token string) string {
	if len(token) <= 20 {
		return token[:min(5, len(token))] + "***"
	}
	return token[:10] + "***" + token[len(token)-5:]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type Mapping struct {
	From   interface{} `json:"from"`         // 可以是字符串或 EndpointConfig 对象
	To     interface{} `json:"to,omitempty"` // 可以是字符串或 EndpointConfig 对象
	Local  string      `json:"local,omitempty"`
	Servers interface{} `json:"servers,omitempty"` // string or []string
	Cc     []string    `json:"cc,omitempty"`
	Proxy    interface{} `json:"proxy,omitempty"` // string or []string, 引用 proxies 的 key
	Endpoint interface{} `json:"endpoint,omitempty"`
	Tunnel   interface{} `json:"tunnel,omitempty"`
	P12      string      `json:"p12,omitempty"` // 引用 p12s 的 key
	Auth     *RuleAuth   `json:"auth,omitempty"`
	Dump     string      `json:"dump,omitempty"`
	ConnectionPolicies

	// 解析后的内部字段
	fromConfig    *EndpointConfig
	toConfig      *EndpointConfig
	serverNames   []string
	proxyNames    []string
	endpointNames []string
	tunnelNames   []string
	resolvedProxy *ProxyManager
}

type RuleAuth struct {
	Users  []string `json:"users,omitempty"`
	Groups []string `json:"groups,omitempty"`
}

type ListenConfig struct {
	Port     int         `json:"port"`
	Cert     interface{} `json:"cert,omitempty"` // string ("auto") or CertFiles
	Key      string      `json:"key,omitempty"`
	Auth     *ServerAuth `json:"auth,omitempty"`
	Dump     string      `json:"dump,omitempty"`
	Endpoint interface{} `json:"endpoint,omitempty"` // string or []string
	Tunnel   interface{} `json:"tunnel,omitempty"`   // string or []string
	ConnectionPolicies
}

type ServerAuth struct {
	Users  []string `json:"users,omitempty"`
	Groups []string `json:"groups,omitempty"`
}

type CertFiles struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

func (lc *ListenConfig) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as an int first
	var port int
	if err := json.Unmarshal(data, &port); err == nil {
		lc.Port = port
		return nil
	}

	// If that fails, try to unmarshal as an object
	type Alias ListenConfig
	var obj Alias
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	*lc = ListenConfig(obj)

	// Check the type of Cert
	if certStr, ok := obj.Cert.(string); ok {
		if certStr != "auto" {
			return errors.New("cert string must be 'auto'")
		}
		lc.Cert = "auto"
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
		return errors.New("invalid type for 'cert' field")
	}

	return nil
}

// GetFromURL 获取 from 的 URL 字符串
func (m *Mapping) GetFromURL() string {
	if m.fromConfig != nil {
		return m.fromConfig.URL
	}
	if str, ok := m.From.(string); ok {
		return str
	}
	return ""
}

// GetToURL 获取 to 的 URL 字符串
func (m *Mapping) GetToURL() string {
	if m.toConfig != nil {
		return m.toConfig.URL
	}
	if str, ok := m.To.(string); ok {
		return str
	}
	return ""
}

// GetFromConfig 获取 from 的完整配置
func (m *Mapping) GetFromConfig() *EndpointConfig {
	return m.fromConfig
}

// GetToConfig 获取 to 的完整配置
func (m *Mapping) GetToConfig() *EndpointConfig {
	return m.toConfig
}

// parseEndpointConfig 解析 interface{} 为 EndpointConfig
func parseEndpointConfig(data interface{}) (*EndpointConfig, error) {
	if data == nil {
		return nil, nil
	}

	// 如果是字符串，创建简单配置
	if str, ok := data.(string); ok {
		str = strings.TrimSpace(str)
		str = strings.Trim(str, "`")
		return &EndpointConfig{
			URL: str,
		}, nil
	}

	// 如果是 map，解析为完整配置
	if mapData, ok := data.(map[string]interface{}); ok {
		config := &EndpointConfig{}

		if url, ok := mapData["url"].(string); ok {
			config.URL = strings.TrimSpace(strings.Trim(url, "`"))
		}

		if headers, ok := mapData["headers"].(map[string]interface{}); ok {
			config.Headers = headers
		}

		if querystring, ok := mapData["querystring"].(map[string]interface{}); ok {
			config.QueryString = querystring
		}

		if proxy, ok := mapData["proxy"]; ok {
			config.Proxy = proxy
		}

		if match, ok := mapData["match"].(string); ok {
			config.Match = match
		}

		if replace, ok := mapData["replace"].(map[string]interface{}); ok {
			config.Replace = make(map[string]string)
			for k, v := range replace {
				if vStr, ok := v.(string); ok {
					config.Replace[k] = vStr
				}
			}
		}

		return config, nil
	}

	return nil, errors.New("invalid endpoint config format")
}

func parseStringOrArray(data interface{}) []string {
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

func LoadConfig(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var config Config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}

	if err := processConfig(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

func processConfig(config *Config) error {
	// 解析并验证每个 mapping
	validMappings := make([]Mapping, 0, len(config.Mappings))
	for i := range config.Mappings {
		mapping := &config.Mappings[i]

		// 验证 from 字段（必须存在）
		if mapping.From == nil {
			log.Printf("Warning: mapping %d skipped - 'from' field is required", i+1)
			continue
		}

		fromConfig, err := parseEndpointConfig(mapping.From)
		if err != nil {
			log.Printf("Warning: mapping %d skipped - failed to parse 'from': %v", i+1, err)
			continue
		}
		if fromConfig == nil || fromConfig.URL == "" {
			log.Printf("Warning: mapping %d skipped - 'from' URL is empty", i+1)
			continue
		}
		mapping.fromConfig = fromConfig

		// 验证 to 和 local 至少存在一个
		hasTo := mapping.To != nil
		hasLocal := mapping.Local != ""

		if !hasTo && !hasLocal {
			log.Printf("Warning: mapping %d skipped - either 'to' or 'local' field is required", i+1)
			continue
		}

		// 解析 to 配置（如果存在）
		if hasTo {
			toConfig, err := parseEndpointConfig(mapping.To)
			if err != nil {
				log.Printf("Warning: mapping %d skipped - failed to parse 'to': %v", i+1, err)
				continue
			}
			if toConfig == nil || toConfig.URL == "" {
				log.Printf("Warning: mapping %d skipped - 'to' URL is empty", i+1)
				continue
			}
			mapping.toConfig = toConfig
		}

		// 解析 server names
		mapping.serverNames = parseStringOrArray(mapping.Servers)
		if len(mapping.serverNames) == 0 {
			// If no servers are specified, this mapping applies to ALL servers.
			// This is a common use case for global rules.
			// We will populate serverNames with all available server names.
			for name := range config.Servers {
				mapping.serverNames = append(mapping.serverNames, name)
			}
			if len(mapping.serverNames) == 0 {
				log.Printf("Warning: mapping %d skipped - 'servers' is not specified and no servers are defined", i+1)
				continue
			}
		} else {
			// 验证 server names 是否存在
			for _, name := range mapping.serverNames {
				if _, ok := config.Servers[name]; !ok {
					log.Printf("Warning: mapping %d skipped - server name '%s' not found in servers config", i+1, name)
					continue
				}
			}
		}

		// 解析 proxy names
		proxySource := mapping.Proxy
		if fromConfig.Proxy != nil {
			proxySource = fromConfig.Proxy
		}
		mapping.proxyNames = parseStringOrArray(proxySource)

		// 解析并初始化代理
		if len(mapping.proxyNames) > 0 {
			var allProxies []string
			for _, name := range mapping.proxyNames {
				if proxyConfig, ok := config.Proxies[name]; ok {
					proxies := parseStringOrArray(proxyConfig)
					allProxies = append(allProxies, proxies...)
				} else {
					// 也可能是直接的 proxy url
					allProxies = append(allProxies, name)
				}
			}
			if len(allProxies) > 0 {
				mapping.resolvedProxy = NewProxyManager(allProxies)
			}
		}

		// 解析 endpoint names
		mapping.endpointNames = parseStringOrArray(mapping.Endpoint)

		// 解析 tunnel names
		mapping.tunnelNames = parseStringOrArray(mapping.Tunnel)

		// 验证通过，添加到有效列表
		validMappings = append(validMappings, *mapping)
	}

	config.Mappings = validMappings
	log.Printf("Loaded %d valid mapping rules (filtered from %d total)", len(validMappings), len(config.Mappings))
	return nil
}

func (c *Config) Reload(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	var newConfig Config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&newConfig); err != nil {
		return err
	}

	if err := processConfig(&newConfig); err != nil {
		return err
	}

	c.mu.Lock()
	c.Servers = newConfig.Servers
	c.Proxies = newConfig.Proxies
	c.Mappings = newConfig.Mappings
	c.Auth = newConfig.Auth
	c.mu.Unlock()

	log.Printf("Configuration reloaded: %d valid mapping rules", len(newConfig.Mappings))
	for _, mapping := range c.Mappings {
		log.Printf("  Rule: %s -> %s on servers: %v", mapping.GetFromURL(), mapping.GetToURL(), mapping.serverNames)
	}

	return nil
}

func (c *Config) GetMappings() []Mapping {
	c.mu.RLock()
	defer c.mu.RUnlock()

	mappings := make([]Mapping, len(c.Mappings))
	copy(mappings, c.Mappings)
	return mappings
}

// FinalPolicies represents the resolved, non-pointer values for connection policies.
type FinalPolicies struct {
	Timeout     time.Duration
	IdleTimeout time.Duration
	MaxThread   int
	Quality     float64
}

// ResolvePolicies determines the final connection policies based on the hierarchy:
// user > group > mapping > server.
func (c *Config) ResolvePolicies(server *ListenConfig, mapping *Mapping, user *User) FinalPolicies {
	// Set default values
	final := FinalPolicies{
		Timeout:     10 * time.Minute,
		IdleTimeout: 100 * time.Second,
		MaxThread:   0, // 0 means no limit
		Quality:     1.0,
	}

	// Layer 1: Server policies
	applyPolicy(&final, &server.ConnectionPolicies)

	// Layer 2: Mapping policies
	applyPolicy(&final, &mapping.ConnectionPolicies)

	// Layer 3: Group policies (if user is present)
	if user != nil && c.Auth != nil && c.Auth.Groups != nil {
		for _, groupName := range user.Groups {
			if group, ok := c.Auth.Groups[groupName]; ok {
				applyPolicy(&final, &group.ConnectionPolicies)
			}
		}
	}

	// Layer 4: User policies (highest priority)
	if user != nil {
		applyPolicy(&final, &user.ConnectionPolicies)
	}

	return final
}

// applyPolicy updates the final policies from a specific policy level.
func applyPolicy(final *FinalPolicies, specific *ConnectionPolicies) {
	if specific.Timeout != nil {
		final.Timeout = time.Duration(*specific.Timeout) * time.Second
	}
	if specific.IdleTimeout != nil {
		final.IdleTimeout = time.Duration(*specific.IdleTimeout) * time.Second
	}
	if specific.MaxThread != nil {
		final.MaxThread = *specific.MaxThread
	}
	if specific.Quality != nil {
		final.Quality = *specific.Quality
	}
}