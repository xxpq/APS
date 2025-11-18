package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func init() {
	// 初始化随机数生成器
	// rand.Seed(time.Now().UnixNano())
}

type Config struct {
	Servers   map[string]*ListenConfig `json:"servers"`
	Proxies   map[string]*ProxyConfig  `json:"proxies,omitempty"`
	Tunnels   map[string]*TunnelConfig `json:"tunnels,omitempty"`
	Auth      *AuthConfig              `json:"auth,omitempty"`
	P12s      map[string]*P12Config    `json:"p12s,omitempty"`
	Scripting *ScriptingConfig         `json:"scripting,omitempty"`
	Mappings  []Mapping                `json:"mappings"`
	mu        sync.RWMutex
}

type DataStore struct {
	QuotaUsage map[string]*QuotaUsageData `json:"quotaUsage,omitempty"`
	mu         sync.Mutex
}

type QuotaUsageData struct {
	TrafficUsed  int64 `json:"trafficUsed"`
	RequestsUsed int64 `json:"requestsUsed"`
}

type ProxyConfig struct {
	URLs []string `json:"urls"`
	ConnectionPolicies
	TrafficPolicies
}

func (pc *ProxyConfig) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as a string first
	var singleURL string
	if err := json.Unmarshal(data, &singleURL); err == nil {
		pc.URLs = []string{singleURL}
		return nil
	}

	// Try to unmarshal as an array of strings
	var urls []string
	if err := json.Unmarshal(data, &urls); err == nil {
		pc.URLs = urls
		return nil
	}

	// If that fails, try to unmarshal as a full object
	type Alias ProxyConfig
	var obj Alias
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	*pc = ProxyConfig(obj)
	return nil
}

type TunnelConfig struct {
	Servers  []string  `json:"servers"`
	Password string    `json:"password,omitempty"` // AES key for encryption
	Auth     *RuleAuth `json:"auth,omitempty"`
	TrafficPolicies
}

type ScriptingConfig struct {
	PythonPath string `json:"pythonPath,omitempty"`
	NodePath   string `json:"nodePath,omitempty"`
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

// TrafficPolicies defines policies for rate limiting and traffic quotas.
type TrafficPolicies struct {
	RateLimit    *string `json:"rateLimit,omitempty"`    // e.g., "1mbps", "500kbps"
	TrafficQuota *string `json:"trafficQuota,omitempty"` // e.g., "10gb", "500mb"
	RequestQuota *int64  `json:"requestQuota,omitempty"`
}

type User struct {
	Password string      `json:"password"`
	Admin    bool        `json:"admin,omitempty"`
	Token    string      `json:"token,omitempty"`
	Groups   []string    `json:"groups,omitempty"`
	Dump     string      `json:"dump,omitempty"`
	Endpoint interface{} `json:"endpoint,omitempty"` // string or []string
	Tunnel   interface{} `json:"tunnel,omitempty"`   // string or []string
	ConnectionPolicies
	TrafficPolicies
}

type Group struct {
	Users    []string    `json:"users"`
	Dump     string      `json:"dump,omitempty"`
	Endpoint interface{} `json:"endpoint,omitempty"` // string or []string
	Tunnel   interface{} `json:"tunnel,omitempty"`   // string or []string
	ConnectionPolicies
	TrafficPolicies
}

// GRPCConfig 定义了用于匹配和修改 gRPC 请求的规则
type GRPCConfig struct {
	Service    string                 `json:"service,omitempty"`
	Method     string                 `json:"method,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"` // 支持 string 或 []string，null 表示移除
	RestToGrpc *RestToGrpcConfig      `json:"rest_to_grpc,omitempty"`
}

// RestToGrpcConfig 定义了将 RESTful 请求转换为 gRPC 调用的规则
type RestToGrpcConfig struct {
	// RequestBodyMapping 定义了如何从 HTTP 请求构建 gRPC 请求消息。
	// key 是 gRPC 消息中的字段名 (e.g., "user.name")。
	// value 是从 HTTP 请求中提取数据的位置 (e.g., "json:name", "query:id", "path:user_id")。
	RequestBodyMapping map[string]string `json:"request_body_mapping,omitempty"`
}

// WebSocketMessageConfig 定义了用于匹配和修改单个 WebSocket 消息的规则
type WebSocketMessageConfig struct {
	Match   string            `json:"match,omitempty"`   // 用于匹配消息内容的正则表达式
	Replace map[string]string `json:"replace,omitempty"` // 对匹配内容进行替换
	Log     bool              `json:"log,omitempty"`     // 如果匹配，是否记录消息
	Drop    bool              `json:"drop,omitempty"`    // 如果匹配，是否丢弃消息
}

// WebSocketConfig 定义了拦截 WebSocket 流量的规则
type WebSocketConfig struct {
	InterceptClientMessages []WebSocketMessageConfig `json:"intercept_client_messages,omitempty"`
	InterceptServerMessages []WebSocketMessageConfig `json:"intercept_server_messages,omitempty"`
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
	GRPC        *GRPCConfig            `json:"grpc,omitempty"`
	WebSocket   *WebSocketConfig       `json:"websocket,omitempty"`
	Script      string                 `json:"script,omitempty"`
	IPs         interface{}            `json:"ips,omitempty"`         // 支持 string 或 []string，指定目标IP地址
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

// GetIPs 获取 IPs 配置，支持单个字符串或字符串数组
func (ec *EndpointConfig) GetIPs() []string {
	if ec.IPs == nil {
		return nil
	}
	return parseStringOrArray(ec.IPs)
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

type ViaConfig struct {
	Proxies   interface{} `json:"proxies,omitempty"`
	Tunnels   interface{} `json:"tunnels,omitempty"`
	Endpoints interface{} `json:"endpoints,omitempty"`
}

type Mapping struct {
	From    interface{} `json:"from"` // 可以是字符串或 EndpointConfig 对象
	To      interface{} `json:"to"`   // 可以是字符串或 EndpointConfig 对象
	Via     *ViaConfig  `json:"via,omitempty"`
	Servers interface{} `json:"servers,omitempty"` // string or []string
	Cc      []string    `json:"cc,omitempty"`
	P12     string      `json:"p12,omitempty"` // 引用 p12s 的 key
	Auth    *RuleAuth   `json:"auth,omitempty"`
	Dump    string      `json:"dump,omitempty"`
	ConnectionPolicies
	TrafficPolicies

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
	Port      int         `json:"port"`
	Cert      interface{} `json:"cert,omitempty"` // string ("auto") or CertFiles
	Key       string      `json:"key,omitempty"`
	Auth      *ServerAuth `json:"auth,omitempty"`
	Dump      string      `json:"dump,omitempty"`
	Endpoints interface{} `json:"endpoints,omitempty"` // string or []string
	Tunnels   interface{} `json:"tunnels,omitempty"`   // string or []string
	Public    *bool       `json:"public,omitempty"`    // true: 0.0.0.0:port, false: 127.0.0.1:port (default true)
	Panel     *bool       `json:"panel,omitempty"`     // true: register /.api & /.admin, false: do not (default false)
	ConnectionPolicies
	TrafficPolicies
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
		// Defaults when only port is provided
		t := true
		lc.Public = &t // public defaults to true
		// panel defaults to false (nil)
		return nil
	}

	// If that fails, try to unmarshal as an object
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
	// lc.Panel: nil means default false

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
		// To handle this properly, we marshal it back to JSON and then unmarshal into the struct.
		// This correctly handles all fields and their types, including nested ones like ScriptConfig.
		jsonBytes, err := json.Marshal(mapData)
		if err != nil {
			return nil, err
		}
		var config EndpointConfig
		if err := json.Unmarshal(jsonBytes, &config); err != nil {
			return nil, err
		}
		return &config, nil
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

func LoadDataStore(filename string) (*DataStore, error) {
	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Data file '%s' not found, creating a new one.", filename)
			return &DataStore{QuotaUsage: make(map[string]*QuotaUsageData)}, nil
		}
		return nil, err
	}
	defer file.Close()

	var dataStore DataStore
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&dataStore); err != nil {
		log.Printf("Error decoding data file '%s', starting with empty data: %v", filename, err)
		// If the file is corrupted or empty, start with a fresh data store
		return &DataStore{QuotaUsage: make(map[string]*QuotaUsageData)}, nil
	}

	if dataStore.QuotaUsage == nil {
		dataStore.QuotaUsage = make(map[string]*QuotaUsageData)
	}

	return &dataStore, nil
}

func SaveDataStore(dataStore *DataStore, filename string) error {
	dataStore.mu.Lock()
	defer dataStore.mu.Unlock()

	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(dataStore)
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

		// 验证 to 字段（必须存在）
		if mapping.To == nil {
			log.Printf("Warning: mapping %d skipped - 'to' field is required", i+1)
			continue
		}

		// 解析 to 配置
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

		if mapping.Via != nil {
			// 解析 proxy names from via
			proxySource := mapping.Via.Proxies
			if fromConfig.Proxy != nil {
				proxySource = fromConfig.Proxy // from中的proxy优先级更高
			}
			mapping.proxyNames = parseStringOrArray(proxySource)

			// 解析并初始化代理
			if len(mapping.proxyNames) > 0 {
				var allProxies []string
				for _, name := range mapping.proxyNames {
					if proxyConfig, ok := config.Proxies[name]; ok {
						allProxies = append(allProxies, proxyConfig.URLs...)
					} else {
						// 也可能是直接的 proxy url
						allProxies = append(allProxies, name)
					}
				}
				if len(allProxies) > 0 {
					mapping.resolvedProxy = NewProxyManager(allProxies)
				}
			}

			// 解析 endpoint names from via
			mapping.endpointNames = parseStringOrArray(mapping.Via.Endpoints)

			// 解析 tunnel names from via
			mapping.tunnelNames = parseStringOrArray(mapping.Via.Tunnels)
		}

		// 验证通过，添加到有效列表
		validMappings = append(validMappings, *mapping)
	}

	config.Mappings = validMappings
	log.Printf("Loaded %d valid mapping rules (filtered from %d total)", len(validMappings), len(config.Mappings))
	return nil
}

func (c *Config) Reload(filename string) (map[string]*ListenConfig, error) {
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
	oldServers := c.Servers
	c.Servers = newConfig.Servers
	c.Proxies = newConfig.Proxies
	c.Tunnels = newConfig.Tunnels
	c.P12s = newConfig.P12s
	c.Scripting = newConfig.Scripting
	c.Mappings = newConfig.Mappings
	c.Auth = newConfig.Auth
	c.mu.Unlock()

	log.Printf("Configuration reloaded: %d valid mapping rules", len(newConfig.Mappings))
	for _, mapping := range c.Mappings {
		log.Printf("  Rule: %s -> %s on servers: %v", mapping.GetFromURL(), mapping.GetToURL(), mapping.serverNames)
	}

	return oldServers, nil
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

// ResolvePolicies determines the final connection policies by taking the minimum value from all applicable levels.
func (c *Config) ResolvePolicies(server *ListenConfig, mapping *Mapping, user *User, username string) FinalPolicies {
	// Set default values to maximums, so any defined value will be smaller
	final := FinalPolicies{
		Timeout:     10 * time.Minute,
		IdleTimeout: 100 * time.Second,
		MaxThread:   math.MaxInt32,
		Quality:     1.0,
	}

	// Create a list of all applicable policies
	policies := []*ConnectionPolicies{
		&server.ConnectionPolicies,
	}
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

	// Apply the "minimum wins" logic
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

	// If no maxThread was set, reset to 0 (unlimited)
	if final.MaxThread == math.MaxInt32 {
		final.MaxThread = 0
	}

	return final
}

// ResolveTrafficPolicies gathers all applicable traffic policies.
// It returns the lowest rate limit, a map of traffic quotas, and a map of request quotas.
func (c *Config) ResolveTrafficPolicies(server *ListenConfig, mapping *Mapping, tunnel *TunnelConfig, proxy *ProxyConfig, user *User, username string) (string, map[string]string, map[string]int64, error) {
	trafficQuotas := make(map[string]string)
	requestQuotas := make(map[string]int64)
	var rateLimits []string

	// Gather policies from all levels
	policies := []TrafficPolicies{}
	sourceKeys := []string{}

	if server != nil {
		policies = append(policies, server.TrafficPolicies)
		// Find server name for key
		for name, s := range c.Servers {
			if s == server {
				sourceKeys = append(sourceKeys, fmt.Sprintf("server:%s", name))
				break
			}
		}
	}
	if mapping != nil {
		policies = append(policies, mapping.TrafficPolicies)
		sourceKeys = append(sourceKeys, fmt.Sprintf("mapping:%s", mapping.GetFromURL()))
	}
	if tunnel != nil {
		policies = append(policies, tunnel.TrafficPolicies)
		// Find tunnel name for key
		for name, t := range c.Tunnels {
			if t == tunnel {
				sourceKeys = append(sourceKeys, fmt.Sprintf("tunnel:%s", name))
				break
			}
		}
	}
	if proxy != nil {
		policies = append(policies, proxy.TrafficPolicies)
		// Find proxy name for key
		for name, p := range c.Proxies {
			if p == proxy {
				sourceKeys = append(sourceKeys, fmt.Sprintf("proxy:%s", name))
				break
			}
		}
	}
	if user != nil {
		policies = append(policies, user.TrafficPolicies)
		sourceKeys = append(sourceKeys, fmt.Sprintf("user:%s", username))
		if c.Auth != nil && c.Auth.Groups != nil {
			for _, groupName := range user.Groups {
				if group, ok := c.Auth.Groups[groupName]; ok {
					policies = append(policies, group.TrafficPolicies)
					sourceKeys = append(sourceKeys, fmt.Sprintf("group:%s", groupName))
				}
			}
		}
	}

	// Process gathered policies
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

	// Find the minimum rate limit
	minRateLimit, err := minRate(rateLimits)
	if err != nil {
		return "", nil, nil, fmt.Errorf("failed to determine minimum rate limit: %w", err)
	}

	return minRateLimit, trafficQuotas, requestQuotas, nil
}

// parseRateLimit converts a rate string (e.g., "10mbps") to bytes per second.
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
		return 0, fmt.Errorf("invalid rate limit unit, use kbps, mbps, or gbps")
	}

	val, err := strconv.ParseFloat(rateStr, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid rate limit value: %w", err)
	}

	return val * multiplier, nil
}

// minRate finds the minimum rate from a slice of rate strings.
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
