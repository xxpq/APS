package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/pkcs12"
)

// 对象池 - 用于高并发场景下复用对象，减少 GC 压力
var (
	// bufferPool 复用 bytes.Buffer
	bufferPool = sync.Pool{
		New: func() interface{} {
			return new(bytes.Buffer)
		},
	}

	// byteSlicePool 复用 32KB byte 切片用于 I/O 操作
	byteSlicePool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 32*1024)
			return &b
		},
	}

	// counterWriterPool 复用 ByteCounterWriter
	counterWriterPool = sync.Pool{
		New: func() interface{} {
			return &ByteCounterWriter{}
		},
	}
)

// getBuffer 从池中获取 buffer
func getBuffer() *bytes.Buffer {
	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	return buf
}

// putBuffer 归还 buffer 到池中（限制大小避免内存泄漏）
func putBuffer(buf *bytes.Buffer) {
	if buf.Cap() <= 1024*1024 { // 只回收 <= 1MB 的 buffer
		bufferPool.Put(buf)
	}
}

// getByteSlice 从池中获取 byte 切片
func getByteSlice() *[]byte {
	return byteSlicePool.Get().(*[]byte)
}

// putByteSlice 归还 byte 切片到池中
func putByteSlice(b *[]byte) {
	byteSlicePool.Put(b)
}

// getCounterWriter 从池中获取 ByteCounterWriter
func getCounterWriter(w io.Writer) *ByteCounterWriter {
	cw := counterWriterPool.Get().(*ByteCounterWriter)
	cw.Writer = w
	cw.BytesWritten = 0
	return cw
}

// putCounterWriter 归还 ByteCounterWriter 到池中
func putCounterWriter(cw *ByteCounterWriter) {
	cw.Writer = nil
	counterWriterPool.Put(cw)
}

func (p *MapRemoteProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Start timing and basic stats
	startTime := time.Now()
	p.stats.IncTotalRequests()
	p.stats.IncActiveConnections()
	defer p.stats.DecActiveConnections()

	// Prepare variables for stats recording
	var (
		bytesSent uint64
		bytesRecv uint64
		isError   bool
		ruleKey   string
		userKey   string
		tunnelKey string
		proxyKey  string
	)

	// Defer the consolidated stats recording
	defer func() {
		responseTime := time.Since(startTime)
		p.stats.AddBytesSent(bytesSent)
		p.stats.AddBytesRecv(bytesRecv)
		p.stats.Record(RecordData{
			RuleKey:      ruleKey,
			UserKey:      userKey,
			ServerKey:    p.serverName,
			TunnelKey:    tunnelKey,
			ProxyKey:     proxyKey,
			BytesSent:    bytesSent,
			BytesRecv:    bytesRecv,
			ResponseTime: responseTime,
			IsError:      isError,
		})
	}()

	// Check if it's a gRPC or WebSocket request
	if strings.ToLower(r.Header.Get("Upgrade")) == "websocket" && strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		p.handleWebSocket(w, r)
		return
	}

	// 静态文件缓存检查
	fullURL := p.buildOriginalURL(r)
	if p.staticCache != nil && p.staticCache.IsCacheable(r.URL.Path) {
		if cachedEntry, ok := p.staticCache.Get(fullURL); ok {
			// 缓存命中，直接返回缓存内容（包含原始响应头）
			for key, values := range cachedEntry.Headers {
				// 跳过这些头，我们会自己设置
				lowerKey := strings.ToLower(key)
				if lowerKey == "content-encoding" || lowerKey == "transfer-encoding" ||
					lowerKey == "content-length" || lowerKey == "cache-control" ||
					lowerKey == "etag" || lowerKey == "last-modified" {
					continue
				}
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}

			// 设置缓存相关头
			w.Header().Set("X-Cache", "HIT")
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(cachedEntry.Body)))

			// 设置浏览器缓存头（Cache-Control: 1天）
			w.Header().Set("Cache-Control", "public, max-age=86400")

			// 设置 ETag 和 Last-Modified
			if cachedEntry.ETag != "" {
				w.Header().Set("ETag", cachedEntry.ETag)
			}
			if cachedEntry.LastModified != "" {
				w.Header().Set("Last-Modified", cachedEntry.LastModified)
			}

			// 如果是压缩内容，设置 Content-Encoding: br
			if cachedEntry.IsCompressed {
				w.Header().Set("Content-Encoding", "br")
			}

			w.WriteHeader(cachedEntry.StatusCode)
			w.Write(cachedEntry.Body)
			bytesSent = uint64(len(cachedEntry.Body))
			log.Printf("[CACHE] HIT: %s (%d bytes, compressed=%v)", fullURL, len(cachedEntry.Body), cachedEntry.IsCompressed)
			return
		}
	}

	targetURL, matched, mapping, matchedFromURL := p.mapRequest(r)
	originalURL := p.buildOriginalURL(r)

	// 获取server配置
	serverConfig := p.config.Servers[p.serverName]

	// 检查server级别的Endpoints/Tunnels配置
	var serverEndpointNames, serverTunnelNames []string
	if serverConfig != nil {
		serverEndpointNames = parseStringOrArray(serverConfig.Endpoints)
		serverTunnelNames = parseStringOrArray(serverConfig.Tunnels)
	}

	authorized, user, username := p.checkAuth(r, mapping)
	if !authorized {
		isError = true
		if r.Method == http.MethodConnect || r.Header.Get("Proxy-Authorization") == "" {
			w.Header().Set("Proxy-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
		} else {
			http.Error(w, "Forbidden by rule", http.StatusForbidden)
		}
		return
	}
	if user != nil {
		userKey = username
	}

	// Check firewall rules (server firewall takes priority over mapping firewall)
	var firewallRule *FirewallRule
	if serverConfig != nil && serverConfig.Firewall != "" {
		firewallRule = GetFirewallRule(p.config, serverConfig.Firewall)
		if firewallRule != nil {
			DebugLog("[FIREWALL] Using server-level firewall rule '%s'", serverConfig.Firewall)
		}
	}
	if firewallRule == nil && mapping != nil && mapping.Firewall != "" {
		firewallRule = GetFirewallRule(p.config, mapping.Firewall)
		if firewallRule != nil {
			DebugLog("[FIREWALL] Using mapping-level firewall rule '%s'", mapping.Firewall)
		}
	}

	// Check if client IP is allowed
	clientIP := getClientIP(r)
	if !CheckFirewall(clientIP, firewallRule) {
		isError = true
		log.Printf("[FIREWALL] Request from %s blocked by firewall", clientIP)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// 获取用户和组级别的Endpoints/Tunnels配置（最高优先级）
	var userEndpointNames, userTunnelNames []string

	if user != nil {
		// 用户级别配置
		userEndpointNames = parseStringOrArray(user.Endpoint)
		userTunnelNames = parseStringOrArray(user.Tunnel)

		// 组级别配置（只有用户级别没有配置时，才使用组级别配置）
		if len(userEndpointNames) == 0 && len(userTunnelNames) == 0 {
			if p.config.Auth != nil && p.config.Auth.Groups != nil {
				for _, groupName := range user.Groups {
					if group, ok := p.config.Auth.Groups[groupName]; ok {
						groupEndpoints := parseStringOrArray(group.Endpoint)
						groupTunnels := parseStringOrArray(group.Tunnel)
						if len(groupEndpoints) > 0 || len(groupTunnels) > 0 {
							userEndpointNames = groupEndpoints
							userTunnelNames = groupTunnels
							break // 使用第一个有配置的组
						}
					}
				}
			}
		}
	}

	// 只有在未命中mapping且没有任何级别（user/group/server/mapping）的Endpoints/Tunnels配置时，才返回404
	hasAnyConfig := len(userEndpointNames) > 0 || len(userTunnelNames) > 0 ||
		len(serverEndpointNames) > 0 || len(serverTunnelNames) > 0 ||
		(mapping != nil && (len(mapping.endpointNames) > 0 || len(mapping.tunnelNames) > 0))

	if !matched && !hasAnyConfig && !r.URL.IsAbs() {
		isError = true
		http.NotFound(w, r)
		log.Printf("[%s][%s] %s (NO MAPPING - 404 Not Found)", clientIP, r.Method, originalURL)
		return
	}

	// Populate keys for stats
	if mapping != nil {
		ruleKey = matchedFromURL
		if len(mapping.tunnelNames) > 0 {
			tunnelKey = mapping.tunnelNames[0]
		}
		if len(mapping.proxyNames) > 0 {
			proxyKey = mapping.proxyNames[0]
		}
	}

	// Check tunnel access permissions
	if tunnelKey != "" {
		if tunnelConfig, ok := p.config.Tunnels[tunnelKey]; ok && tunnelConfig.Auth != nil {
			if !p.checkTunnelAccess(user, username, tunnelConfig.Auth) {
				isError = true
				log.Printf("[TUNNEL] User '%s' is not authorized for tunnel '%s'", username, tunnelKey)
				http.Error(w, "Forbidden by tunnel access rule", http.StatusForbidden)
				return
			}
		}
	}

	policies := p.config.ResolvePolicies(serverConfig, mapping, user, username)

	var tunnelConfig *TunnelConfig
	if tunnelKey != "" {
		tunnelConfig = p.config.Tunnels[tunnelKey]
	}
	var proxyConfig *ProxyConfig
	if proxyKey != "" {
		proxyConfig = p.config.Proxies[proxyKey]
	}
	rateLimit, quotas, requestQuotas, err := p.config.ResolveTrafficPolicies(serverConfig, mapping, tunnelConfig, proxyConfig, user, username)
	if err != nil {
		isError = true
		log.Printf("[TRAFFIC] Error resolving traffic policies: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	for source, quotaLimit := range quotas {
		var initialUsage int64
		p.dataStore.mu.Lock()
		if usage, ok := p.dataStore.QuotaUsage[source]; ok {
			initialUsage = usage.TrafficUsed
		}
		p.dataStore.mu.Unlock()
		quota, err := p.trafficShaper.GetTrafficQuota(source, quotaLimit, initialUsage)
		if err != nil {
			log.Printf("[TRAFFIC] Error creating quota for %s: %v", source, err)
			continue
		}
		if quota.Exceeded {
			isError = true
			errMsg := fmt.Sprintf("Traffic quota exceeded for %s", source)
			http.Error(w, errMsg, http.StatusTooManyRequests)
			return
		}
	}

	for source, quotaLimit := range requestQuotas {
		var initialUsage int64
		p.dataStore.mu.Lock()
		if usage, ok := p.dataStore.QuotaUsage[source]; ok {
			initialUsage = usage.RequestsUsed
		}
		p.dataStore.mu.Unlock()
		quota, err := p.trafficShaper.GetRequestQuota(source, quotaLimit, initialUsage)
		if err != nil {
			log.Printf("[TRAFFIC] Error creating request quota for %s: %v", source, err)
			continue
		}
		if !quota.AddRequest() {
			isError = true
			errMsg := fmt.Sprintf("Request quota exceeded for %s", source)
			http.Error(w, errMsg, http.StatusTooManyRequests)
			return
		}
	}

	limiterKey := "global"
	if user != nil {
		limiterKey = username
	} else {
		limiterKey = getClientIP(r)
	}
	limiter, err := p.trafficShaper.GetLimiter(limiterKey, rateLimit)
	if err != nil {
		log.Printf("[TRAFFIC] Error creating limiter: %v", err)
	}

	trackingQuota, _ := p.trafficShaper.GetTrafficQuota(limiterKey, "", 0)

	if policies.MaxThread > 0 {
		select {
		case p.concurrencyLimiter <- struct{}{}:
			defer func() { <-p.concurrencyLimiter }()
		default:
			isError = true
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
	}

	if matched {
		if strings.HasPrefix(targetURL, "file://") {
			log.Printf("[%s][%s] %s -> [LOCAL] %s", clientIP, r.Method, originalURL, targetURL)
			p.serveFile(w, r, mapping)
			return
		}
		log.Printf("[%s][%s] %s -> %s (MAPPED)", clientIP, r.Method, originalURL, targetURL)
	} else if len(userEndpointNames) > 0 || len(userTunnelNames) > 0 {
		log.Printf("[%s][%s] %s (NO MAPPING - FORWARDED TO USER-LEVEL ENDPOINT/TUNNEL)", clientIP, r.Method, originalURL)
	} else if len(serverEndpointNames) > 0 || len(serverTunnelNames) > 0 {
		log.Printf("[%s][%s] %s (NO MAPPING - FORWARDED TO SERVER-LEVEL ENDPOINT/TUNNEL)", clientIP, r.Method, originalURL)
	} else if mapping != nil && (len(mapping.endpointNames) > 0 || len(mapping.tunnelNames) > 0) {
		log.Printf("[%s][%s] %s (NO MAPPING - FORWARDED TO MAPPING-LEVEL ENDPOINT/TUNNEL)", clientIP, r.Method, originalURL)
	} else {
		log.Printf("[%s][%s] %s (NO MAPPING)", clientIP, r.Method, originalURL)
	}

	var requestBody io.Reader = r.Body
	if matched && mapping != nil {
		originalBody, err := io.ReadAll(r.Body)
		if err != nil {
			isError = true
			http.Error(w, "Failed to read request body", http.StatusInternalServerError)
			return
		}
		r.Body = io.NopCloser(bytes.NewBuffer(originalBody))
		modifiedBody, err := p.modifyRequestBody(r, mapping)
		if err != nil {
			isError = true
			http.Error(w, "Failed to modify request body", http.StatusInternalServerError)
			log.Printf("Error modifying request body: %v", err)
			return
		}
		requestBody = bytes.NewBuffer(modifiedBody)
	}

	// 处理IPS参数：如果mapping配置了ips，则随机选择一个IP并替换目标地址
	var actualTargetURL = targetURL
	var selectedIP string
	if matched && mapping != nil {
		toConfig := mapping.GetToConfig()
		if toConfig != nil {
			ips := toConfig.GetIPs()
			if len(ips) > 0 {
				selectedIP = pickRandomIP(ips)
				if selectedIP != "" {
					newURL, err := replaceHostWithIP(targetURL, selectedIP)
					if err != nil {
						log.Printf("[IPS] Error replacing host with IP: %v", err)
					} else {
						actualTargetURL = newURL
						log.Printf("[IPS] Selected IP %s for target %s, new URL: %s", selectedIP, targetURL, actualTargetURL)
					}
				}
			}
		}
	}

	proxyReq, err := http.NewRequest(r.Method, actualTargetURL, requestBody)
	if err != nil {
		isError = true
		http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
		log.Printf("Error creating request: %v", err)
		return
	}

	if matched && mapping != nil {
		fromConfig := mapping.GetFromConfig()
		if fromConfig != nil && fromConfig.Script != "" {
			proxyReq, err = p.scriptRunner.RunOnRequest(proxyReq, fromConfig.Script)
			if err != nil {
				log.Printf("[SCRIPT] Error running onRequest script %s: %v", fromConfig.Script, err)
			}
		}
	}

	if mapping != nil {
		ctx := context.WithValue(r.Context(), "mapping", mapping)
		proxyReq = proxyReq.WithContext(ctx)
	}

	copyHeaders(proxyReq.Header, r.Header)
	// Correctly set the Host header. When using IP substitution, the request's Host
	// header must contain the original domain name for the target server to identify
	// the correct virtual host.

	// The original destination URL is in `targetURL`. We need to parse the host from it.
	// A schemeless URL (e.g., "example.com") won't be parsed correctly by url.Parse
	// to extract a host. Prepending "//" makes it a valid scheme-relative URL.
	hostParseURL := targetURL
	if !strings.Contains(hostParseURL, "://") {
		hostParseURL = "//" + hostParseURL
	}

	originalParsed, _ := url.Parse(hostParseURL)

	// Set the Host for the outgoing request. This is correct for both cases
	// (with or without IP substitution) because originalParsed.Host will always
	// be the domain we want to target.
	proxyReq.Host = originalParsed.Host
	proxyReq.Header.Set("Host", originalParsed.Host)

	if selectedIP != "" {
		log.Printf("[IPS] Preserving original Host header: %s", originalParsed.Host)
	}

	proxyReq.Header.Set("X-Forwarded-For", getClientIP(r))
	proxyReq.Header.Set("X-Forwarded-Host", r.Host)
	proxyReq.Header.Set("X-Forwarded-Proto", getScheme(r))

	client := &http.Client{
		Transport: p.client.Transport,
		Timeout:   policies.Timeout,
	}

	if matched && mapping != nil && mapping.P12 != "" {
		if p12Config, ok := p.config.P12s[mapping.P12]; ok {
			p12Client, err := p.createClientWithP12(p12Config.Path, p12Config.Password, policies)
			if err != nil {
				log.Printf("[P12] Error creating client with P12 certificate: %v", err)
			} else {
				log.Printf("[P12] Using client certificate from %s for this request", p12Config.Path)
				client = p12Client
			}
		} else {
			log.Printf("[P12] Warning: P12 certificate name '%s' not found in config", mapping.P12)
		}
	}

	if matched && mapping != nil {
		fromConfig := mapping.GetFromConfig()
		if fromConfig != nil {
			if len(fromConfig.Headers) > 0 {
				headers, headersToRemove := fromConfig.GetAllHeaders()
				for _, key := range headersToRemove {
					proxyReq.Header.Del(key)
				}
				for key, value := range headers {
					proxyReq.Header.Set(key, value)
				}
			}
			if len(fromConfig.QueryString) > 0 {
				parsedURL, _ := url.Parse(targetURL)
				query := parsedURL.Query()
				params, paramsToRemove := fromConfig.GetQueryString()
				for _, key := range paramsToRemove {
					query.Del(key)
				}
				for key, value := range params {
					query.Set(key, value)
				}
				parsedURL.RawQuery = query.Encode()
				targetURL = parsedURL.String()
				proxyReq.URL = parsedURL
			}
			if fromConfig.Proxy != nil {
				proxyManager := NewProxyManager(fromConfig.Proxy)
				defer proxyManager.Close()
				proxyURL := proxyManager.GetRandomProxy()
				if proxyURL != "" {
					proxyClient, err := p.createProxyClient(proxyURL)
					if err != nil {
						log.Printf("[PROXY] Error creating proxy client: %v", err)
					} else {
						client = proxyClient
					}
				}
			}
		}
		if len(mapping.Cc) > 0 {
			go p.carbonCopyRequest(proxyReq, mapping.Cc)
		}
	}

	var resp *http.Response

	// New tunnel/endpoint selection logic
	var tunnelName, endpointName string
	isTunnelRequest := false

	// Priority 1: 用户级别的endpoints配置（最高优先级）
	if len(userEndpointNames) > 0 {
		isTunnelRequest = true
		randomEndpoint := userEndpointNames[rand.Intn(len(userEndpointNames))]

		foundTunnel, ok := p.tunnelManager.FindTunnelForEndpoint(randomEndpoint)
		if !ok {
			isError = true
			http.Error(w, "User-level endpoint not found or not connected: "+randomEndpoint, http.StatusBadGateway)
			log.Printf("[TUNNEL] User-level specified endpoint '%s' not found in any active tunnel", randomEndpoint)
			return
		}
		tunnelName = foundTunnel
		endpointName = randomEndpoint
		tunnelKey = tunnelName // for stats
		DebugLog("[TUNNEL] Using user-level endpoint '%s' via tunnel '%s'", endpointName, tunnelName)

	} else if len(userTunnelNames) > 0 {
		// Priority 2: 用户级别的tunnels配置
		isTunnelRequest = true
		foundTunnel, foundEndpoint, err := p.tunnelManager.GetRandomEndpointFromTunnels(userTunnelNames)
		if err != nil {
			isError = true
			http.Error(w, "No available endpoint for user-level tunnels", http.StatusBadGateway)
			log.Printf("[TUNNEL] %v", err)
			return
		}
		tunnelName = foundTunnel
		endpointName = foundEndpoint
		tunnelKey = tunnelName // for stats
		DebugLog("[TUNNEL] Using user-level tunnel '%s' to endpoint '%s'", tunnelName, endpointName)

	} else if len(serverEndpointNames) > 0 {
		// Priority 3: server级别的endpoints配置
		isTunnelRequest = true
		randomEndpoint := serverEndpointNames[rand.Intn(len(serverEndpointNames))]

		foundTunnel, ok := p.tunnelManager.FindTunnelForEndpoint(randomEndpoint)
		if !ok {
			isError = true
			http.Error(w, "Server-level endpoint not found or not connected: "+randomEndpoint, http.StatusBadGateway)
			log.Printf("[TUNNEL] Server-level specified endpoint '%s' not found in any active tunnel", randomEndpoint)
			return
		}
		tunnelName = foundTunnel
		endpointName = randomEndpoint
		tunnelKey = tunnelName // for stats
		DebugLog("[TUNNEL] Using server-level endpoint '%s' via tunnel '%s'", endpointName, tunnelName)

	} else if len(serverTunnelNames) > 0 {
		// Priority 4: server级别的tunnels配置
		isTunnelRequest = true
		foundTunnel, foundEndpoint, err := p.tunnelManager.GetRandomEndpointFromTunnels(serverTunnelNames)
		if err != nil {
			isError = true
			http.Error(w, "No available endpoint for server-level tunnels", http.StatusBadGateway)
			log.Printf("[TUNNEL] %v", err)
			return
		}
		tunnelName = foundTunnel
		endpointName = foundEndpoint
		tunnelKey = tunnelName // for stats
		DebugLog("[TUNNEL] Using server-level tunnel '%s' to endpoint '%s'", tunnelName, endpointName)

	} else if mapping != nil && len(mapping.endpointNames) > 0 {
		// Priority 5: mapping级别的endpoints配置（fallback）
		isTunnelRequest = true
		randomEndpoint := mapping.endpointNames[rand.Intn(len(mapping.endpointNames))]

		foundTunnel, ok := p.tunnelManager.FindTunnelForEndpoint(randomEndpoint)
		if !ok {
			isError = true
			http.Error(w, "Endpoint not found or not connected: "+randomEndpoint, http.StatusBadGateway)
			log.Printf("[TUNNEL] Specified endpoint '%s' not found in any active tunnel", randomEndpoint)
			return
		}
		tunnelName = foundTunnel
		endpointName = randomEndpoint
		tunnelKey = tunnelName // for stats

	} else if mapping != nil && len(mapping.tunnelNames) > 0 {
		// Priority 6: mapping级别的tunnels配置（fallback）
		isTunnelRequest = true
		foundTunnel, foundEndpoint, err := p.tunnelManager.GetRandomEndpointFromTunnels(mapping.tunnelNames)
		if err != nil {
			isError = true
			http.Error(w, "No available endpoint for specified tunnels", http.StatusBadGateway)
			log.Printf("[TUNNEL] %v", err)
			return
		}
		tunnelName = foundTunnel
		endpointName = foundEndpoint
		tunnelKey = tunnelName // for stats
	}

	if isTunnelRequest {
		// If insecure is set, add a header to signal the endpoint to skip TLS verification.
		if toConfig := mapping.GetToConfig(); toConfig != nil && toConfig.Insecure != nil && *toConfig.Insecure {
			proxyReq.Header.Set("X-Aps-Insecure", "true")
		}

		reqBytes, err := httputil.DumpRequest(proxyReq, true)
		if err != nil {
			isError = true
			http.Error(w, "Failed to serialize request for tunnel", http.StatusInternalServerError)
			log.Printf("[TUNNEL] Error serializing request: %v", err)
			return
		}

		DebugLog("[TUNNEL] Forwarding request for %s via tunnel '%s' to endpoint '%s'", originalURL, tunnelName, endpointName)

		reqPayload := &RequestPayload{
			URL:  proxyReq.URL.String(),
			Data: reqBytes,
		}

		bodyStream, headerBytes, err := p.tunnelManager.SendRequestStream(r.Context(), tunnelName, endpointName, reqPayload)
		if err != nil {
			isError = true
			http.Error(w, "Failed to send request through tunnel: "+err.Error(), http.StatusBadGateway)
			log.Printf("[TUNNEL] Error sending request via endpoint '%s': %v", endpointName, err)
			return
		}
		defer bodyStream.Close()

		// Read the initial response from the header bytes
		resp, err = http.ReadResponse(bufio.NewReader(bytes.NewReader(headerBytes)), proxyReq)
		if err != nil {
			isError = true
			http.Error(w, "Failed to read response header from tunnel", http.StatusInternalServerError)
			log.Printf("[TUNNEL] Error reading response header from endpoint '%s': %v", endpointName, err)
			return
		}
		// The body from ReadResponse is empty; we will stream the real body.
		resp.Body = bodyStream
	} else {
		// This is a direct request (not via tunnel)
		// If we are using IP substitution for an HTTPS request, we need to
		// customize the TLS client config to set the SNI to the original host.
		if selectedIP != "" && proxyReq.URL.Scheme == "https" {
			// Clone the default transport and set the ServerName for SNI.
			baseTransport, ok := p.client.Transport.(*http.Transport)
			if !ok {
				// If the transport is not a standard http.Transport (e.g., it's a TunnelRoundTripper),
				// we need to get the underlying transport.
				if trt, ok := p.client.Transport.(*TunnelRoundTripper); ok {
					baseTransport, _ = trt.GetInnerTransport().(*http.Transport)
				}
			}

			if baseTransport != nil {
				customTransport := baseTransport.Clone()
				if baseTransport.TLSClientConfig != nil {
					customTransport.TLSClientConfig = baseTransport.TLSClientConfig.Clone()
				} else {
					customTransport.TLSClientConfig = &tls.Config{}
				}

				// Apply the insecure setting from the mapping
				if toConfig := mapping.GetToConfig(); toConfig != nil && toConfig.Insecure != nil && *toConfig.Insecure {
					customTransport.TLSClientConfig.InsecureSkipVerify = true
					log.Printf("[IPS] InsecureSkipVerify enabled for direct request to %s", actualTargetURL)
				}

				serverName := proxyReq.Host
				if strings.Contains(serverName, ":") {
					serverName = strings.Split(serverName, ":")[0]
				}
				customTransport.TLSClientConfig.ServerName = serverName

				// Create a temporary client with the custom transport for this request.
				sniClient := &http.Client{
					Transport: customTransport,
					Timeout:   client.Timeout,
					CheckRedirect: func(req *http.Request, via []*http.Request) error {
						return http.ErrUseLastResponse
					},
				}
				log.Printf("[IPS] Using custom transport with SNI: %s for direct request to %s", serverName, actualTargetURL)
				resp, err = sniClient.Do(proxyReq)
			} else {
				log.Printf("[IPS] Warning: Could not get base http.Transport to configure SNI.")
				resp, err = client.Do(proxyReq)
			}
		} else {
			resp, err = client.Do(proxyReq)
		}

		if err != nil {
			isError = true
			p.logHarEntry(r, nil, startTime, mapping, user)
			http.Error(w, "Failed to proxy request", http.StatusBadGateway)
			log.Printf("Error proxying request: %v", err)
			return
		}
	}
	defer resp.Body.Close()

	if matched && mapping != nil {
		toConfig := mapping.GetToConfig()
		if toConfig != nil && toConfig.Script != "" {
			resp, err = p.scriptRunner.RunOnResponse(resp, toConfig.Script)
			if err != nil {
				log.Printf("[SCRIPT] Error running onResponse script %s: %v", toConfig.Script, err)
			}
		}
	}

	p.logHarEntry(r, resp, startTime, mapping, user)

	copyHeaders(w.Header(), resp.Header)
	setCorsHeaders(w.Header())

	if matched && mapping != nil {
		toConfig := mapping.GetToConfig()
		if toConfig != nil && len(toConfig.Headers) > 0 {
			headers, headersToRemove := toConfig.GetAllHeaders()
			for _, key := range headersToRemove {
				w.Header().Del(key)
			}
			for key, value := range headers {
				w.Header().Set(key, value)
			}
		}
	}

	body, err := p.modifyResponseBody(resp, mapping)
	if err != nil {
		isError = true
		http.Error(w, "Failed to modify response body", http.StatusInternalServerError)
		log.Printf("Error modifying response body: %v", err)
		return
	}
	bytesRecv = uint64(len(body))

	if encoding := resp.Header.Get("Content-Encoding"); encoding == "" {
		w.Header().Del("Content-Encoding")
	} else {
		w.Header().Set("Content-Encoding", encoding)
	}

	// Remove conflicting Transfer-Encoding and set a strict numeric Content-Length
	w.Header().Del("Transfer-Encoding")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	w.WriteHeader(resp.StatusCode)

	var reader io.Reader = bytes.NewReader(body)
	if policies.Quality < 1.0 && policies.Quality > 0 {
		reader = NewThrottledReader(reader, policies.Quality)
	}

	var writer io.Writer = w
	if limiter != nil || len(quotas) > 0 {
		limitedWriter := newLimitedReadWriteCloser(nil, limiter, trackingQuota)
		writer = limitedWriter.(io.Writer)
	}

	// Use pooled writer wrapper to count bytes written
	counterWriter := getCounterWriter(writer)
	defer putCounterWriter(counterWriter)
	_, err = io.Copy(counterWriter, reader)
	if err != nil {
		log.Printf("Error writing response body: %v", err)
	}
	bytesSent = counterWriter.BytesWritten

	// 静态文件缓存保存 - 仅缓存成功的200响应
	if p.staticCache != nil && p.staticCache.IsCacheable(r.URL.Path) && resp.StatusCode == http.StatusOK {
		cacheURL := p.buildOriginalURL(r)
		// 确保缓存的是解压后的明文内容
		cacheBody := body
		if encoding := resp.Header.Get("Content-Encoding"); encoding != "" {
			decodedBody, _, decoded, err := decodeBodyWithEncoding(body, encoding)
			if err == nil && decoded {
				cacheBody = decodedBody
				log.Printf("[CACHE] Decoded %s content before caching: %d -> %d bytes", encoding, len(body), len(cacheBody))
			}
		}
		if err := p.staticCache.Set(cacheURL, resp.Header, resp.StatusCode, cacheBody); err != nil {
			log.Printf("[CACHE] Error saving cache for %s: %v", cacheURL, err)
		}
	}

	if policies.Quality < 1.0 {
		log.Printf("[%s] %s - %d (%d bytes, throttled)", r.Method, originalURL, resp.StatusCode, bytesSent)
	} else {
		log.Printf("[%s] %s - %d (%d bytes)", r.Method, originalURL, resp.StatusCode, bytesSent)
	}
}

// ByteCounterWriter is a simple io.Writer that counts the number of bytes written.
type ByteCounterWriter struct {
	Writer       io.Writer
	BytesWritten uint64
}

func (w *ByteCounterWriter) Write(p []byte) (n int, err error) {
	n, err = w.Writer.Write(p)
	w.BytesWritten += uint64(n)
	return
}

func (p *MapRemoteProxy) modifyRequestBody(r *http.Request, mapping *Mapping) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body))
	if mapping == nil {
		return body, nil
	}
	fromConfig := mapping.GetFromConfig()
	if fromConfig == nil {
		return body, nil
	}
	if fromConfig.Match != "" {
		re, err := compileRegex(fromConfig.Match)
		if err != nil {
			log.Printf("Invalid match regex in 'from' config: %v", err)
			return body, nil
		}
		matches := re.FindSubmatch(body)
		if len(matches) > 1 {
			body = matches[1]
		} else {
			body = []byte{}
		}
	}
	if len(fromConfig.Replace) > 0 {
		tempBody := string(body)
		for key, value := range fromConfig.Replace {
			re, err := compileRegex(key)
			if err != nil {
				log.Printf("Invalid replace regex in 'from' config: %v", err)
				continue
			}
			unescapedValue := unescapeReplacementString(value)
			tempBody = re.ReplaceAllString(tempBody, unescapedValue)
		}
		body = []byte(tempBody)
	}
	return body, nil
}

func (p *MapRemoteProxy) modifyResponseBody(resp *http.Response, mapping *Mapping) ([]byte, error) {
	if resp.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewBuffer(body))

	if mapping == nil {
		return body, nil
	}

	toConfig := mapping.GetToConfig()
	if toConfig == nil {
		return body, nil
	}

	if toConfig.Match == "" && len(toConfig.Replace) == 0 {
		return body, nil
	}

	encodingHeader := resp.Header.Get("Content-Encoding")
	decodedBody, encoding, decoded, err := decodeBodyWithEncoding(body, encodingHeader)
	if err != nil {
		log.Printf("[RESPONSE DECODE] Failed to decode body (%s): %v", encodingHeader, err)
	} else if decoded {
		body = decodedBody
	}

	if toConfig.Match != "" {
		re, err := compileRegex(toConfig.Match)
		if err != nil {
			log.Printf("Invalid match regex in 'to' config: %v", err)
			return body, nil
		}
		matches := re.FindSubmatch(body)
		if len(matches) > 1 {
			body = matches[1]
			log.Printf("[RESPONSE MATCH] Extracted %d bytes from response body", len(body))
		} else {
			body = []byte{}
			log.Printf("[RESPONSE MATCH] No match found, returning empty body")
		}
	}

	if len(toConfig.Replace) > 0 {
		tempBody := string(body)
		for key, value := range toConfig.Replace {
			re, err := compileRegex(key)
			if err != nil {
				log.Printf("Invalid replace regex in 'to' config: %v", err)
				continue
			}
			unescapedValue := unescapeReplacementString(value)
			tempBody = re.ReplaceAllString(tempBody, unescapedValue)
			log.Printf("[RESPONSE REPLACE] Applied replacement: %s -> %s", key, value)
		}
		body = []byte(tempBody)
	}

	if decoded && encoding != "" {
		reencodedBody, err := encodeBodyWithEncoding(body, encoding)
		if err != nil {
			log.Printf("[RESPONSE ENCODE] Failed to re-encode body (%s): %v", encoding, err)
			resp.Header.Del("Content-Encoding")
			return body, nil
		}
		resp.Header.Set("Content-Encoding", encoding)
		return reencodedBody, nil
	}

	if decoded {
		resp.Header.Del("Content-Encoding")
	}
	return body, nil
}

type ThrottledReader struct {
	r       io.Reader
	quality float64
}

func NewThrottledReader(r io.Reader, quality float64) *ThrottledReader {
	return &ThrottledReader{r: r, quality: quality}
}

func (tr *ThrottledReader) Read(p []byte) (n int, err error) {
	if tr.quality < 1.0 {
		maxSpeed := 10 * 1024 * 1024 // 10 MB/s
		effectiveSpeed := float64(maxSpeed) * tr.quality
		if effectiveSpeed < 1 {
			effectiveSpeed = 1
		}
		delay := time.Duration(float64(len(p)) / effectiveSpeed * float64(time.Second))
		time.Sleep(delay)
	}
	return tr.r.Read(p)
}

// unescapeReplacementString unescapes a string containing common Go-style escape sequences.
// This allows using sequences like \n, \t, or \" in the 'replace' values in config.json.
func unescapeReplacementString(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '\\' {
			if i+1 < len(s) {
				i++
				switch s[i] {
				case 'n':
					sb.WriteByte('\n')
				case 'r':
					sb.WriteByte('\r')
				case 't':
					sb.WriteByte('\t')
				case '"':
					sb.WriteByte('"')
				case '\\':
					sb.WriteByte('\\')
				default:
					// Not a recognized escape, treat literally
					sb.WriteByte('\\')
					sb.WriteByte(s[i])
				}
			} else {
				// Trailing backslash
				sb.WriteByte('\\')
			}
		} else {
			sb.WriteByte(s[i])
		}
		i++
	}
	return sb.String()
}

func (p *MapRemoteProxy) createClientWithP12(p12Path, password string, policies FinalPolicies) (*http.Client, error) {
	p12Bytes, err := os.ReadFile(p12Path)
	if err != nil {
		return nil, err
	}
	privateKey, certificate, err := pkcs12.Decode(p12Bytes, password)
	if err != nil {
		return nil, err
	}
	baseTransport := p.client.Transport.(*TunnelRoundTripper).GetInnerTransport().(*http.Transport)
	transport := baseTransport.Clone()
	transport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{certificate.Raw},
				PrivateKey:  privateKey,
			},
		},
	}
	tunnelTransport := NewTunnelRoundTripper(p.tunnelManager, transport)
	return &http.Client{
		Transport: tunnelTransport,
		Timeout:   policies.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}
