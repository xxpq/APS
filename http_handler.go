package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/pkcs12"
)

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

	targetURL, matched, mapping := p.mapRequest(r)
	originalURL := p.buildOriginalURL(r)

	if !r.URL.IsAbs() && !matched {
		isError = true
		http.NotFound(w, r)
		log.Printf("[%s] %s (NO MAPPING - 404 Not Found)", r.Method, originalURL)
		return
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

	// Populate keys for stats
	if mapping != nil {
		ruleKey = mapping.GetFromURL()
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

	serverConfig := p.config.Servers[p.serverName]
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
		fromConfig := mapping.GetFromConfig()
		if fromConfig != nil && fromConfig.GRPC != nil && fromConfig.GRPC.RestToGrpc != nil {
			log.Printf("[%s] %s -> [REST-to-gRPC] %s", r.Method, originalURL, targetURL)
			p.handleRestToGrpc(w, r, mapping)
			return
		}
		if strings.HasPrefix(targetURL, "file://") {
			log.Printf("[%s] %s -> [LOCAL] %s", r.Method, originalURL, targetURL)
			p.serveFile(w, r, mapping)
			return
		}
		log.Printf("[%s] %s -> %s (MAPPED)", r.Method, originalURL, targetURL)
	} else {
		log.Printf("[%s] %s (NO MAPPING)", r.Method, originalURL)
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

	proxyReq, err := http.NewRequest(r.Method, targetURL, requestBody)
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
	targetParsed, _ := url.Parse(targetURL)
	proxyReq.Host = targetParsed.Host
	proxyReq.Header.Set("Host", targetParsed.Host)
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
	if tunnelKey != "" {
		var endpointName string
		if len(mapping.endpointNames) > 0 {
			endpointName = mapping.endpointNames[0]
		}

		p.tunnelManager.mu.RLock()
		tunnel, exists := p.tunnelManager.tunnels[tunnelKey]
		p.tunnelManager.mu.RUnlock()
		if !exists {
			isError = true
			http.Error(w, "Tunnel not found: "+tunnelKey, http.StatusBadGateway)
			log.Printf("[TUNNEL] Tunnel '%s' not found", tunnelKey)
			return
		}

		if endpointName == "" {
			tunnel.mu.RLock()
			if len(tunnel.streams) == 0 {
				tunnel.mu.RUnlock()
				isError = true
				http.Error(w, "No available endpoint for tunnel: "+tunnelKey, http.StatusBadGateway)
				log.Printf("[TUNNEL] No available endpoint for tunnel '%s'", tunnelKey)
				return
			}
			for name := range tunnel.streams {
				endpointName = name
				break
			}
			tunnel.mu.RUnlock()
		}

		reqBytes, err := httputil.DumpRequest(proxyReq, true)
		if err != nil {
			isError = true
			http.Error(w, "Failed to serialize request for tunnel", http.StatusInternalServerError)
			log.Printf("[TUNNEL] Error serializing request: %v", err)
			return
		}

		log.Printf("[TUNNEL] Forwarding request for %s via tunnel '%s' to endpoint '%s'", originalURL, tunnelKey, endpointName)

		reqPayload := &RequestPayload{
			URL:  proxyReq.URL.String(),
			Data: reqBytes,
		}

		respBytes, err := p.tunnelManager.SendRequest(r.Context(), tunnelKey, endpointName, reqPayload)
		if err != nil {
			isError = true
			http.Error(w, "Failed to send request through tunnel", http.StatusBadGateway)
			log.Printf("[TUNNEL] Error sending request via endpoint '%s': %v", endpointName, err)
			return
		}

		resp, err = http.ReadResponse(bufio.NewReader(bytes.NewReader(respBytes)), proxyReq)
		if err != nil {
			isError = true
			http.Error(w, "Failed to read response from tunnel", http.StatusInternalServerError)
			log.Printf("[TUNNEL] Error reading response from endpoint '%s': %v", endpointName, err)
			return
		}
	} else {
		var err error
		resp, err = client.Do(proxyReq)
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

	// Use a simple writer wrapper to count bytes written
	counterWriter := &ByteCounterWriter{Writer: writer}
	_, err = io.Copy(counterWriter, reader)
	if err != nil {
		log.Printf("Error writing response body: %v", err)
	}
	bytesSent = counterWriter.BytesWritten

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
			tempBody = re.ReplaceAllString(tempBody, value)
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
			tempBody = re.ReplaceAllString(tempBody, value)
			log.Printf("[RESPONSE REPLACE] Applied replacement: %s -> %s", key, value)
		}
		body = []byte(tempBody)
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
