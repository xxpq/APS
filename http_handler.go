package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/pkcs12"
)

func (p *MapRemoteProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	p.stats.IncTotalRequests()
	p.stats.IncActiveConnections()
	defer p.stats.DecActiveConnections()

	targetURL, matched, mapping := p.mapRequest(r)
	originalURL := p.buildOriginalURL(r)

	// 如果匹配到了规则，需要再次检查该规则的权限
	authorized, user, username := p.checkAuth(r, mapping)
	if !authorized {
		// For CONNECT requests, we already sent ProxyAuthRequired.
		// For regular HTTP, Forbidden is more appropriate if credentials are provided but insufficient.
		if r.Method == http.MethodConnect || r.Header.Get("Proxy-Authorization") == "" {
			w.Header().Set("Proxy-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
		} else {
			http.Error(w, "Forbidden by rule", http.StatusForbidden)
		}
		return
	}

	// Check tunnel access permissions
	if mapping != nil && (len(mapping.tunnelNames) > 0 || len(mapping.endpointNames) > 0) {
		var tunnelName string
		if len(mapping.tunnelNames) > 0 {
			tunnelName = mapping.tunnelNames[0]
		} else if len(mapping.endpointNames) > 0 {
			// Use the pre-built map to find the tunnel for this endpoint
			tunnelName = p.endpointTunnelMap[mapping.endpointNames[0]]
		}

		if tunnelName != "" {
			if tunnelConfig, ok := p.config.Tunnels[tunnelName]; ok && tunnelConfig.Auth != nil {
				if !p.checkTunnelAccess(user, username, tunnelConfig.Auth) {
					log.Printf("[TUNNEL] User '%s' is not authorized for tunnel '%s'", username, tunnelName)
					http.Error(w, "Forbidden by tunnel access rule", http.StatusForbidden)
					return
				}
			}
		}
	}

	// Resolve connection policies
	serverConfig := p.config.Servers[p.serverName]
	policies := p.config.ResolvePolicies(serverConfig, mapping, user, username)

	// Resolve traffic policies
	var tunnelConfig *TunnelConfig
	if mapping != nil && len(mapping.tunnelNames) > 0 {
		tunnelConfig = p.config.Tunnels[mapping.tunnelNames[0]]
	}
	var proxyConfig *ProxyConfig
	if mapping != nil && len(mapping.proxyNames) > 0 {
		proxyConfig = p.config.Proxies[mapping.proxyNames[0]]
	}
	rateLimit, quotas, requestQuotas, err := p.config.ResolveTrafficPolicies(serverConfig, mapping, tunnelConfig, proxyConfig, user, username)
	if err != nil {
		log.Printf("[TRAFFIC] Error resolving traffic policies: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Check all applicable quotas
	for source, quotaLimit := range quotas {
		var initialUsage int64
		if usage, ok := p.config.QuotaUsage[source]; ok {
			initialUsage = usage.TrafficUsed
		}
		quota, err := p.trafficShaper.GetTrafficQuota(source, quotaLimit, initialUsage)
		if err != nil {
			log.Printf("[TRAFFIC] Error creating quota for %s: %v", source, err)
			continue // Or handle error more strictly
		}
		if quota.Exceeded {
			errMsg := fmt.Sprintf("Traffic quota exceeded for %s", source)
			http.Error(w, errMsg, http.StatusTooManyRequests)
			return
		}
	}

	// Check all applicable request quotas
	for source, quotaLimit := range requestQuotas {
		var initialUsage int64
		if usage, ok := p.config.QuotaUsage[source]; ok {
			initialUsage = usage.RequestsUsed
		}
		quota, err := p.trafficShaper.GetRequestQuota(source, quotaLimit, initialUsage)
		if err != nil {
			log.Printf("[TRAFFIC] Error creating request quota for %s: %v", source, err)
			continue
		}
		if !quota.AddRequest() {
			errMsg := fmt.Sprintf("Request quota exceeded for %s", source)
			http.Error(w, errMsg, http.StatusTooManyRequests)
			return
		}
	}

	// Get limiter
	limiterKey := "global" // Default key for rate limiting is per-user or per-IP
	if user != nil {
		limiterKey = username
	} else {
		limiterKey = getClientIP(r)
	}
	limiter, err := p.trafficShaper.GetLimiter(limiterKey, rateLimit)
	if err != nil {
		log.Printf("[TRAFFIC] Error creating limiter: %v", err)
	}

	// The limited writer just needs a quota object for tracking bytes, not for enforcement.
	// Enforcement is handled above. We can create a dummy/tracking quota object.
	trackingQuota, _ := p.trafficShaper.GetTrafficQuota(limiterKey, "", 0) // No limit, just for tracking

	// Apply MaxThread concurrency limit
	if policies.MaxThread > 0 {
		// Non-blocking acquire
		select {
		case p.concurrencyLimiter <- struct{}{}:
			// Acquired, defer release
			defer func() { <-p.concurrencyLimiter }()
		default:
			// Failed to acquire
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
	}

	if matched {
		p.stats.IncRuleMatchCount(mapping.GetFromURL())
		if mapping.Local != "" {
			log.Printf("[%s] %s -> [LOCAL] %s", r.Method, originalURL, mapping.Local)
			p.serveFile(w, r, mapping)
			return
		}
		log.Printf("[%s] %s -> %s (MAPPED)", r.Method, originalURL, targetURL)
	} else {
		log.Printf("[%s] %s (NO MAPPING)", r.Method, originalURL)
	}

	var requestBody io.Reader = r.Body
	if matched && mapping != nil {
		modifiedBody, err := p.modifyRequestBody(r, mapping)
		if err != nil {
			http.Error(w, "Failed to modify request body", http.StatusInternalServerError)
			log.Printf("Error modifying request body: %v", err)
			return
		}
		requestBody = bytes.NewBuffer(modifiedBody)
	}

	proxyReq, err := http.NewRequest(r.Method, targetURL, requestBody)
	if err != nil {
		http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
		log.Printf("Error creating request: %v", err)
		return
	}

	// Run onRequest script if defined
	if matched && mapping != nil && mapping.Script != nil && mapping.Script.OnRequest != "" {
		var scriptErr error
		proxyReq, scriptErr = p.scriptRunner.RunOnRequest(proxyReq, mapping.Script.OnRequest)
		if scriptErr != nil {
			log.Printf("[SCRIPT] Error running onRequest script %s: %v", mapping.Script.OnRequest, scriptErr)
			// Decide if you want to stop the request or continue with the original
			// http.Error(w, "Script execution failed", http.StatusInternalServerError)
			// return
		}
	}

	// 将 mapping 注入 context，以便 TunnelRoundTripper 访问
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

	// Create a client for this specific request to apply timeouts
	client := &http.Client{
		Transport: p.client.Transport,
		Timeout:   policies.Timeout, // Apply overall request timeout
	}

	// Check for mTLS/P12 configuration
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

	var proxyManager *ProxyManager

	if matched && mapping != nil {
		fromConfig := mapping.GetFromConfig()
		if fromConfig != nil && len(fromConfig.Headers) > 0 {
			headers, headersToRemove := fromConfig.GetAllHeaders()
			if len(headersToRemove) > 0 {
				log.Printf("[REQUEST HEADERS] Removing %d headers", len(headersToRemove))
				for _, key := range headersToRemove {
					proxyReq.Header.Del(key)
				}
			}
			if len(headers) > 0 {
				log.Printf("[REQUEST HEADERS] Applying %d custom headers from 'from' config", len(headers))
				for key, value := range headers {
					proxyReq.Header.Set(key, value)
				}
			}
		}

		if fromConfig != nil && len(fromConfig.QueryString) > 0 {
			parsedURL, _ := url.Parse(targetURL)
			query := parsedURL.Query()

			params, paramsToRemove := fromConfig.GetQueryString()
			if len(paramsToRemove) > 0 {
				log.Printf("[REQUEST QUERY] Removing %d query parameters", len(paramsToRemove))
				for _, key := range paramsToRemove {
					query.Del(key)
				}
			}
			if len(params) > 0 {
				log.Printf("[REQUEST QUERY] Applying %d query parameters", len(params))
				for key, value := range params {
					query.Set(key, value)
				}
			}

			parsedURL.RawQuery = query.Encode()
			targetURL = parsedURL.String()
			proxyReq.URL = parsedURL
		}

		if fromConfig != nil && fromConfig.Proxy != nil {
			proxyManager = NewProxyManager(fromConfig.Proxy)
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

		if len(mapping.Cc) > 0 {
			go p.carbonCopyRequest(proxyReq, mapping.Cc)
		}
	}

	startTime := time.Now()
	resp, err := client.Do(proxyReq)
	if err != nil {
		if mapping != nil {
			p.stats.IncRuleErrors(mapping.GetFromURL())
		}
		p.logHarEntry(r, nil, startTime, mapping, user)
		http.Error(w, "Failed to proxy request", http.StatusBadGateway)
		log.Printf("Error proxying request: %v", err)
		return
	}
	defer resp.Body.Close()

	// Run onResponse script if defined
	if matched && mapping != nil && mapping.Script != nil && mapping.Script.OnResponse != "" {
		var scriptErr error
		resp, scriptErr = p.scriptRunner.RunOnResponse(resp, mapping.Script.OnResponse)
		if scriptErr != nil {
			log.Printf("[SCRIPT] Error running onResponse script %s: %v", mapping.Script.OnResponse, scriptErr)
			// Decide if you want to stop or continue with the original response
		}
	}

	p.logHarEntry(r, resp, startTime, mapping, user)

	copyHeaders(w.Header(), resp.Header)
	setCorsHeaders(w.Header())

	if matched && mapping != nil {
		toConfig := mapping.GetToConfig()
		if toConfig != nil && len(toConfig.Headers) > 0 {
			headers, headersToRemove := toConfig.GetAllHeaders()
			if len(headersToRemove) > 0 {
				log.Printf("[RESPONSE HEADERS] Removing %d headers", len(headersToRemove))
				for _, key := range headersToRemove {
					w.Header().Del(key)
				}
			}
			if len(headers) > 0 {
				log.Printf("[RESPONSE HEADERS] Applying %d custom headers from 'to' config", len(headers))
				for key, value := range headers {
					w.Header().Set(key, value)
				}
			}
		}
	}

	body, err := p.modifyResponseBody(resp, mapping)
	if err != nil {
		http.Error(w, "Failed to modify response body", http.StatusInternalServerError)
		log.Printf("Error modifying response body: %v", err)
		return
	}

	w.Header().Set("Content-Length", string(len(body)))
	w.WriteHeader(resp.StatusCode)

	// Apply Quality (throttling) and Rate Limiting to the response body
	var reader io.Reader = bytes.NewReader(body)
	if policies.Quality < 1.0 && policies.Quality > 0 {
		reader = NewThrottledReader(reader, policies.Quality)
	}

	// Wrap the response writer for rate limiting and quota tracking
	var writer io.Writer = w
	if limiter != nil || len(quotas) > 0 {
		limitedWriter := newLimitedReadWriteCloser(nil, limiter, trackingQuota)
		writer = limitedWriter.(io.Writer)
	}

	// Use a custom writer to track bytes written for stats
	statWriter := &StatsWriter{ResponseWriter: writer, Stats: p.stats, RuleKey: ""}
	if mapping != nil {
		statWriter.RuleKey = mapping.GetFromURL()
	}

	bytesWritten, err := io.Copy(statWriter, reader)
	if err != nil {
		log.Printf("Error writing response body: %v", err)
	}

	// Track received bytes (response body size)
	p.stats.AddBytesRecv(uint64(len(body)))
	if mapping != nil {
		p.stats.AddRuleBytesRecv(mapping.GetFromURL(), uint64(len(body)))
	}


	if policies.Quality < 1.0 {
		log.Printf("[%s] %s - %d (%d bytes, throttled)", r.Method, originalURL, resp.StatusCode, bytesWritten)
	} else {
		log.Printf("[%s] %s - %d (%d bytes)", r.Method, originalURL, resp.StatusCode, len(body))
	}
}

// StatsWriter is a wrapper around an io.Writer that tracks the number of bytes written.
type StatsWriter struct {
	ResponseWriter io.Writer
	BytesWritten   uint64
	Stats          *StatsCollector
	RuleKey        string
}

func (sw *StatsWriter) Write(p []byte) (n int, err error) {
	n, err = sw.ResponseWriter.Write(p)
	sw.BytesWritten += uint64(n)
	sw.Stats.AddBytesSent(uint64(n))
	if sw.RuleKey != "" {
		sw.Stats.AddRuleBytesSent(sw.RuleKey, uint64(n))
	}
	return
}

func (p *MapRemoteProxy) modifyRequestBody(r *http.Request, mapping *Mapping) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body))

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
			log.Printf("[REQUEST MATCH] Extracted %d bytes from request body", len(body))
		} else {
			body = []byte{}
			log.Printf("[REQUEST MATCH] No match found, returning empty body")
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
			log.Printf("[REQUEST REPLACE] Applied replacement: %s -> %s", key, value)
		}
		body = []byte(tempBody)
	}

	return body, nil
}

// ThrottledReader simulates a slow network by limiting the read speed.
type ThrottledReader struct {
	r       io.Reader
	quality float64 // 0.0 to 1.0
}

func NewThrottledReader(r io.Reader, quality float64) *ThrottledReader {
	return &ThrottledReader{r: r, quality: quality}
}

func (tr *ThrottledReader) Read(p []byte) (n int, err error) {
	// This is a very simplistic implementation. A real-world scenario would use a token bucket.
	// For now, we just sleep a bit on each read to simulate slowness.
	// The delay is inversely proportional to the quality.
	if tr.quality < 1.0 {
		// Calculate delay based on a hypothetical max speed of 10 MB/s
		// and the size of the buffer 'p'.
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

// createClientWithP12 creates an HTTP client configured with a client certificate from a P12 file.
func (p *MapRemoteProxy) createClientWithP12(p12Path, password string, policies FinalPolicies) (*http.Client, error) {
	p12Bytes, err := ioutil.ReadFile(p12Path)
	if err != nil {
		return nil, err
	}

	privateKey, certificate, err := pkcs12.Decode(p12Bytes, password)
	if err != nil {
		return nil, err
	}

	// Create a new transport, inheriting from the default one but adding the client cert
	// This is important to keep other transport settings like proxy, timeouts, etc.
	baseTransport := p.client.Transport.(*TunnelRoundTripper).GetInnerTransport().(*http.Transport)
	transport := baseTransport.Clone()

	transport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true, // Keep this for general proxy functionality
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{certificate.Raw},
				PrivateKey:  privateKey,
			},
		},
	}

	// Wrap it in the TunnelRoundTripper again
	tunnelTransport := NewTunnelRoundTripper(p.tunnelManager, transport)

	return &http.Client{
		Transport: tunnelTransport,
		Timeout:   policies.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}