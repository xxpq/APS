package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type MapRemoteProxy struct {
	config    *Config
	client    *http.Client
	harLogger *HarLogger
}

func NewMapRemoteProxy(config *Config, harLogger *HarLogger) *MapRemoteProxy {
	// 默认不使用代理的 transport
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &MapRemoteProxy{
		config:    config,
		harLogger: harLogger,
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Timeout: 60 * time.Second,
		},
	}
}

// createProxyClient 为指定的代理 URL 创建 HTTP 客户端
func (p *MapRemoteProxy) createProxyClient(proxyURL string) (*http.Client, error) {
	if proxyURL == "" {
		return p.client, nil
	}

	parsedProxy, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		Proxy:           http.ProxyURL(parsedProxy),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 60 * time.Second,
	}, nil
}

func (p *MapRemoteProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		setCorsHeaders(w.Header())
		w.WriteHeader(http.StatusOK)
		log.Printf("[OPTIONS] %s - Handled with CORS headers", r.URL.String())
		return
	}

	if r.Method == http.MethodConnect {
		p.handleConnectWithIntercept(w, r)
		return
	}

	p.handleHTTP(w, r)
}

func (p *MapRemoteProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	originalURL := p.buildOriginalURL(r)
	targetURL, matched, mapping := p.mapRequestWithMappingAndMethod(originalURL, r.Method)

	if matched {
		if mapping.Local != "" {
			log.Printf("[%s] %s -> [LOCAL] %s", r.Method, originalURL, mapping.Local)
			p.serveFile(w, r, mapping)
			return
		}
		log.Printf("[%s] %s -> %s (MAPPED)", r.Method, originalURL, targetURL)
	} else {
		log.Printf("[%s] %s (NO MAPPING)", r.Method, originalURL)
	}

	// 读取并可能修改请求体
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

	copyHeaders(proxyReq.Header, r.Header)

	targetParsed, _ := url.Parse(targetURL)
	proxyReq.Host = targetParsed.Host
	proxyReq.Header.Set("Host", targetParsed.Host)

	proxyReq.Header.Set("X-Forwarded-For", getClientIP(r))
	proxyReq.Header.Set("X-Forwarded-Host", r.Host)
	proxyReq.Header.Set("X-Forwarded-Proto", getScheme(r))

	// 选择使用的 HTTP 客户端（可能带代理）
	client := p.client
	var proxyManager *ProxyManager
	
	if matched && mapping != nil {
		// 应用来自 from 配置的请求头
		fromConfig := mapping.GetFromConfig()
		if fromConfig != nil && len(fromConfig.Headers) > 0 {
			headers, headersToRemove := fromConfig.GetAllHeaders()
			if len(headersToRemove) > 0 {
				log.Printf("[REQUEST HEADERS] Removing %d headers", len(headersToRemove))
				for _, key := range headersToRemove {
					proxyReq.Header.Del(key)
					log.Printf("[REQUEST HEADERS]   Removed: %s", key)
				}
			}
			if len(headers) > 0 {
				log.Printf("[REQUEST HEADERS] Applying %d custom headers from 'from' config", len(headers))
				for key, value := range headers {
					proxyReq.Header.Set(key, value)
					log.Printf("[REQUEST HEADERS]   %s: %s", key, value)
				}
			}
		}
		
		// 应用来自 from 配置的查询参数
		if fromConfig != nil && len(fromConfig.QueryString) > 0 {
			parsedURL, _ := url.Parse(targetURL)
			query := parsedURL.Query()
			
			params, paramsToRemove := fromConfig.GetQueryString()
			if len(paramsToRemove) > 0 {
				log.Printf("[REQUEST QUERY] Removing %d query parameters", len(paramsToRemove))
				for _, key := range paramsToRemove {
					query.Del(key)
					log.Printf("[REQUEST QUERY]   Removed: %s", key)
				}
			}
			if len(params) > 0 {
				log.Printf("[REQUEST QUERY] Applying %d query parameters", len(params))
				for key, value := range params {
					query.Set(key, value)
					log.Printf("[REQUEST QUERY]   %s: %s", key, value)
				}
			}
			
			parsedURL.RawQuery = query.Encode()
			targetURL = parsedURL.String()
			proxyReq.URL = parsedURL
		}
		
		// 处理代理配置
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
		if p.harLogger != nil {
			p.logHarEntry(r, nil, startTime)
		}
		http.Error(w, "Failed to proxy request", http.StatusBadGateway)
		log.Printf("Error proxying request: %v", err)
		return
	}
	defer resp.Body.Close()

	if p.harLogger != nil {
		p.logHarEntry(r, resp, startTime)
	}

	copyHeaders(w.Header(), resp.Header)
	
	// 先设置默认跨域头
	setCorsHeaders(w.Header())
	
	// 然后应用来自 to 配置的响应头（覆盖默认跨域头）
	if matched && mapping != nil {
		toConfig := mapping.GetToConfig()
		if toConfig != nil && len(toConfig.Headers) > 0 {
			headers, headersToRemove := toConfig.GetAllHeaders()
			if len(headersToRemove) > 0 {
				log.Printf("[RESPONSE HEADERS] Removing %d headers", len(headersToRemove))
				for _, key := range headersToRemove {
					w.Header().Del(key)
					log.Printf("[RESPONSE HEADERS]   Removed: %s", key)
				}
			}
			if len(headers) > 0 {
				log.Printf("[RESPONSE HEADERS] Applying %d custom headers from 'to' config", len(headers))
				for key, value := range headers {
					w.Header().Set(key, value)
					log.Printf("[RESPONSE HEADERS]   %s: %s", key, value)
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
	w.Write(body)

	log.Printf("[%s] %s - %d (%d bytes)", r.Method, originalURL, resp.StatusCode, len(body))
}

func (p *MapRemoteProxy) handleConnectWithIntercept(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	log.Printf("[CONNECT] %s", host)

	hostname := strings.Split(r.Host, ":")[0]

	shouldIntercept := p.shouldInterceptHost(hostname)

	if shouldIntercept {
		log.Printf("[CONNECT] Intercepting HTTPS for mapping: %s", r.Host)
		p.handleConnectWithMITM(w, r)
	} else {
		log.Printf("[CONNECT] Tunneling without intercept: %s", r.Host)
		p.handleConnectTunnel(w, r, host)
	}
}

func (p *MapRemoteProxy) shouldInterceptHost(hostname string) bool {
	mappings := p.config.GetMappings()
	for _, mapping := range mappings {
		fromURL := mapping.GetFromURL()
		parsedFrom, err := url.Parse(fromURL)
		if err != nil {
			continue
		}

		if parsedFrom.Host == hostname {
			log.Printf("[DEBUG] Host %s matches mapping pattern %s", hostname, fromURL)
			return true
		}
	}
	return false
}

func (p *MapRemoteProxy) handleConnectWithMITM(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Failed to hijack connection", http.StatusServiceUnavailable)
		log.Printf("Error hijacking connection: %v", err)
		return
	}
	defer clientConn.Close()

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	hostname := strings.Split(r.Host, ":")[0]

	tlsClientConn := tls.Server(clientConn, &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return GenerateCertForHost(hostname)
		},
	})
	defer tlsClientConn.Close()

	if err := tlsClientConn.Handshake(); err != nil {
		log.Printf("TLS handshake error: %v", err)
		return
	}

	reader := bufio.NewReader(tlsClientConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				log.Printf("Error reading HTTPS request: %v", err)
			}
			break
		}

		req.URL.Scheme = "https"
		req.URL.Host = r.Host
		if !strings.HasPrefix(req.RequestURI, "http") {
			req.RequestURI = "https://" + r.Host + req.RequestURI
		}

		originalURL := "https://" + hostname + req.URL.Path
		if req.URL.RawQuery != "" {
			originalURL += "?" + req.URL.RawQuery
		}

		log.Printf("[DEBUG] Original URL: %s", originalURL)

		targetURL, matched, mapping := p.mapRequestWithMappingAndMethod(originalURL, req.Method)
		if matched {
			log.Printf("[HTTPS %s] %s -> %s (✓ MAPPED)", req.Method, originalURL, targetURL)
		} else {
			log.Printf("[HTTPS %s] %s (✗ NO MAPPING)", req.Method, originalURL)
		}

		// 读取并可能修改请求体
		var requestBody io.Reader = req.Body
		if matched && mapping != nil {
			modifiedBody, err := p.modifyRequestBody(req, mapping)
			if err != nil {
				log.Printf("Error modifying request body: %v", err)
			} else {
				requestBody = bytes.NewBuffer(modifiedBody)
			}
		}

		proxyReq, err := http.NewRequest(req.Method, targetURL, requestBody)
		if err != nil {
			log.Printf("Error creating proxy request: %v", err)
			break
		}

		copyHeaders(proxyReq.Header, req.Header)

		targetParsed, _ := url.Parse(targetURL)
		proxyReq.Host = targetParsed.Host
		proxyReq.Header.Set("Host", targetParsed.Host)

		// 选择使用的 HTTP 客户端（可能带代理）
		client := p.client
		var proxyManager *ProxyManager
		
		if matched && mapping != nil {
			// 应用来自 from 配置的请求头
			fromConfig := mapping.GetFromConfig()
			if fromConfig != nil && len(fromConfig.Headers) > 0 {
				headers, headersToRemove := fromConfig.GetAllHeaders()
				if len(headersToRemove) > 0 {
					log.Printf("[REQUEST HEADERS] Removing %d headers", len(headersToRemove))
					for _, key := range headersToRemove {
						proxyReq.Header.Del(key)
						log.Printf("[REQUEST HEADERS]   Removed: %s", key)
					}
				}
				if len(headers) > 0 {
					log.Printf("[REQUEST HEADERS] Applying %d custom headers from 'from' config", len(headers))
					for key, value := range headers {
						proxyReq.Header.Set(key, value)
						log.Printf("[REQUEST HEADERS]   %s: %s", key, value)
					}
				}
			}
			
			// 应用来自 from 配置的查询参数
			if fromConfig != nil && len(fromConfig.QueryString) > 0 {
				parsedURL, _ := url.Parse(targetURL)
				query := parsedURL.Query()
				
				params, paramsToRemove := fromConfig.GetQueryString()
				if len(paramsToRemove) > 0 {
					log.Printf("[REQUEST QUERY] Removing %d query parameters", len(paramsToRemove))
					for _, key := range paramsToRemove {
						query.Del(key)
						log.Printf("[REQUEST QUERY]   Removed: %s", key)
					}
				}
				if len(params) > 0 {
					log.Printf("[REQUEST QUERY] Applying %d query parameters", len(params))
					for key, value := range params {
						query.Set(key, value)
						log.Printf("[REQUEST QUERY]   %s: %s", key, value)
					}
				}
				
				parsedURL.RawQuery = query.Encode()
				targetURL = parsedURL.String()
				proxyReq.URL = parsedURL
			}
			
			// 处理代理配置
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

		log.Printf("[DEBUG] Sending request to: %s (Host: %s)", targetURL, targetParsed.Host)

		startTime := time.Now()
		resp, err := client.Do(proxyReq)
		if err != nil {
			if p.harLogger != nil {
				p.logHarEntry(req, nil, startTime)
			}
			log.Printf("Error proxying HTTPS request: %v", err)
			errorResp := &http.Response{
				StatusCode: http.StatusBadGateway,
				ProtoMajor: 1,
				ProtoMinor: 1,
				Body:       io.NopCloser(strings.NewReader("Proxy Error")),
			}
			errorResp.Write(tlsClientConn)
			break
		}

		if p.harLogger != nil {
			p.logHarEntry(req, resp, startTime)
		}

		// 先设置默认跨域头
		setCorsHeaders(resp.Header)
		
		// 然后应用来自 to 配置的响应头（覆盖默认跨域头）
		if matched && mapping != nil {
			toConfig := mapping.GetToConfig()
			if toConfig != nil && len(toConfig.Headers) > 0 {
				headers, headersToRemove := toConfig.GetAllHeaders()
				if len(headersToRemove) > 0 {
					log.Printf("[RESPONSE HEADERS] Removing %d headers", len(headersToRemove))
					for _, key := range headersToRemove {
						resp.Header.Del(key)
						log.Printf("[RESPONSE HEADERS]   Removed: %s", key)
					}
				}
				if len(headers) > 0 {
					log.Printf("[RESPONSE HEADERS] Applying %d custom headers from 'to' config", len(headers))
					for key, value := range headers {
						resp.Header.Set(key, value)
						log.Printf("[RESPONSE HEADERS]   %s: %s", key, value)
					}
				}
			}
		}

		body, err := p.modifyResponseBody(resp, mapping)
		if err != nil {
			log.Printf("Error modifying response body: %v", err)
			// Still try to write original response
			resp.Write(tlsClientConn)
		} else {
			resp.Body = ioutil.NopCloser(bytes.NewBuffer(body))
			resp.Header.Set("Content-Length", string(len(body)))
			resp.Write(tlsClientConn)
		}

		resp.Body.Close()

		log.Printf("[HTTPS %s] %s - %d (Target: %s)", req.Method, originalURL, resp.StatusCode, targetParsed.Host)
	}
}

func (p *MapRemoteProxy) handleConnectTunnel(w http.ResponseWriter, r *http.Request, destHost string) {
	destConn, err := net.DialTimeout("tcp", destHost, 10*time.Second)
	if err != nil {
		http.Error(w, "Failed to connect to destination", http.StatusServiceUnavailable)
		log.Printf("Error connecting to %s: %v", destHost, err)
		return
	}
	defer destConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Failed to hijack connection", http.StatusServiceUnavailable)
		log.Printf("Error hijacking connection: %v", err)
		return
	}
	defer clientConn.Close()

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	done := make(chan struct{}, 2)

	go func() {
		io.Copy(destConn, clientConn)
		done <- struct{}{}
	}()

	go func() {
		io.Copy(clientConn, destConn)
		done <- struct{}{}
	}()

	<-done
	log.Printf("[CONNECT] %s - Connection closed", r.Host)
}

func (p *MapRemoteProxy) buildOriginalURL(r *http.Request) string {
	originalURL := r.URL.String()

	if !strings.HasPrefix(originalURL, "http://") && !strings.HasPrefix(originalURL, "https://") {
		scheme := getScheme(r)
		originalURL = scheme + "://" + r.Host + originalURL
	}

	return originalURL
}

func (p *MapRemoteProxy) mapRequestWithMapping(originalURL string) (string, bool, *Mapping) {
	return p.mapRequestWithMappingAndMethod(originalURL, "")
}

func (p *MapRemoteProxy) mapRequestWithMappingAndMethod(originalURL string, method string) (string, bool, *Mapping) {
	mappings := p.config.GetMappings()
	for i := range mappings {
		mapping := &mappings[i]
		
		// 检查 method 是否匹配
		fromConfig := mapping.GetFromConfig()
		if fromConfig != nil && method != "" && !fromConfig.MatchesMethod(method) {
			continue
		}
		
		if matched, newURL := p.matchAndReplace(originalURL, *mapping); matched {
			return newURL, true, mapping
		}
	}
	return originalURL, false, nil
}

func (p *MapRemoteProxy) matchAndReplace(originalURL string, mapping Mapping) (bool, string) {
	fromPattern := mapping.GetFromURL()
	toPattern := mapping.GetToURL()

	log.Printf("[DEBUG] Trying to match: %s with pattern: %s", originalURL, fromPattern)

	// 尝试正则表达式匹配
	if matched, newURL := p.tryRegexMatch(originalURL, fromPattern, toPattern); matched {
		return true, newURL
	}

	// 回退到原始的字符串匹配逻辑
	parsedOriginal, err := url.Parse(originalURL)
	if err != nil {
		log.Printf("[DEBUG] Failed to parse original URL: %v", err)
		return false, originalURL
	}

	parsedFrom, err := url.Parse(fromPattern)
	if err != nil {
		log.Printf("[DEBUG] Failed to parse from pattern: %v", err)
		return false, originalURL
	}

	log.Printf("[DEBUG] Original - Scheme: %s, Host: %s, Path: %s",
		parsedOriginal.Scheme, parsedOriginal.Host, parsedOriginal.Path)
	log.Printf("[DEBUG] Pattern  - Scheme: %s, Host: %s, Path: %s",
		parsedFrom.Scheme, parsedFrom.Host, parsedFrom.Path)

	if parsedOriginal.Scheme != parsedFrom.Scheme {
		log.Printf("[DEBUG] Scheme mismatch: %s != %s", parsedOriginal.Scheme, parsedFrom.Scheme)
		return false, originalURL
	}

	if parsedOriginal.Host != parsedFrom.Host {
		log.Printf("[DEBUG] Host mismatch: %s != %s", parsedOriginal.Host, parsedFrom.Host)
		return false, originalURL
	}

	fromPath := parsedFrom.Path
	originalPath := parsedOriginal.Path

	if originalPath == "" {
		originalPath = "/"
	}

	if strings.HasSuffix(fromPath, "*") {
		fromPathPrefix := strings.TrimSuffix(fromPath, "*")

		if fromPathPrefix == "" || fromPathPrefix == "/" {
			log.Printf("[DEBUG] Root wildcard match - matches any path")
		} else {
			log.Printf("[DEBUG] Wildcard match - checking if %s starts with %s", originalPath, fromPathPrefix)
		}

		if fromPathPrefix == "" || fromPathPrefix == "/" || strings.HasPrefix(originalPath, fromPathPrefix) {
			toPath := strings.TrimSuffix(toPattern, "*")

			parsedTo, err := url.Parse(toPath)
			if err != nil {
				return false, originalURL
			}

			var remainingPath string
			if fromPathPrefix == "" || fromPathPrefix == "/" {
				if originalPath == "/" {
					remainingPath = ""
				} else {
					remainingPath = originalPath
				}
			} else {
				remainingPath = strings.TrimPrefix(originalPath, fromPathPrefix)
			}

			newPath := parsedTo.Path
			if strings.HasSuffix(newPath, "/") && strings.HasPrefix(remainingPath, "/") {
				newPath = strings.TrimSuffix(newPath, "/")
			}
			newPath = newPath + remainingPath

			newURL := url.URL{
				Scheme:   parsedTo.Scheme,
				Host:     parsedTo.Host,
				Path:     newPath,
				RawQuery: parsedOriginal.RawQuery,
				Fragment: parsedOriginal.Fragment,
			}

			log.Printf("[DEBUG] ✓ Wildcard matched! New URL: %s", newURL.String())
			return true, newURL.String()
		}
	} else {
		log.Printf("[DEBUG] Exact match - checking if %s == %s", originalPath, fromPath)
		if originalPath == fromPath || (originalPath == "/" && fromPath == "") || (originalPath == "" && fromPath == "/") {
			parsedTo, err := url.Parse(toPattern)
			if err != nil {
				return false, originalURL
			}

			newURL := url.URL{
				Scheme:   parsedTo.Scheme,
				Host:     parsedTo.Host,
				Path:     parsedTo.Path,
				RawQuery: parsedOriginal.RawQuery,
				Fragment: parsedOriginal.Fragment,
			}

			log.Printf("[DEBUG] ✓ Exact matched! New URL: %s", newURL.String())
			return true, newURL.String()
		}
	}

	log.Printf("[DEBUG] ✗ No match")
	return false, originalURL
}

// tryRegexMatch 尝试使用正则表达式匹配 URL
func (p *MapRemoteProxy) tryRegexMatch(originalURL, fromPattern, toPattern string) (bool, string) {
	// 检查 fromPattern 是否包含正则表达式特征（但排除简单的 * 通配符）
	if !strings.Contains(fromPattern, "(") && !strings.Contains(fromPattern, "[") &&
	   !strings.Contains(fromPattern, "{") && !strings.Contains(fromPattern, "^") &&
	   !strings.Contains(fromPattern, "$") && !strings.Contains(fromPattern, "|") {
		return false, originalURL
	}

	re, err := regexp.Compile(fromPattern)
	if err != nil {
		log.Printf("[DEBUG] Not a valid regex pattern: %v", err)
		return false, originalURL
	}

	if !re.MatchString(originalURL) {
		return false, originalURL
	}

	// 使用正则表达式替换
	newURL := re.ReplaceAllString(originalURL, toPattern)
	log.Printf("[DEBUG] ✓ Regex matched! %s -> %s", originalURL, newURL)
	return true, newURL
}

// modifyRequestBody 修改请求体（如果 from 配置中有 match 或 replace）
func (p *MapRemoteProxy) modifyRequestBody(r *http.Request, mapping *Mapping) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body)) // Restore body

	if mapping == nil {
		return body, nil
	}

	// 使用 from 配置中的 match 和 replace（如果有）
	fromConfig := mapping.GetFromConfig()
	if fromConfig == nil {
		return body, nil
	}

	// Match
	if fromConfig.Match != "" {
		re, err := regexp.Compile(fromConfig.Match)
		if err != nil {
			log.Printf("Invalid match regex in 'from' config: %v", err)
			return body, nil // Return original body
		}
		matches := re.FindSubmatch(body)
		if len(matches) > 1 {
			body = matches[1] // Use the first capture group
			log.Printf("[REQUEST MATCH] Extracted %d bytes from request body", len(body))
		} else {
			body = []byte{} // No match, return empty
			log.Printf("[REQUEST MATCH] No match found, returning empty body")
		}
	}

	// Replace
	if len(fromConfig.Replace) > 0 {
		tempBody := string(body)
		for key, value := range fromConfig.Replace {
			re, err := regexp.Compile(key)
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

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		if key == "Host" || key == "Connection" || key == "Proxy-Connection" ||
			key == "Keep-Alive" || key == "Proxy-Authenticate" || key == "Proxy-Authorization" ||
			key == "Te" || key == "Trailer" || key == "Transfer-Encoding" || key == "Upgrade" {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func setCorsHeaders(h http.Header) {
	h.Set("Origin", "*")
	h.Set("Timing-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Vary", "Etag, Save-Data, Accept-Encoding")
	h.Set("Access-Control-Allow-Headers", "*")
	h.Set("Access-Control-Allow-Methods", "*")
	h.Set("Access-Control-Allow-Credentials", "true")
	h.Set("Access-Control-Expose-Headers", "*")
	h.Set("Access-Control-Request-Method", "*")
	h.Set("Access-Control-Request-Headers", "*")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "cross-origin")
}

func getClientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0]
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}

func getScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if scheme := r.Header.Get("X-Forwarded-Proto"); scheme != "" {
		return scheme
	}
	return "http"
}

func (p *MapRemoteProxy) logHarEntry(req *http.Request, resp *http.Response, startTime time.Time) {
	harEntry, err := p.createHarEntry(req, resp, startTime)
	if err != nil {
		log.Printf("Error creating HAR entry: %v", err)
		return
	}
	p.harLogger.AddEntry(*harEntry)
}

func (p *MapRemoteProxy) createHarEntry(req *http.Request, resp *http.Response, startTime time.Time) (*HarEntry, error) {
	// Request
	harReq, err := p.createHarRequest(req)
	if err != nil {
		return nil, err
	}

	// Response
	var harResp HarResponse
	if resp != nil {
		harResp, err = p.createHarResponse(resp)
		if err != nil {
			return nil, err
		}
	}

	return &HarEntry{
		StartedDateTime: startTime.Format(time.RFC3339),
		Time:            float64(time.Since(startTime).Milliseconds()),
		Request:         *harReq,
		Response:        harResp,
		Cache:           HarCache{},
		Timings: HarTimings{
			Send:    0, // Simplified
			Wait:    float64(time.Since(startTime).Milliseconds()),
			Receive: 0, // Simplified
		},
	}, nil
}

func (p *MapRemoteProxy) createHarRequest(req *http.Request) (*HarRequest, error) {
	// Read body
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = ioutil.ReadAll(req.Body)
		req.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes)) // Restore body
	}

	// Headers
	headers := make([]HarHeader, 0)
	for name, values := range req.Header {
		for _, value := range values {
			headers = append(headers, HarHeader{Name: name, Value: value})
		}
	}

	// QueryString
	queryString := make([]HarQueryPair, 0)
	for name, values := range req.URL.Query() {
		for _, value := range values {
			queryString = append(queryString, HarQueryPair{Name: name, Value: value})
		}
	}

	// PostData
	var postData *HarPostData
	if len(bodyBytes) > 0 {
		postData = &HarPostData{
			MimeType: req.Header.Get("Content-Type"),
			Text:     string(bodyBytes),
		}
	}

	reqDump, _ := httputil.DumpRequest(req, false)

	return &HarRequest{
		Method:      req.Method,
		URL:         req.URL.String(),
		HTTPVersion: req.Proto,
		Headers:     headers,
		QueryString: queryString,
		PostData:    postData,
		HeadersSize: int64(len(reqDump)),
		BodySize:    req.ContentLength,
	}, nil
}

func (p *MapRemoteProxy) createHarResponse(resp *http.Response) (HarResponse, error) {
	// Read body
	var bodyBytes []byte
	if resp.Body != nil {
		bodyBytes, _ = ioutil.ReadAll(resp.Body)
		resp.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes)) // Restore body
	}

	// Headers
	headers := make([]HarHeader, 0)
	for name, values := range resp.Header {
		for _, value := range values {
			headers = append(headers, HarHeader{Name: name, Value: value})
		}
	}

	respDump, _ := httputil.DumpResponse(resp, false)

	return HarResponse{
		Status:      resp.StatusCode,
		StatusText:  resp.Status,
		HTTPVersion: resp.Proto,
		Headers:     headers,
		Content: HarContentDetails{
			Size:     int64(len(bodyBytes)),
			MimeType: resp.Header.Get("Content-Type"),
			Text:     string(bodyBytes),
		},
		RedirectURL: resp.Header.Get("Location"),
		HeadersSize: int64(len(respDump)),
		BodySize:    resp.ContentLength,
	}, nil
}

func (p *MapRemoteProxy) carbonCopyRequest(req *http.Request, ccTargets []string) {
	for _, target := range ccTargets {
		go func(targetURL string) {
			// Create a new request for CC
			var bodyBytes []byte
			if req.Body != nil {
				bodyBytes, _ = ioutil.ReadAll(req.Body)
				req.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes)) // Restore original body
			}

			ccReq, err := http.NewRequest(req.Method, targetURL, bytes.NewBuffer(bodyBytes))
			if err != nil {
				log.Printf("[CC] Error creating request for %s: %v", targetURL, err)
				return
			}
			copyHeaders(ccReq.Header, req.Header)

			resp, err := p.client.Do(ccReq)
			if err != nil {
				log.Printf("[CC] Error sending request to %s: %v", targetURL, err)
				return
			}
			defer resp.Body.Close()
			log.Printf("[CC] Request sent to %s, status: %d", targetURL, resp.StatusCode)
		}(target)
	}
}

func (p *MapRemoteProxy) serveFile(w http.ResponseWriter, r *http.Request, mapping *Mapping) {
	localPath := mapping.Local
	if strings.HasSuffix(localPath, "*") {
		basePath := strings.TrimSuffix(localPath, "*")
		fromURL := mapping.GetFromURL()
		fromBasePath := strings.TrimSuffix(fromURL, "*")
		requestedPath := strings.TrimPrefix(r.URL.Path, fromBasePath)
		localPath = filepath.Join(basePath, requestedPath)
	}

	// 尝试查找 index 文件
	localPath = findIndexFile(localPath)

	content, err := ioutil.ReadFile(localPath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		log.Printf("Error reading file %s: %v", localPath, err)
		return
	}

	contentType := getMimeType(localPath)
	w.Header().Set("Content-Type", contentType)
	setCorsHeaders(w.Header())
	w.WriteHeader(http.StatusOK)
	w.Write(content)
}

// findIndexFile 如果路径是目录，尝试查找 index.html 或 index.htm
func findIndexFile(path string) string {
	// 检查路径是否为目录
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return path
	}

	// 按优先级尝试 index 文件
	indexFiles := []string{"index.html", "index.htm"}
	for _, indexFile := range indexFiles {
		indexPath := filepath.Join(path, indexFile)
		if _, err := os.Stat(indexPath); err == nil {
			log.Printf("[INDEX] Found %s for directory %s", indexFile, path)
			return indexPath
		}
	}

	// 没找到 index 文件，返回原路径
	return path
}

func (p *MapRemoteProxy) modifyResponseBody(resp *http.Response, mapping *Mapping) ([]byte, error) {
	if resp.Body == nil {
		return nil, nil
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body = ioutil.NopCloser(bytes.NewBuffer(body)) // Restore body for HAR logger

	if mapping == nil {
		return body, nil
	}

	// 使用 to 配置中的 match 和 replace（如果有）
	toConfig := mapping.GetToConfig()
	if toConfig == nil {
		return body, nil
	}

	// Match
	if toConfig.Match != "" {
		re, err := regexp.Compile(toConfig.Match)
		if err != nil {
			log.Printf("Invalid match regex in 'to' config: %v", err)
			return body, nil // Return original body
		}
		matches := re.FindSubmatch(body)
		if len(matches) > 1 {
			body = matches[1] // Use the first capture group
			log.Printf("[RESPONSE MATCH] Extracted %d bytes from response body", len(body))
		} else {
			body = []byte{} // No match, return empty
			log.Printf("[RESPONSE MATCH] No match found, returning empty body")
		}
	}

	// Replace
	if len(toConfig.Replace) > 0 {
		tempBody := string(body)
		for key, value := range toConfig.Replace {
			re, err := regexp.Compile(key)
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
