package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type DedicatedProxy struct {
	mapping *Mapping
	client  *http.Client
	port    int
}

func NewDedicatedProxy(mapping *Mapping, port int) *DedicatedProxy {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	return &DedicatedProxy{
		mapping: mapping,
		port:    port,
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
func (p *DedicatedProxy) createProxyClient(proxyURL string) (*http.Client, error) {
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
	}

	return &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 60 * time.Second,
	}, nil
}

func (p *DedicatedProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 处理 OPTIONS 请求
	if r.Method == http.MethodOptions {
		setCorsHeaders(w.Header())

		// 如果有 to 配置的自定义 headers，也应用到 OPTIONS 响应
		toConfig := p.mapping.GetToConfig()
		if toConfig != nil && len(toConfig.Headers) > 0 {
			headers, _ := toConfig.GetAllHeaders()
			for key, value := range headers {
				w.Header().Set(key, value)
			}
		}

		w.WriteHeader(http.StatusOK)
		log.Printf("[DEDICATED:%d OPTIONS] %s - Handled with CORS headers", p.port, r.URL.String())
		return
	}

	targetURL, err := p.buildTargetURL(r)
	if err != nil {
		http.Error(w, "Failed to build target URL", http.StatusInternalServerError)
		log.Printf("Error building target URL: %v", err)
		return
	}

	// Handle local file serving
	if strings.HasPrefix(targetURL, "file://") {
		log.Printf("[DEDICATED:%d] %s -> [LOCAL] %s", p.port, r.URL.String(), targetURL)
		p.serveFile(w, r)
		return
	}

	log.Printf("[DEDICATED:%d] %s -> %s", p.port, r.URL.String(), targetURL)

	// 读取并可能修改请求体
	requestBody, err := p.modifyRequestBody(r)
	if err != nil {
		http.Error(w, "Failed to modify request body", http.StatusInternalServerError)
		log.Printf("Error modifying request body: %v", err)
		return
	}

	proxyReq, err := http.NewRequest(r.Method, targetURL, bytes.NewBuffer(requestBody))
	if err != nil {
		http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
		log.Printf("Error creating request: %v", err)
		return
	}

	copyHeaders(proxyReq.Header, r.Header)

	targetParsed, _ := url.Parse(targetURL)
	proxyReq.Host = targetParsed.Host
	proxyReq.Header.Set("Host", targetParsed.Host)

	// 选择使用的 HTTP 客户端（可能带代理）
	client := p.client
	var proxyManager *ProxyManager

	// 应用来自 from 配置的请求头
	fromConfig := p.mapping.GetFromConfig()
	if fromConfig != nil && len(fromConfig.Headers) > 0 {
		headers, headersToRemove := fromConfig.GetAllHeaders()
		if len(headersToRemove) > 0 {
			log.Printf("[DEDICATED:%d REQUEST HEADERS] Removing %d headers", p.port, len(headersToRemove))
			for _, key := range headersToRemove {
				proxyReq.Header.Del(key)
			}
		}
		if len(headers) > 0 {
			log.Printf("[DEDICATED:%d REQUEST HEADERS] Applying %d custom headers from 'from' config", p.port, len(headers))
			for key, value := range headers {
				proxyReq.Header.Set(key, value)
			}
		}
	}

	// 应用来自 from 配置的查询参数
	if fromConfig != nil && len(fromConfig.QueryString) > 0 {
		query := proxyReq.URL.Query()

		params, paramsToRemove := fromConfig.GetQueryString()
		if len(paramsToRemove) > 0 {
			log.Printf("[DEDICATED:%d REQUEST QUERY] Removing %d query parameters", p.port, len(paramsToRemove))
			for _, key := range paramsToRemove {
				query.Del(key)
			}
		}
		if len(params) > 0 {
			log.Printf("[DEDICATED:%d REQUEST QUERY] Applying %d query parameters", p.port, len(params))
			for key, value := range params {
				query.Set(key, value)
			}
		}

		proxyReq.URL.RawQuery = query.Encode()
	}

	// 处理代理配置
	if fromConfig != nil && fromConfig.Proxy != nil {
		proxyManager = NewProxyManager(fromConfig.Proxy)
		defer proxyManager.Close()

		proxyURL := proxyManager.GetRandomProxy()
		if proxyURL != "" {
			proxyClient, err := p.createProxyClient(proxyURL)
			if err != nil {
				log.Printf("[DEDICATED:%d PROXY] Error creating proxy client: %v", p.port, err)
			} else {
				client = proxyClient
			}
		}
	}

	if len(p.mapping.Cc) > 0 {
		go p.carbonCopyRequest(proxyReq, p.mapping.Cc)
	}

	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, "Failed to proxy request", http.StatusBadGateway)
		log.Printf("Error proxying request: %v", err)
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)

	// 先设置默认跨域头
	setCorsHeaders(w.Header())

	// 然后应用来自 to 配置的响应头（覆盖默认跨域头）
	toConfig := p.mapping.GetToConfig()
	if toConfig != nil && len(toConfig.Headers) > 0 {
		headers, headersToRemove := toConfig.GetAllHeaders()
		if len(headersToRemove) > 0 {
			log.Printf("[DEDICATED:%d RESPONSE HEADERS] Removing %d headers", p.port, len(headersToRemove))
			for _, key := range headersToRemove {
				w.Header().Del(key)
			}
		}
		if len(headers) > 0 {
			log.Printf("[DEDICATED:%d RESPONSE HEADERS] Applying %d custom headers from 'to' config", p.port, len(headers))
			for key, value := range headers {
				w.Header().Set(key, value)
			}
		}
	}

	body, err := p.modifyResponseBody(resp)
	if err != nil {
		http.Error(w, "Failed to modify response body", http.StatusInternalServerError)
		log.Printf("Error modifying response body: %v", err)
		return
	}

	if encoding := resp.Header.Get("Content-Encoding"); encoding == "" {
		w.Header().Del("Content-Encoding")
	} else {
		w.Header().Set("Content-Encoding", encoding)
	}

	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

func (p *DedicatedProxy) buildTargetURL(r *http.Request) (string, error) {
	fromPath := p.mapping.GetFromURL()
	toPath := p.mapping.GetToURL()

	originalPath := r.URL.Path

	if strings.HasSuffix(fromPath, "*") {
		fromPathPrefix := strings.TrimSuffix(fromPath, "*")
		toPathPrefix := strings.TrimSuffix(toPath, "*")

		if strings.HasPrefix(originalPath, fromPathPrefix) {
			remainingPath := strings.TrimPrefix(originalPath, fromPathPrefix)
			newPath := toPathPrefix + remainingPath

			parsedURL, err := url.Parse(newPath)
			if err != nil {
				return "", err
			}

			parsedURL.RawQuery = r.URL.RawQuery
			return parsedURL.String(), nil
		}
	}

	// Exact match
	parsedURL, err := url.Parse(toPath)
	if err != nil {
		return "", err
	}
	parsedURL.RawQuery = r.URL.RawQuery
	return parsedURL.String(), nil
}

func (p *DedicatedProxy) carbonCopyRequest(req *http.Request, ccTargets []string) {
	for _, target := range ccTargets {
		go func(targetURL string) {
			var bodyBytes []byte
			if req.Body != nil {
				bodyBytes, _ = io.ReadAll(req.Body)
				req.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
			}

			ccReq, err := http.NewRequest(req.Method, targetURL, strings.NewReader(string(bodyBytes)))
			if err != nil {
				log.Printf("[CC DEDICATED:%d] Error creating request for %s: %v", p.port, targetURL, err)
				return
			}
			copyHeaders(ccReq.Header, req.Header)

			resp, err := p.client.Do(ccReq)
			if err != nil {
				log.Printf("[CC DEDICATED:%d] Error sending request to %s: %v", p.port, targetURL, err)
				return
			}
			defer resp.Body.Close()
			log.Printf("[CC DEDICATED:%d] Request sent to %s, status: %d", p.port, targetURL, resp.StatusCode)
		}(target)
	}
}

func (p *DedicatedProxy) serveFile(w http.ResponseWriter, r *http.Request) {
	toURL := p.mapping.GetToURL()
	// file://path/to/file or file:///C:/path/to/file
	localPath := strings.TrimPrefix(toURL, "file://")
	if strings.HasPrefix(localPath, "/") && len(localPath) > 2 && localPath[2] == ':' { // Windows path like /C:/...
		localPath = localPath[1:]
	}

	if strings.HasSuffix(localPath, "*") {
		basePath := strings.TrimSuffix(localPath, "*")
		fromURL := p.mapping.GetFromURL()
		fromBasePath := strings.TrimSuffix(fromURL, "*")
		requestedPath := strings.TrimPrefix(r.URL.Path, fromBasePath)
		localPath = filepath.Join(basePath, requestedPath)
	}

	content, err := os.ReadFile(localPath)
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

// modifyRequestBody 修改请求体（如果 from 配置中有 match 或 replace）
func (p *DedicatedProxy) modifyRequestBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body)) // Restore body

	// 使用 from 配置中的 match 和 replace（如果有）
	fromConfig := p.mapping.GetFromConfig()
	if fromConfig == nil {
		return body, nil
	}

	// Match
	if fromConfig.Match != "" {
		re, err := GetOrCompileRegex(fromConfig.Match)
		if err != nil {
			log.Printf("[DEDICATED:%d] Invalid match regex in 'from' config: %v", p.port, err)
			return body, nil
		}
		matches := re.FindSubmatch(body)
		if len(matches) > 1 {
			body = matches[1]
			log.Printf("[DEDICATED:%d REQUEST MATCH] Extracted %d bytes from request body", p.port, len(body))
		} else {
			body = []byte{}
			log.Printf("[DEDICATED:%d REQUEST MATCH] No match found, returning empty body", p.port)
		}
	}

	// Replace
	if len(fromConfig.Replace) > 0 {
		tempBody := string(body)
		for key, value := range fromConfig.Replace {
			re, err := GetOrCompileRegex(key)
			if err != nil {
				log.Printf("[DEDICATED:%d] Invalid replace regex in 'from' config: %v", p.port, err)
				continue
			}
			tempBody = re.ReplaceAllString(tempBody, value)
			log.Printf("[DEDICATED:%d REQUEST REPLACE] Applied replacement: %s -> %s", p.port, key, value)
		}
		body = []byte(tempBody)
	}

	return body, nil
}

func (p *DedicatedProxy) modifyResponseBody(resp *http.Response) ([]byte, error) {
	if resp.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewBuffer(body))

	// 使用 to 配置中的 match 和 replace（如果有）
	toConfig := p.mapping.GetToConfig()
	if toConfig == nil {
		return body, nil
	}

	if toConfig.Match == "" && len(toConfig.Replace) == 0 {
		return body, nil
	}

	encodingHeader := resp.Header.Get("Content-Encoding")
	decodedBody, encoding, decoded, err := decodeBodyWithEncoding(body, encodingHeader)
	if err != nil {
		log.Printf("[DEDICATED:%d] Failed to decode response body (%s): %v", p.port, encodingHeader, err)
	} else if decoded {
		body = decodedBody
	}

	// Match
	if toConfig.Match != "" {
		re, err := GetOrCompileRegex(toConfig.Match)
		if err != nil {
			log.Printf("[DEDICATED:%d] Invalid match regex in 'to' config: %v", p.port, err)
			return body, nil
		}
		matches := re.FindSubmatch(body)
		if len(matches) > 1 {
			body = matches[1]
			log.Printf("[DEDICATED:%d RESPONSE MATCH] Extracted %d bytes from response body", p.port, len(body))
		} else {
			body = []byte{}
			log.Printf("[DEDICATED:%d RESPONSE MATCH] No match found, returning empty body", p.port)
		}
	}

	// Replace
	if len(toConfig.Replace) > 0 {
		tempBody := string(body)
		for key, value := range toConfig.Replace {
			re, err := GetOrCompileRegex(key)
			if err != nil {
				log.Printf("[DEDICATED:%d] Invalid replace regex in 'to' config: %v", p.port, err)
				continue
			}
			tempBody = re.ReplaceAllString(tempBody, value)
			log.Printf("[DEDICATED:%d RESPONSE REPLACE] Applied replacement: %s -> %s", p.port, key, value)
		}
		body = []byte(tempBody)
	}

	if decoded && encoding != "" {
		reencodedBody, err := encodeBodyWithEncoding(body, encoding)
		if err != nil {
			log.Printf("[DEDICATED:%d] Failed to re-encode response body (%s): %v", p.port, encoding, err)
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
