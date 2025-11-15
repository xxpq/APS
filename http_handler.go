package main

import (
	"bytes"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"
)

func (p *MapRemoteProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	originalURL := p.buildOriginalURL(r)
	targetURL, matched, mapping := p.mapRequestWithMappingAndMethod(originalURL, r.Method)

	// 如果匹配到了规则，需要再次检查该规则的权限
	authorized, user := p.checkAuth(r, mapping)
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

	client := p.client
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
		p.logHarEntry(r, nil, startTime, mapping, user)
		http.Error(w, "Failed to proxy request", http.StatusBadGateway)
		log.Printf("Error proxying request: %v", err)
		return
	}
	defer resp.Body.Close()

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
	w.Write(body)

	log.Printf("[%s] %s - %d (%d bytes)", r.Method, originalURL, resp.StatusCode, len(body))
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