package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

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
		if strings.HasPrefix(fromURL, "https://"+hostname) {
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

	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		log.Printf("Error writing 200 OK to client: %v", err)
		return
	}

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

		// 在这里处理被拦截的 HTTPS 请求
		p.handleHTTP(w, req)
	}
}

func (p *MapRemoteProxy) handleConnectTunnel(w http.ResponseWriter, r *http.Request, destHost string) {
	p.stats.IncTotalRequests()
	p.stats.IncActiveConnections()
	defer p.stats.DecActiveConnections()

	// Auth and policy resolution for CONNECT should happen before tunneling
	_, user, username := p.checkAuth(r, nil) // No specific mapping for pure CONNECT

	serverConfig := p.config.Servers[p.serverName]
	// For a simple tunnel, we don't have a mapping or tunnel context
	rateLimit, quotas, requestQuotas, err := p.config.ResolveTrafficPolicies(serverConfig, nil, nil, nil, user, username)
	if err != nil {
		log.Printf("[TRAFFIC] Error resolving traffic policies for CONNECT: %v", err)
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
			continue
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
	limiterKey := "global"
	if user != nil {
		limiterKey = username
	} else {
		limiterKey = getClientIP(r)
	}
	limiter, err := p.trafficShaper.GetLimiter(limiterKey, rateLimit)
	if err != nil {
		log.Printf("[TRAFFIC] Error creating limiter for CONNECT: %v", err)
	}

	// Get a tracking quota object for the writer
	trackingQuota, _ := p.trafficShaper.GetTrafficQuota(limiterKey, "", 0)

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

	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		log.Printf("Error writing 200 OK to client: %v", err)
		return
	}

	// Wrap connections if limiter or quota is active
	var clientReader io.Reader = clientConn
	var destReader io.Reader = destConn

	if limiter != nil || len(quotas) > 0 {
		limitedClient := newLimitedReadWriteCloser(clientConn, limiter, trackingQuota)
		clientReader = limitedClient

		limitedDest := newLimitedReadWriteCloser(destConn, limiter, trackingQuota)
		destReader = limitedDest
	}

	// Wrap for stats collection
	statsClient := NewStatsReadWriteCloser(clientConn, p.stats)
	statsDest := NewStatsReadWriteCloser(destConn, p.stats)

	done := make(chan struct{}, 2)

	go func() {
		// client -> destination
		// bytes written to statsDest are bytes received from client
		io.Copy(statsDest, clientReader)
		done <- struct{}{}
	}()

	go func() {
		// destination -> client
		// bytes written to statsClient are bytes sent to client
		io.Copy(statsClient, destReader)
		done <- struct{}{}
	}()

	<-done
	log.Printf("[CONNECT] %s - Connection closed", r.Host)
}

// modifyResponseBody 移动到 http_handler.go
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
