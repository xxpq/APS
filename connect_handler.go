package main

import (
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

	DebugLog("[CONNECT] %s", host)

	// 检查 server 是否启用了代理功能
	serverConfig := p.config.Servers[p.serverName]
	if serverConfig == nil || serverConfig.Proxy == nil || !*serverConfig.Proxy {
		log.Printf("[PROXY] CONNECT request rejected: server '%s' does not have proxy enabled", p.serverName)
		w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy Disabled"`)
		DebugLog("Proxy service is not enabled on this server", http.StatusProxyAuthRequired)
		return
	}

	// 检查防火墙规则
	var firewallRule *FirewallRule
	if serverConfig.Firewall != "" {
		firewallRule = GetFirewallRule(p.config, serverConfig.Firewall)
	}
	clientIP := getClientIP(r)
	if !CheckFirewall(clientIP, firewallRule) {
		log.Printf("[FIREWALL] CONNECT request from %s blocked by firewall", clientIP)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	hostname := strings.Split(r.Host, ":")[0]
	shouldIntercept := p.shouldInterceptHost(hostname)

	if shouldIntercept {
		DebugLog("[CONNECT] Intercepting HTTPS for mapping: %s", r.Host)
		p.handleConnectWithMITM(w, r)
	} else {
		// For non-intercepted CONNECT, we must enforce server-level auth here
		// because we won't see the inner requests.
		authorized, user, username := p.checkAuth(r, nil)
		if !authorized {
			w.Header().Set("Proxy-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
			return
		}

		// 检查用户是否有代理权限
		if hasPermission, errMsg := p.checkProxyPermission(user, username); !hasPermission {
			log.Printf("[PROXY] User '%s' denied CONNECT access: %s", username, errMsg)
			http.Error(w, "Forbidden: "+errMsg, http.StatusForbidden)
			return
		}

		DebugLog("[CONNECT] Tunneling without intercept: %s", r.Host)
		p.handleConnectTunnel(w, r, host, user, username)
	}
}

func (p *MapRemoteProxy) shouldInterceptHost(hostname string) bool {
	mappings := p.config.GetMappings()
	for _, mapping := range mappings {
		fromURL := mapping.GetFromURL()
		if strings.HasPrefix(fromURL, "https://"+hostname) {
			DebugLog("[DEBUG] Host %s matches mapping pattern %s", hostname, fromURL)
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

	_, err = clientConn.Write(connectEstablishedResponse)
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

	reader := GetBufioReader(tlsClientConn)
	defer PutBufioReader(reader)
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

func (p *MapRemoteProxy) handleConnectTunnel(w http.ResponseWriter, r *http.Request, destHost string, user *User, username string) {
	startTime := time.Now()
	p.stats.IncTotalRequests()
	p.stats.IncActiveConnections()
	defer p.stats.DecActiveConnections()

	var isError bool
	var userKey = username

	serverConfig := p.config.Servers[p.serverName]
	// For a simple tunnel, we don't have a mapping or tunnel context
	rateLimit, quotas, requestQuotas, err := p.config.ResolveTrafficPolicies(serverConfig, nil, nil, nil, user, username)
	if err != nil {
		isError = true
		log.Printf("[TRAFFIC] Error resolving traffic policies for CONNECT: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Check all applicable quotas
	for source, quotaLimit := range quotas {
		quota, err := p.trafficShaper.GetTrafficQuota(source, quotaLimit)
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

	// Check all applicable request quotas
	for source, quotaLimit := range requestQuotas {
		quota, err := p.trafficShaper.GetRequestQuota(source, quotaLimit)
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
	trackingQuota, _ := p.trafficShaper.GetTrafficQuota(limiterKey, "")

	destConn, err := net.DialTimeout("tcp", destHost, 10*time.Second)
	if err != nil {
		isError = true
		http.Error(w, "Failed to connect to destination", http.StatusServiceUnavailable)
		log.Printf("Error connecting to %s: %v", destHost, err)
		return
	}
	defer destConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		isError = true
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		isError = true
		http.Error(w, "Failed to hijack connection", http.StatusServiceUnavailable)
		log.Printf("Error hijacking connection: %v", err)
		return
	}
	defer clientConn.Close()

	_, err = clientConn.Write(connectEstablishedResponse)
	if err != nil {
		isError = true
		log.Printf("Error writing 200 OK to client: %v", err)
		return
	}

	var clientWriter io.Writer = clientConn
	var destWriter io.Writer = destConn
	var clientReader io.Reader = clientConn
	var destReader io.Reader = destConn

	if limiter != nil || len(quotas) > 0 {
		limitedClient := newLimitedReadWriteCloser(clientConn, limiter, trackingQuota)
		clientWriter = limitedClient
		clientReader = limitedClient

		limitedDest := newLimitedReadWriteCloser(destConn, limiter, trackingQuota)
		destWriter = limitedDest
		destReader = limitedDest
	}

	var bytesSent, bytesRecv int64
	done := GetDoneChannel()
	defer PutDoneChannel(done)

	go func() {
		// client -> destination (upload)
		n, _ := io.Copy(destWriter, clientReader)
		bytesRecv = n
		done <- struct{}{}
	}()

	go func() {
		// destination -> client (download)
		n, _ := io.Copy(clientWriter, destReader)
		bytesSent = n
		done <- struct{}{}
	}()

	<-done
	<-done // Wait for both goroutines to finish

	responseTime := time.Since(startTime)
	p.stats.AddBytesSent(uint64(bytesSent))
	p.stats.AddBytesRecv(uint64(bytesRecv))
	p.stats.Record(RecordData{
		// No rule for pure CONNECT tunnel
		UserKey:      userKey,
		ServerKey:    p.serverName,
		BytesSent:    uint64(bytesSent),
		BytesRecv:    uint64(bytesRecv),
		ResponseTime: responseTime,
		IsError:      isError,
		Protocol:     "http", // CONNECT is HTTP method
		StatusCode:   200,    // Successful connection
		ClientIP:     getClientIP(r),
	})

	DebugLog("[CONNECT] %s - Connection closed. Sent: %d, Recv: %d", r.Host, bytesSent, bytesRecv)
}

// modifyResponseBody is now only in http_handler.go
