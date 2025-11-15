package main

import (
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"
)

type MapRemoteProxy struct {
	config             *Config
	harManager         *HarLoggerManager
	tunnelManager      *TunnelManager
	serverName         string
	client             *http.Client
	concurrencyLimiter chan struct{}
}

func NewMapRemoteProxy(config *Config, harManager *HarLoggerManager, tunnelManager *TunnelManager, serverName string) *MapRemoteProxy {
	// Default policies from the server config, if they exist
	serverConfig := config.Servers[serverName]
	policies := config.ResolvePolicies(serverConfig, &Mapping{}, nil) // Get server-level or default policies

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second, // This is connection timeout, should be kept reasonable
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       policies.IdleTimeout, // Apply IdleTimeout from policies
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	tunnelTransport := NewTunnelRoundTripper(tunnelManager, transport)

	p := &MapRemoteProxy{
		config:        config,
		harManager:    harManager,
		tunnelManager: tunnelManager,
		serverName:    serverName,
		client: &http.Client{
			Transport: tunnelTransport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			// Timeout is now set per-request in handleHTTP
		},
	}

	// Initialize concurrency limiter if MaxThread is set at the server level
	if policies.MaxThread > 0 {
		p.concurrencyLimiter = make(chan struct{}, policies.MaxThread)
	}

	return p
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

	// Note: We don't resolve policies here because this client is for a specific upstream proxy,
	// not for a specific rule. The main request client's transport will handle idle timeouts.
	transport := &http.Transport{
		Proxy:           http.ProxyURL(parsedProxy),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second, // Keep a default for upstream proxy connections
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	tunnelTransport := NewTunnelRoundTripper(p.tunnelManager, transport)

	return &http.Client{
		Transport: tunnelTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 60 * time.Second,
	}, nil
}

func (p *MapRemoteProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 认证检查
	authorized, _ := p.checkAuth(r, nil)
	if !authorized {
		w.Header().Set("Proxy-Authenticate", `Basic realm="Restricted"`)
		http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
		return
	}

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