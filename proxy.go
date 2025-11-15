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
	config        *Config
	harManager    *HarLoggerManager
	tunnelManager *TunnelManager
	serverName    string
	client        *http.Client
}

func NewMapRemoteProxy(config *Config, harManager *HarLoggerManager, tunnelManager *TunnelManager, serverName string) *MapRemoteProxy {
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

	tunnelTransport := NewTunnelRoundTripper(tunnelManager, transport)

	return &MapRemoteProxy{
		config:        config,
		harManager:    harManager,
		tunnelManager: tunnelManager,
		serverName:    serverName,
		client: &http.Client{
			Transport: tunnelTransport,
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