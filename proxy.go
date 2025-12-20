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
	config *Config
	// dataStore          *DataStore // Removed, no longer needed
	harManager    *HarLoggerManager
	tunnelManager TunnelManagerInterface
	scriptRunner  *ScriptRunner
	trafficShaper *TrafficShaper
	stats         *StatsCollector
	staticCache   *StaticCacheManager // 静态文件缓存管理器
	loggingDB     *LoggingDB          // 请求日志数据库
	serverName    string

	rateLimiter        *RateLimitEngine
	client             *http.Client
	concurrencyLimiter chan struct{}
	endpointTunnelMap  map[string]string // endpointName -> tunnelName
}

func NewMapRemoteProxy(config *Config, harManager *HarLoggerManager, tunnelManager TunnelManagerInterface, scriptRunner *ScriptRunner, trafficShaper *TrafficShaper, stats *StatsCollector, staticCache *StaticCacheManager, loggingDB *LoggingDB, serverName string, rateLimiter *RateLimitEngine) *MapRemoteProxy {
	// Default policies from the server config, if they exist
	serverConfig := config.Servers[serverName]
	policies := config.ResolvePolicies(serverConfig, &Mapping{}, nil, "") // Get server-level or default policies

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
		config:            config,
		harManager:        harManager,
		tunnelManager:     tunnelManager,
		scriptRunner:      scriptRunner,
		trafficShaper:     trafficShaper,
		stats:             stats,
		staticCache:       staticCache,
		loggingDB:         loggingDB,
		serverName:        serverName,
		rateLimiter:       rateLimiter,
		endpointTunnelMap: make(map[string]string),
		client: &http.Client{
			Transport: tunnelTransport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			// Timeout is now set per-request in handleHTTP
		},
	}

	// Build the endpoint -> tunnel reverse map
	if config.Auth != nil {
		if config.Auth.Users != nil {
			for _, user := range config.Auth.Users {
				endpoints := parseStringOrArray(user.Endpoint)
				tunnels := parseStringOrArray(user.Tunnel)
				if len(endpoints) > 0 && len(tunnels) > 0 {
					// Simple association: first tunnel for all endpoints in this user
					for _, ep := range endpoints {
						p.endpointTunnelMap[ep] = tunnels[0]
					}
				}
			}
		}
		if config.Auth.Groups != nil {
			for _, group := range config.Auth.Groups {
				endpoints := parseStringOrArray(group.Endpoint)
				tunnels := parseStringOrArray(group.Tunnel)
				if len(endpoints) > 0 && len(tunnels) > 0 {
					for _, ep := range endpoints {
						// User config takes precedence over group config
						if _, exists := p.endpointTunnelMap[ep]; !exists {
							p.endpointTunnelMap[ep] = tunnels[0]
						}
					}
				}
			}
		}
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
	// Check rate limit (Server level)
	if p.rateLimiter != nil {
		clientIP := getClientIP(r)

		// Get server rules
		serverConfig := p.config.Servers[p.serverName]
		var ruleNames []string
		if serverConfig != nil {
			ruleNames = serverConfig.RateLimitRules
		}

		if len(ruleNames) > 0 {
			bindings := map[string][]string{
				"server:" + p.serverName: ruleNames,
			}

			// We don't have token here yet, pass empty
			result := p.rateLimiter.CheckRequest(clientIP, "", bindings)
			if !result.Allowed {
				if result.Action == ActionRedirect {
					http.Redirect(w, r, result.RedirectURL, http.StatusFound)
					return
				}
				if result.Action == ActionQueue {
					// Simple queue implementation: sleep
					time.Sleep(result.WaitDuration)
					// Re-check? Or just allow?
					// Ideally we should re-check or just proceed.
					// For now, just sleep and proceed.
				} else {
					// Ban or default block
					http.Error(w, result.Message, http.StatusTooManyRequests)
					return
				}
			}

			// Record start for concurrency metric
			p.rateLimiter.OnRequestStart(clientIP, "", bindings)
		}
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
