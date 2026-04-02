package main

import (
	"container/list"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	_ "modernc.org/sqlite"
)

// ServerManager manages the lifecycle of multiple HTTP servers.
type ServerManager struct {
	servers    map[string]*http.Server
	tcpServers map[string]*RawTCPServer  // Raw TCP servers
	udpServers map[string]*RawUDPServer  // Raw UDP servers
	muxes      map[string]*ConnectionMux // Connection multiplexers
	mu         sync.Mutex
	wg         sync.WaitGroup
	config     *Config
	configFile string
	// dataStore     *DataStore // Removed, replaced by statsDB for persistence
	harManager     *HarLoggerManager
	tunnelManager  TunnelManagerInterface
	scriptRunner   *ScriptRunner
	trafficShaper  *TrafficShaper
	stats          *StatsCollector
	staticCache    *StaticCacheManager
	replayManager  *ReplayManager
	statsDB        *StatsDB
	loggingDB      *LoggingDB
	logBroadcaster *LogBroadcaster
	rateLimiter    *RateLimitEngine
}

type tunnelInboundConn struct {
	net.Conn
	serverName string
}

func (c *tunnelInboundConn) TunnelServerName() string {
	return c.serverName
}

func NewServerManager(config *Config, configFile string, harManager *HarLoggerManager, tunnelManager TunnelManagerInterface, scriptRunner *ScriptRunner, trafficShaper *TrafficShaper, stats *StatsCollector, staticCache *StaticCacheManager, replayManager *ReplayManager, statsDB *StatsDB, loggingDB *LoggingDB, logBroadcaster *LogBroadcaster) *ServerManager {
	rateLimiter := NewRateLimitEngine(config.RateLimitRules)
	// go rateLimiter.CleanupExpired() // RateLimitEngine handles cleanup internally or doesn't need explicit cleanup loop yet?
	// The new engine uses sync.Map and doesn't have a cleanup loop yet.
	// We should probably add one, but for now let's just initialize it.
	// The old one had CleanupExpired. The new one has trackers that might grow.
	// WindowTracker resets itself. Banned map might grow.
	// We can add a cleanup goroutine later if needed.

	return &ServerManager{
		servers:        make(map[string]*http.Server),
		tcpServers:     make(map[string]*RawTCPServer),
		udpServers:     make(map[string]*RawUDPServer),
		muxes:          make(map[string]*ConnectionMux),
		config:         config,
		configFile:     configFile,
		harManager:     harManager,
		tunnelManager:  tunnelManager,
		scriptRunner:   scriptRunner,
		trafficShaper:  trafficShaper,
		stats:          stats,
		staticCache:    staticCache,
		replayManager:  replayManager,
		statsDB:        statsDB,
		loggingDB:      loggingDB,
		logBroadcaster: logBroadcaster,
		rateLimiter:    rateLimiter,
	}
}

func (sm *ServerManager) Start(name string, serverConfig *ListenConfig, isACMEEnabled bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Check if already running (HTTP or TCP)
	if _, exists := sm.servers[name]; exists {
		log.Printf("Server '%s' is already running.", name)
		return
	}
	if _, exists := sm.tcpServers[name]; exists {
		log.Printf("TCP Server '%s' is already running.", name)
		return
	}
	if _, exists := sm.udpServers[name]; exists {
		log.Printf("UDP Server '%s' is already running.", name)
		return
	}

	// Re-calculate mappings for this specific server
	serverMappings := make(map[string][]*Mapping)
	for i := range sm.config.Mappings {
		mapping := &sm.config.Mappings[i]
		// First, add mappings that explicitly specify this server
		for _, serverName := range mapping.serverNames {
			serverMappings[serverName] = append(serverMappings[serverName], mapping)
		}

		// For rawTCP servers, also match by port if no explicit server assignment
		if (serverConfig.Type == ServerTypeTCP || serverConfig.Type == ServerTypeTCPUDP) && len(mapping.serverNames) == 0 {
			fromURL := mapping.GetFromURL()
			DebugLog("[TCP MAPPING] Checking mapping %s for server '%s' (port %d), serverNames=%v", fromURL, name, serverConfig.Port, mapping.serverNames)
			if strings.HasPrefix(fromURL, "tcp://") {
				// Parse the from URL to get the port
				if u, err := url.Parse(fromURL); err == nil {
					if portStr := u.Port(); portStr != "" {
						if mappingPort, err := strconv.Atoi(portStr); err == nil {
							DebugLog("[TCP MAPPING] Parsed port %d from %s, comparing with server port %d", mappingPort, fromURL, serverConfig.Port)
							if mappingPort == serverConfig.Port {
								serverMappings[name] = append(serverMappings[name], mapping)
								log.Printf("[RAW TCP] Auto-assigned mapping %s to server '%s' (port %d)", fromURL, name, serverConfig.Port)
							}
						}
					}
				}
			}
		}

		// For rawUDP servers, also match by port if no explicit server assignment
		if (serverConfig.Type == ServerTypeUDP || serverConfig.Type == ServerTypeTCPUDP || serverConfig.Type == ServerTypeHTTPUDP) && len(mapping.serverNames) == 0 {
			fromURL := mapping.GetFromURL()
			if strings.HasPrefix(fromURL, "udp://") {
				// Parse the from URL to get the port
				if u, err := url.Parse(fromURL); err == nil {
					if portStr := u.Port(); portStr != "" {
						if mappingPort, err := strconv.Atoi(portStr); err == nil {
							if mappingPort == serverConfig.Port {
								serverMappings[name] = append(serverMappings[name], mapping)
								log.Printf("[RAW UDP] Auto-assigned mapping %s to server  '%s' (port %d)", fromURL, name, serverConfig.Port)
							}
						}
					}
				}
			}
		}
	}

	// Start TCP Server if enabled (Type 1 or 4)
	if serverConfig.Type == ServerTypeTCP || serverConfig.Type == ServerTypeTCPUDP {
		tcpServer := NewRawTCPServer(name, serverConfig, sm.config, serverMappings[name],
			sm.tunnelManager, sm.trafficShaper, sm.stats, sm.loggingDB)
		if err := tcpServer.Start(); err != nil {
			log.Printf("Failed to start TCP server '%s': %v", name, err)
			// If TCP fails, we might still want to try UDP if it's combined?
			// For now, let's just log and continue, or return?
			// If it's pure TCP, we should probably return.
			if serverConfig.Type == ServerTypeTCP {
				return
			}
		} else {
			sm.tcpServers[name] = tcpServer
			log.Printf("[RAW TCP] Server '%s' started on port %d with %d mappings", name, serverConfig.Port, len(serverMappings[name]))
		}
	}

	// Start UDP Server if enabled (Type 3, 4, or 5)
	if serverConfig.Type == ServerTypeUDP || serverConfig.Type == ServerTypeTCPUDP || serverConfig.Type == ServerTypeHTTPUDP {
		udpServer := NewRawUDPServer(name, serverConfig, sm.config, serverMappings[name],
			sm.tunnelManager, sm.trafficShaper, sm.stats, sm.loggingDB)
		if err := udpServer.Start(); err != nil {
			log.Printf("Failed to start UDP server '%s': %v", name, err)
			if serverConfig.Type == ServerTypeUDP {
				return
			}
		} else {
			sm.udpServers[name] = udpServer
			log.Printf("[RAW UDP] Server '%s' started on port %d with %d mappings", name, serverConfig.Port, len(serverMappings[name]))
		}
	}

	// Start HTTP Server if enabled (Type 2 or 5)
	// Note: Type 0 defaults to HTTP in config processing, but here we check explicitly
	if serverConfig.Type == ServerTypeHTTP || serverConfig.Type == ServerTypeHTTPUDP {
		handler := createServerHandler(name, serverMappings[name], serverConfig, sm.config, sm.configFile, sm.harManager, sm.tunnelManager, sm.scriptRunner, sm.trafficShaper, sm.stats, sm.staticCache, sm.replayManager, isACMEEnabled, sm.statsDB, sm.loggingDB, sm.logBroadcaster, sm.rateLimiter)
		server, mux := startServer(name, serverConfig, handler, sm.rateLimiter)
		if server != nil {
			sm.servers[name] = server
			if mux != nil {
				sm.muxes[name] = mux
			}
			sm.wg.Add(1)
			go func() {
				defer sm.wg.Done()
				// The server's ListenAndServe/Serve method will block here.
				// When it returns (e.g., after Shutdown), the goroutine will exit.
			}()
		}
	}
}

func (sm *ServerManager) Stop(name string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Try to stop HTTP server
	if server, exists := sm.servers[name]; exists {
		log.Printf("Stopping server '%s'...", name)
		// Use a context to allow for a graceful shutdown.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Error shutting down server '%s': %v", name, err)
		}
		delete(sm.servers, name)

		if mux, exists := sm.muxes[name]; exists {
			mux.Stop()
			delete(sm.muxes, name)
		}

		log.Printf("HTTP Server '%s' stopped.", name)
	}

	// Try to stop TCP server
	if tcpServer, exists := sm.tcpServers[name]; exists {
		log.Printf("Stopping TCP server '%s'...", name)
		if err := tcpServer.Stop(); err != nil {
			log.Printf("Error stopping TCP server '%s': %v", name, err)
		}
		delete(sm.tcpServers, name)
		log.Printf("TCP Server '%s' stopped.", name)
	}

	// Try to stop UDP server
	if udpServer, exists := sm.udpServers[name]; exists {
		log.Printf("Stopping UDP server '%s'...", name)
		if err := udpServer.Stop(); err != nil {
			log.Printf("Error stopping UDP server '%s': %v", name, err)
		}
		delete(sm.udpServers, name)
		log.Printf("UDP Server '%s' stopped.", name)
	}
}

// UpdateRawTCPMappings updates mappings for all rawTCP servers (for config hot reload)
func (sm *ServerManager) UpdateRawTCPMappings() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Re-calculate mappings for all servers using the same logic as server startup
	serverMappings := make(map[string][]*Mapping)

	// First, collect mappings that explicitly specify servers
	for i := range sm.config.Mappings {
		mapping := &sm.config.Mappings[i]
		for _, serverName := range mapping.serverNames {
			serverMappings[serverName] = append(serverMappings[serverName], mapping)
		}
	}

	// Then, for each rawTCP server, also match TCP mappings by port
	for name, tcpServer := range sm.tcpServers {
		serverPort := tcpServer.config.Port

		// Look for TCP mappings without explicit server assignment that match this port
		for i := range sm.config.Mappings {
			mapping := &sm.config.Mappings[i]

			// Skip if already assigned via serverNames
			if len(mapping.serverNames) > 0 {
				continue
			}

			fromURL := mapping.GetFromURL()
			if !strings.HasPrefix(fromURL, "tcp://") {
				continue
			}

			// Parse the from URL to get the port
			u, err := url.Parse(fromURL)
			if err != nil {
				continue
			}

			portStr := u.Port()
			if portStr == "" {
				continue
			}

			mappingPort, err := strconv.Atoi(portStr)
			if err != nil {
				continue
			}

			// If ports match, add this mapping
			if mappingPort == serverPort {
				serverMappings[name] = append(serverMappings[name], mapping)
			}
		}
	}

	// Update each rawTCP server's mappings
	for name, tcpServer := range sm.tcpServers {
		tcpServer.UpdateMappings(serverMappings[name])
	}

	// Also update UDP mappings
	sm.UpdateUDPMappings()
}

// UpdateUDPMappings updates mappings for all rawUDP servers
func (sm *ServerManager) UpdateUDPMappings() {
	// Re-calculate mappings for all servers using the same logic as server startup
	serverMappings := make(map[string][]*Mapping)

	// First, collect mappings that explicitly specify servers
	for i := range sm.config.Mappings {
		mapping := &sm.config.Mappings[i]
		for _, serverName := range mapping.serverNames {
			serverMappings[serverName] = append(serverMappings[serverName], mapping)
		}
	}

	// Then, for each rawUDP server, also match UDP mappings by port
	for name, udpServer := range sm.udpServers {
		serverPort := udpServer.config.Port

		// Look for UDP mappings without explicit server assignment that match this port
		for i := range sm.config.Mappings {
			mapping := &sm.config.Mappings[i]

			// Skip if already assigned via serverNames
			if len(mapping.serverNames) > 0 {
				continue
			}

			fromURL := mapping.GetFromURL()
			if !strings.HasPrefix(fromURL, "udp://") {
				continue
			}

			// Parse the from URL to get the port
			u, err := url.Parse(fromURL)
			if err != nil {
				continue
			}

			portStr := u.Port()
			if portStr == "" {
				continue
			}

			mappingPort, err := strconv.Atoi(portStr)
			if err != nil {
				continue
			}

			// If ports match, add this mapping
			if mappingPort == serverPort {
				serverMappings[name] = append(serverMappings[name], mapping)
			}
		}
	}

	// Update each rawUDP server's mappings
	for name, udpServer := range sm.udpServers {
		udpServer.UpdateMappings(serverMappings[name])
	}
}

func (sm *ServerManager) StopAll() {
	sm.mu.Lock()
	names := make([]string, 0, len(sm.servers)+len(sm.tcpServers))
	for name := range sm.servers {
		names = append(names, name)
	}
	for name := range sm.tcpServers {
		names = append(names, name)
	}
	for name := range sm.udpServers {
		names = append(names, name)
	}
	// Muxes are stopped when their corresponding server is stopped, but we should ensure cleanup
	// No need to iterate muxes separately as they are keyed by server name
	sm.mu.Unlock()

	for _, name := range names {
		sm.Stop(name)
	}
	sm.wg.Wait()
}

func main() {
	configFile := flag.String("config", "config.json", "Path to configuration file")
	flag.Parse()

	log.Println("===========================================")
	log.Println("  Any Proxy Service (APS) v1.0.0")
	log.Println("===========================================")

	if err := InitCertificates(); err != nil {
		log.Fatalf("Failed to initialize certificates: %v", err)
	}

	config, err := LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	InitACME(config)

	// Initialize shared database
	db, err := sql.Open("sqlite", "aps.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Set connection pool settings for SQLite
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	log.Printf("[DB] Opened shared database: aps.db")

	// Initialize statistics module with shared database
	statsDB, err := NewStatsDB(db)
	if err != nil {
		log.Fatalf("Failed to initialize stats DB: %v", err)
	}
	defer statsDB.Close()

	// Initialize logging module with shared database
	loggingDB, err := NewLoggingDB(db)
	if err != nil {
		log.Fatalf("Failed to initialize logging DB: %v", err)
	}
	defer loggingDB.Close()

	//Initialize ASN cache with shared database
	globalASNCache, err = NewASNCache(db, 1000)
	if err != nil {
		log.Printf("[ASN] Failed to initialize ASN cache: %v (continuing without database caching)", err)
		// Create minimal cache without database
		globalASNCache = &ASNCache{
			memoryCache: make(map[string]*cacheEntry),
			lruList:     list.New(),
			maxEntries:  1000,
			httpClient: &http.Client{
				Timeout: 10 * time.Second,
			},
			apiURL: "https://api.ipapi.is/",
		}
	}

	// Initialize LogBroadcaster to capture logs for SSE
	logBroadcaster := NewLogBroadcaster(os.Stderr)
	log.SetOutput(logBroadcaster)

	// Load initial quota usage from DB
	initialQuotaUsage, err := statsDB.LoadAllQuotaUsage()
	if err != nil {
		log.Fatalf("Failed to load initial quota usage from DB: %v", err)
	}

	harManager := NewHarLoggerManager(config)
	defer harManager.Shutdown()

	tunnelManager := NewHybridTunnelManager(config, nil) // 使用混合隧道管理器
	scriptRunner := NewScriptRunner(config.Scripting)
	trafficShaper := NewTrafficShaper(initialQuotaUsage)
	statsCollector := NewStatsCollector(config)
	defer statsCollector.Close() // Ensure graceful shutdown of async stats workers

	// 初始化静态文件缓存管理器
	staticCache := NewStaticCacheManager(config.StaticCache)
	defer staticCache.Stop()

	// 设置tunnelManager的statsCollector，实现端点统计的集中式管理
	tunnelManager.SetStatsCollector(statsCollector)
	replayManager := NewReplayManager(config)

	serverManager := NewServerManager(config, *configFile, harManager, tunnelManager, scriptRunner, trafficShaper, statsCollector, staticCache, replayManager, statsDB, loggingDB, logBroadcaster)

	watcher, err := NewConfigWatcher(*configFile, config, serverManager)
	if err != nil {
		log.Fatalf("Failed to create config watcher: %v", err)
	}
	watcher.Start()
	defer watcher.Stop()

	serverManager.StartAll()

	// Start quota persistence (now saving to DB)
	startQuotaPersistence(trafficShaper, statsDB)
	startStatsCollection(statsCollector, statsDB)
	startLogCleanup(config, loggingDB)

	log.Println("===========================================")
	log.Printf("Loaded %d mapping rules:", len(config.Mappings))
	for i, mapping := range config.Mappings {
		log.Printf("  [%d] %s -> %s (on %v)", i+1, mapping.GetFromURL(), mapping.GetToURL(), mapping.serverNames)
	}
	log.Println("===========================================")
	fmt.Println()
	fmt.Println("🔐 HTTPS Interception Setup:")
	fmt.Println("   1. Configure your system or browser to use one of the proxy servers.")
	fmt.Println("   2. Visit '/.ssl' on any server with 'cert: \"auto\"' to download the root certificate.")
	fmt.Println()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan
	log.Println("\nShutting down servers...")
	serverManager.StopAll()
}

func (sm *ServerManager) StartAll() {
	sm.config.mu.RLock()
	defer sm.config.mu.RUnlock()

	// 检查是否有服务配置了ACME
	needsACMEChallengeServer := false
	for _, serverConfig := range sm.config.Servers {
		if certStr, ok := serverConfig.Cert.(string); ok && certStr == "acme" {
			needsACMEChallengeServer = true
			break
		}
	}

	// 如果需要ACME，确保有一个公共的80端口服务器
	if needsACMEChallengeServer {
		foundPort80 := false
		for _, serverConfig := range sm.config.Servers {
			if serverConfig.Port == 80 && (serverConfig.Public == nil || *serverConfig.Public) {
				foundPort80 = true
				break
			}
		}
		if !foundPort80 {
			log.Println("[ACME] No public server on port 80 found, creating one for ACME challenge.")
			acmeServerName := "acme_challenge_server"
			t := true
			sm.config.Servers[acmeServerName] = &ListenConfig{
				Port:   80,
				Public: &t,
			}
		}
	}

	// 将 mappings 按 server name 分组
	serverMappings := make(map[string][]*Mapping)
	for i := range sm.config.Mappings {
		mapping := &sm.config.Mappings[i]
		for _, serverName := range mapping.serverNames {
			serverMappings[serverName] = append(serverMappings[serverName], mapping)
		}
	}

	// 为每个 server 创建并启动一个处理器
	for name, serverConfig := range sm.config.Servers {
		if serverConfig == nil {
			continue
		}
		sm.Start(name, serverConfig, needsACMEChallengeServer)
	}
}

func createServerHandler(serverName string, mappings []*Mapping, serverConfig *ListenConfig, config *Config, configFile string, harManager *HarLoggerManager, tunnelManager TunnelManagerInterface, scriptRunner *ScriptRunner, trafficShaper *TrafficShaper, stats *StatsCollector, staticCache *StaticCacheManager, replayManager *ReplayManager, isACMEEnabled bool, statsDB *StatsDB, loggingDB *LoggingDB, logBroadcaster *LogBroadcaster, rateLimiter *RateLimitEngine) http.Handler {
	mux := http.NewServeMux()
	proxy := NewMapRemoteProxy(config, harManager, tunnelManager, scriptRunner, trafficShaper, stats, staticCache, loggingDB, serverName, rateLimiter)

	// 如果 cert 是 auto，注册证书下载处理器
	if certStr, ok := serverConfig.Cert.(string); ok && certStr == "auto" {
		certHandlers := &CertHandlers{}
		certHandlers.RegisterHandlers(mux)
	}

	// 注册 Auth 管理接口
	authHandlers := &AuthHandlers{}
	authHandlers.RegisterHandlers(mux)

	// 添加重放端点（始终可用）
	mux.HandleFunc("/.replay", replayManager.ServeHTTP)

	requireTunnelMTLS := serverConfig.TunnelMTLS != nil && *serverConfig.TunnelMTLS
	tunnelBound := isServerBoundToAnyTunnel(config, serverName)

	if tunnelBound {
		// HTTP CONNECT tunnel entry is only exposed on servers bound by tunnels.<name>.servers.
		mux.HandleFunc("/.tunnel", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect {
				http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
				return
			}
			if r.TLS == nil {
				http.Error(w, "TLS is required for /.tunnel", http.StatusUpgradeRequired)
				return
			}
			if requireTunnelMTLS {
				if len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
					http.Error(w, "mTLS client certificate required for /.tunnel", http.StatusForbidden)
					return
				}
			}
			if tunnelManager == nil {
				http.Error(w, "Tunnel manager unavailable", http.StatusServiceUnavailable)
				return
			}
			log.Printf("[TCP TUNNEL] CONNECT /.tunnel request from %s on server '%s'", r.RemoteAddr, serverName)

			hijacker, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
				return
			}

			conn, rw, err := hijacker.Hijack()
			if err != nil {
				log.Printf("[TCP TUNNEL] Failed to hijack CONNECT /.tunnel: %v", err)
				return
			}

			if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
				log.Printf("[TCP TUNNEL] Failed to write CONNECT /.tunnel response: %v", err)
				conn.Close()
				return
			}
			if err := rw.Flush(); err != nil {
				log.Printf("[TCP TUNNEL] Failed to flush CONNECT /.tunnel response: %v", err)
				conn.Close()
				return
			}
			log.Printf("[TCP TUNNEL] CONNECT /.tunnel upgraded for %s on server '%s'", r.RemoteAddr, serverName)

			go tunnelManager.HandleTunnelConnection(&tunnelInboundConn{
				Conn:       conn,
				serverName: serverName,
			})
		})
	} else {
		DebugLog("[TCP TUNNEL] Server '%s' is not bound by any tunnel; '/.tunnel' is not registered", serverName)
	}

	// 根据 panel 控制 /.api 与 /.admin 的注册
	if serverConfig.Panel != nil && *serverConfig.Panel {
		// 添加统计数据端点
		mux.HandleFunc("/.api/stats", stats.ServeHTTP)

		// 注册管理面板处理器
		adminHandlers := NewAdminHandlers(config, configFile, serverName, stats, statsDB, loggingDB, logBroadcaster, rateLimiter)
		// 设置tunnel管理器引用，用于查询endpoint状态
		adminHandlers.SetTunnelManager(tunnelManager)
		adminHandlers.RegisterHandlers(mux)
	}

	// 创建一个统一的处理器来处理所有请求
	var baseHandler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 检查 mux 中是否有更具体的匹配 (例如证书下载页面或相对路径)
		handler, pattern := mux.Handler(r)
		if pattern != "" {
			handler.ServeHTTP(w, r)
			return
		}

		// 代理请求 (CONNECT)
		if r.Method == http.MethodConnect {
			proxy.ServeHTTP(w, r)
			return
		}

		// 默认处理 HTTP 请求转发
		proxy.ServeHTTP(w, r)
	})

	// 如果是80端口，并且全局启用了ACME，则包装处理器以处理ACME挑战
	if serverConfig.Port == 80 && isACMEEnabled {
		baseHandler = GetACMEHandler(baseHandler)
	}

	// Configure HTTP/2 server with strict limits to prevent goroutine leaks
	http2Server := &http2.Server{
		MaxConcurrentStreams:         100,              // Limit concurrent streams per connection
		MaxReadFrameSize:             64 << 10,         // 64kb max frame size
		IdleTimeout:                  10 * time.Second, // Close idle connections
		MaxUploadBufferPerConnection: 64 << 10,         // 64kb buffer per connection
		MaxUploadBufferPerStream:     64 << 10,         // 64kb buffer per stream
	}

	// Use h2c with configured server
	return h2c.NewHandler(baseHandler, http2Server)
}

func isServerBoundToAnyTunnel(config *Config, serverName string) bool {
	if config == nil || config.Tunnels == nil || strings.TrimSpace(serverName) == "" {
		return false
	}
	for _, tunnel := range config.Tunnels {
		if tunnel == nil {
			continue
		}
		for _, boundServer := range tunnel.Servers {
			if strings.TrimSpace(boundServer) == strings.TrimSpace(serverName) {
				return true
			}
		}
	}
	return false
}

func configureTunnelMTLSForServer(name string, serverConfig *ListenConfig, tlsConfig *tls.Config) error {
	if serverConfig == nil || tlsConfig == nil {
		return nil
	}

	requireTunnelMTLS := serverConfig.TunnelMTLS != nil && *serverConfig.TunnelMTLS
	caPath := strings.TrimSpace(serverConfig.TunnelMTLSCA)

	if !requireTunnelMTLS && caPath == "" {
		return nil
	}
	if caPath == "" {
		return fmt.Errorf("server '%s': tunnelMTLS requires tunnelMTLSCA", name)
	}

	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return fmt.Errorf("server '%s': failed to read tunnelMTLSCA '%s': %w", name, caPath, err)
	}
	clientCAPool := x509.NewCertPool()
	if !clientCAPool.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("server '%s': failed to parse tunnelMTLSCA '%s'", name, caPath)
	}

	tlsConfig.ClientCAs = clientCAPool
	if tlsConfig.ClientAuth < tls.VerifyClientCertIfGiven {
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
	}

	if requireTunnelMTLS {
		log.Printf("[TCP TUNNEL] Server '%s' requires mTLS on /.tunnel (CA: %s)", name, caPath)
	} else {
		log.Printf("[TCP TUNNEL] Server '%s' enables client cert verification for /.tunnel (CA: %s)", name, caPath)
	}

	return nil
}

func startServer(name string, config *ListenConfig, handler http.Handler, rateLimiter *RateLimitEngine) (*http.Server, *ConnectionMux) {
	// Determine bind address based on 'public' (default: true)
	host := "127.0.0.1"
	if config.Public == nil || *config.Public {
		host = "0.0.0.0"
	}
	addr := fmt.Sprintf("%s:%d", host, config.Port)
	server := &http.Server{
		Handler: handler,
		// WriteTimeout:      30 * time.Second, // Kill stuck writes after 30s
		ReadHeaderTimeout: 100 * time.Second, // Already set elsewhere, consolidating here
		IdleTimeout:       100 * time.Second, // Close idle connections
		ErrorLog:          newHTTPServerErrorLogger(log.Writer()),
	}

	log.Printf("Starting server '%s' on %s", name, addr)

	// Create listener manually
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("Failed to listen on %s for server '%s': %v", addr, name, err)
		return nil, nil
	}

	// Create ConnectionMux
	mux := NewConnectionMux(listener)
	mux.SetRateLimiter(rateLimiter, name, config.RateLimitRules)

	// Setup HTTP Handler
	httpListener := NewChannelListener(listener.Addr())
	mux.SetHTTPHandler(func(conn net.Conn) {
		httpListener.Push(conn)
	})

	// Start Mux
	go mux.Start()

	if config.Cert != nil {
		// HTTPS server
		go func() {
			tlsConfig := &tls.Config{}
			var err error

			if cert, ok := config.Cert.(CertFiles); ok {
				tlsConfig.Certificates = make([]tls.Certificate, 1)
				tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(cert.Cert, cert.Key)
				if err != nil {
					log.Printf("Failed to load certificate for server '%s': %v", name, err)
					return
				}
				registerTLSPinHash(&tlsConfig.Certificates[0])
			} else if config.Cert == "auto" {
				tlsConfig.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
					cert, certErr := GenerateCertForHost(info.ServerName)
					if certErr == nil && cert != nil {
						registerTLSPinHash(cert, info.ServerName)
					}
					return cert, certErr
				}
			} else if config.Cert == "acme" {
				acmeTLSConfig := GetACMETLSConfig()
				if acmeTLSConfig == nil {
					log.Printf("ACME manager not initialized for server '%s', cannot start HTTPS server.", name)
					return
				}
				tlsConfig = acmeTLSConfig.Clone()
				for i := range tlsConfig.Certificates {
					registerTLSPinHash(&tlsConfig.Certificates[i])
				}
				if tlsConfig.GetCertificate != nil {
					baseGetCertificate := tlsConfig.GetCertificate
					tlsConfig.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
						cert, certErr := baseGetCertificate(info)
						if certErr == nil && cert != nil {
							registerTLSPinHash(cert, info.ServerName)
						}
						return cert, certErr
					}
				}
			}

			if tlsConfig.MinVersion == 0 || tlsConfig.MinVersion < tls.VersionTLS12 {
				tlsConfig.MinVersion = tls.VersionTLS12
			}
			if err := configureTunnelMTLSForServer(name, config, tlsConfig); err != nil {
				log.Printf("Server '%s' TLS setup failed: %v", name, err)
				return
			}

			tlsListener := NewTlsListener(httpListener, tlsConfig)
			if err := server.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
				log.Printf("Server '%s' (HTTPS) failed: %v", name, err)
			}
		}()
	} else {
		// HTTP server
		go func() {
			if err := server.Serve(httpListener); err != nil && err != http.ErrServerClosed {
				log.Printf("Server '%s' (HTTP) failed: %v", name, err)
			}
		}()
	}
	return server, mux
}
func startQuotaPersistence(trafficShaper *TrafficShaper, statsDB *StatsDB) {
	ticker := time.NewTicker(10 * time.Second)
	go func() {
		for range ticker.C {
			trafficShaper.quotas.Range(func(key, value interface{}) bool {
				sourceKey := key.(string)
				var trafficUsed, requestsUsed int64
				if tq, ok := value.(*TrafficQuota); ok {
					trafficUsed = tq.Used
				}
				if rq, ok := value.(*RequestQuota); ok {
					requestsUsed = rq.Used
				}
				if err := statsDB.SaveQuotaUsage(sourceKey, trafficUsed, requestsUsed); err != nil {
					log.Printf("[QUOTA] Error saving quota usage to DB for %s: %v", sourceKey, err)
				}
				return true
			})
		}
	}()
}

func startStatsCollection(stats *StatsCollector, statsDB *StatsDB) {
	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		for range ticker.C {
			snapshot := TimeSeriesSnapshot{
				Timestamp: time.Now().Unix(),
				Global: GlobalStats{
					TotalRequests:     atomic.LoadUint64(&stats.TotalRequests),
					ActiveConnections: atomic.LoadInt64(&stats.ActiveConnections),
					BytesReceived:     atomic.LoadUint64(&stats.TotalBytesRecv),
					BytesSent:         atomic.LoadUint64(&stats.TotalBytesSent),
				},
				Rules:   make(map[string]*DimensionStats),
				Users:   make(map[string]*DimensionStats),
				Servers: make(map[string]*DimensionStats),
				Tunnels: make(map[string]*DimensionStats),
				Proxies: make(map[string]*DimensionStats),
			}

			// Calculate global QPS
			uptime := time.Since(stats.StartTime).Seconds()
			if uptime > 0 {
				snapshot.Global.RequestsPerSecond = float64(snapshot.Global.TotalRequests) / uptime
			}

			// Collect dimensional stats - Rules
			stats.RuleStats.Range(func(key, value interface{}) bool {
				k := key.(string)
				m := value.(*Metrics)
				snapshot.Rules[k] = extractDimensionStats(m)
				return true
			})

			// Collect dimensional stats - Users
			stats.UserStats.Range(func(key, value interface{}) bool {
				k := key.(string)
				m := value.(*Metrics)
				snapshot.Users[k] = extractDimensionStats(m)
				return true
			})

			// Collect dimensional stats - Servers
			stats.ServerStats.Range(func(key, value interface{}) bool {
				k := key.(string)
				m := value.(*Metrics)
				snapshot.Servers[k] = extractDimensionStats(m)
				return true
			})

			// Collect dimensional stats - Tunnels
			stats.TunnelStats.Range(func(key, value interface{}) bool {
				k := key.(string)
				m := value.(*Metrics)
				snapshot.Tunnels[k] = extractDimensionStats(m)
				return true
			})

			// Collect dimensional stats - Proxies
			stats.ProxyStats.Range(func(key, value interface{}) bool {
				k := key.(string)
				m := value.(*Metrics)
				snapshot.Proxies[k] = extractDimensionStats(m)
				return true
			})

			// Collect dimensional stats - IPs (Top 200)
			snapshot.IPs = stats.GetTopIPsAsDimensionStats(200)

			// Save to DB
			if err := statsDB.AddSnapshot(snapshot); err != nil {
				log.Printf("[STATS] Error saving snapshot to DB: %v", err)
			}
		}
	}()
}

// extractDimensionStats extracts dimension-specific statistics from Metrics
func extractDimensionStats(m *Metrics) *DimensionStats {
	requestCount := atomic.LoadUint64(&m.RequestCount)
	totalBytesRecv := atomic.LoadUint64(&m.BytesRecv.Total)
	totalBytesSent := atomic.LoadUint64(&m.BytesSent.Total)
	totalResponseTime := atomic.LoadInt64(&m.ResponseTime.Total)

	var avgRespTime float64
	if requestCount > 0 {
		avgRespTime = float64(totalResponseTime) / float64(requestCount) / 1e6 // Convert to ms
	}

	return &DimensionStats{
		Requests:    requestCount,
		BytesRecv:   totalBytesRecv,
		BytesSent:   totalBytesSent,
		Errors:      atomic.LoadUint64(&m.Errors),
		AvgRespTime: avgRespTime,

		// Protocol-specific statistics
		HTTPRequests:    atomic.LoadUint64(&m.HTTPRequests),
		HTTPSuccess:     atomic.LoadUint64(&m.HTTPSuccess),
		HTTPFailure:     atomic.LoadUint64(&m.HTTPFailure),
		RawTCPRequests:  atomic.LoadUint64(&m.RawTCPRequests),
		HTTPBytesSent:   atomic.LoadUint64(&m.HTTPBytesSent),
		HTTPBytesRecv:   atomic.LoadUint64(&m.HTTPBytesRecv),
		RawTCPBytesSent: atomic.LoadUint64(&m.RawTCPBytesSent),
		RawTCPBytesRecv: atomic.LoadUint64(&m.RawTCPBytesRecv),
	}
}

// startLogCleanup starts a goroutine that periodically cleans up old logs
func startLogCleanup(config *Config, loggingDB *LoggingDB) {
	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		for range ticker.C {
			// Get maximum retention hours from all dimensions
			// This ensures we don't delete logs that should still be retained
			retentionHours := getMaxRetentionHours(config)

			if err := loggingDB.CleanupOldLogs(retentionHours); err != nil {
				log.Printf("[LOGGING] Error cleaning up old logs: %v", err)
			} else {
				DebugLog("[LOGGING] Cleanup completed, retention=%d hours", retentionHours)
			}
		}
	}()
}
