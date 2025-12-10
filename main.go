package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// ServerManager manages the lifecycle of multiple HTTP servers.
type ServerManager struct {
	servers       map[string]*http.Server
	tcpServers    map[string]*RawTCPServer  // Raw TCP servers
	muxes         map[string]*ConnectionMux // Connection multiplexers
	mu            sync.Mutex
	wg            sync.WaitGroup
	config        *Config
	configFile    string
	dataStore     *DataStore
	harManager    *HarLoggerManager
	tunnelManager TunnelManagerInterface
	scriptRunner  *ScriptRunner
	trafficShaper *TrafficShaper
	stats         *StatsCollector
	staticCache   *StaticCacheManager
	replayManager *ReplayManager
}

func NewServerManager(config *Config, configFile string, dataStore *DataStore, harManager *HarLoggerManager, tunnelManager TunnelManagerInterface, scriptRunner *ScriptRunner, trafficShaper *TrafficShaper, stats *StatsCollector, staticCache *StaticCacheManager, replayManager *ReplayManager) *ServerManager {
	return &ServerManager{
		servers:       make(map[string]*http.Server),
		tcpServers:    make(map[string]*RawTCPServer),
		muxes:         make(map[string]*ConnectionMux),
		config:        config,
		configFile:    configFile,
		dataStore:     dataStore,
		harManager:    harManager,
		tunnelManager: tunnelManager,
		scriptRunner:  scriptRunner,
		trafficShaper: trafficShaper,
		stats:         stats,
		staticCache:   staticCache,
		replayManager: replayManager,
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

	// Re-calculate mappings for this specific server
	serverMappings := make(map[string][]*Mapping)
	for i := range sm.config.Mappings {
		mapping := &sm.config.Mappings[i]
		for _, serverName := range mapping.serverNames {
			serverMappings[serverName] = append(serverMappings[serverName], mapping)
		}
	}

	// Check if this is a rawTCP server
	if serverConfig.RawTCP {
		tcpServer := NewRawTCPServer(name, serverConfig, sm.config, serverMappings[name],
			sm.tunnelManager, sm.trafficShaper, sm.stats, sm.dataStore)
		if err := tcpServer.Start(); err != nil {
			log.Printf("Failed to start TCP server '%s': %v", name, err)
			return
		}
		sm.tcpServers[name] = tcpServer
		log.Printf("[RAW TCP] Server '%s' started on port %d", name, serverConfig.Port)
		return
	}

	// HTTP server
	handler := createServerHandler(name, serverMappings[name], serverConfig, sm.config, sm.configFile, sm.dataStore, sm.harManager, sm.tunnelManager, sm.scriptRunner, sm.trafficShaper, sm.stats, sm.staticCache, sm.replayManager, isACMEEnabled)
	server, mux := startServer(name, serverConfig, handler, sm.tunnelManager)
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

		log.Printf("Server '%s' stopped.", name)
		return
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
	dataFile := flag.String("data", "data.json", "Path to data file for quota persistence")
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

	dataStore, err := LoadDataStore(*dataFile)
	if err != nil {
		log.Fatalf("Failed to load data store: %v", err)
	}

	harManager := NewHarLoggerManager(config)
	defer harManager.Shutdown()

	tunnelManager := NewHybridTunnelManager(config, nil) // 使用混合隧道管理器
	scriptRunner := NewScriptRunner(config.Scripting)
	trafficShaper := NewTrafficShaper(dataStore.QuotaUsage)
	statsCollector := NewStatsCollector(config)

	// 初始化静态文件缓存管理器
	staticCache := NewStaticCacheManager(config.StaticCache)
	defer staticCache.Stop()

	// 设置tunnelManager的statsCollector，实现端点统计的集中式管理
	tunnelManager.SetStatsCollector(statsCollector)
	replayManager := NewReplayManager(config)

	serverManager := NewServerManager(config, *configFile, dataStore, harManager, tunnelManager, scriptRunner, trafficShaper, statsCollector, staticCache, replayManager)

	watcher, err := NewConfigWatcher(*configFile, config, serverManager)
	if err != nil {
		log.Fatalf("Failed to create config watcher: %v", err)
	}
	watcher.Start()
	defer watcher.Stop()

	serverManager.StartAll()

	startQuotaPersistence(dataStore, trafficShaper, *dataFile)

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

func createServerHandler(serverName string, mappings []*Mapping, serverConfig *ListenConfig, config *Config, configFile string, dataStore *DataStore, harManager *HarLoggerManager, tunnelManager TunnelManagerInterface, scriptRunner *ScriptRunner, trafficShaper *TrafficShaper, stats *StatsCollector, staticCache *StaticCacheManager, replayManager *ReplayManager, isACMEEnabled bool) http.Handler {
	mux := http.NewServeMux()
	proxy := NewMapRemoteProxy(config, dataStore, harManager, tunnelManager, scriptRunner, trafficShaper, stats, staticCache, serverName)

	// 如果 cert 是 auto，注册证书下载处理器
	if certStr, ok := serverConfig.Cert.(string); ok && certStr == "auto" {
		certHandlers := &CertHandlers{}
		certHandlers.RegisterHandlers(mux)
	}

	// 添加重放端点（始终可用）
	mux.HandleFunc("/.replay", replayManager.ServeHTTP)

	// 根据 panel 控制 /.api 与 /.admin 的注册
	if serverConfig.Panel != nil && *serverConfig.Panel {
		// 添加统计数据端点
		mux.HandleFunc("/.api/stats", stats.ServeHTTP)

		// 注册管理面板处理器
		adminHandlers := NewAdminHandlers(config, configFile)
		// TCP tunnel manager handles endpoints directly
		adminHandlers.RegisterHandlers(mux)
	}

	// 创建一个统一的处理器来处理所有请求
	var baseHandler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 代理请求 (CONNECT)
		if r.Method == http.MethodConnect {
			proxy.ServeHTTP(w, r)
			return
		}

		// 检查 mux 中是否有更具体的匹配 (例如证书下载页面或相对路径)
		handler, pattern := mux.Handler(r)
		if pattern != "" {
			handler.ServeHTTP(w, r)
			return
		}

		// 默认处理 HTTP 请求转发
		proxy.ServeHTTP(w, r)
	})

	// 如果是80端口，并且全局启用了ACME，则包装处理器以处理ACME挑战
	if serverConfig.Port == 80 && isACMEEnabled {
		baseHandler = GetACMEHandler(baseHandler)
	}

	// 使用 h2c 包裹处理器，以支持 HTTP/2
	return h2c.NewHandler(baseHandler, &http2.Server{})
}

func startServer(name string, config *ListenConfig, handler http.Handler, tunnelManager TunnelManagerInterface) (*http.Server, *ConnectionMux) {
	// Determine bind address based on 'public' (default: true)
	host := "127.0.0.1"
	if config.Public == nil || *config.Public {
		host = "0.0.0.0"
	}
	addr := fmt.Sprintf("%s:%d", host, config.Port)
	server := &http.Server{Handler: handler}

	log.Printf("Starting server '%s' on %s", name, addr)

	// Create listener manually
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("Failed to listen on %s for server '%s': %v", addr, name, err)
		return nil, nil
	}

	// Create ConnectionMux
	mux := NewConnectionMux(listener)

	// Setup Tunnel Handler
	mux.SetTunnelHandler(func(conn net.Conn) {
		tunnelManager.HandleTunnelConnection(conn)
	})

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
			} else if config.Cert == "auto" {
				tlsConfig.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
					return GenerateCertForHost(info.ServerName)
				}
			} else if config.Cert == "acme" {
				acmeTLSConfig := GetACMETLSConfig()
				if acmeTLSConfig == nil {
					log.Printf("ACME manager not initialized for server '%s', cannot start HTTPS server.", name)
					return
				}
				tlsConfig = acmeTLSConfig
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
func startQuotaPersistence(dataStore *DataStore, trafficShaper *TrafficShaper, dataFile string) {
	ticker := time.NewTicker(10 * time.Second)
	go func() {
		for range ticker.C {
			trafficShaper.quotas.Range(func(key, value interface{}) bool {
				sourceKey := key.(string)
				dataStore.mu.Lock()
				if tq, ok := value.(*TrafficQuota); ok {
					if _, ok := dataStore.QuotaUsage[sourceKey]; !ok {
						dataStore.QuotaUsage[sourceKey] = &QuotaUsageData{}
					}
					dataStore.QuotaUsage[sourceKey].TrafficUsed = tq.Used
				} else if rq, ok := value.(*RequestQuota); ok {
					if _, ok := dataStore.QuotaUsage[sourceKey]; !ok {
						dataStore.QuotaUsage[sourceKey] = &QuotaUsageData{}
					}
					dataStore.QuotaUsage[sourceKey].RequestsUsed = rq.Used
				}
				dataStore.mu.Unlock()
				return true
			})
			if err := SaveDataStore(dataStore, dataFile); err != nil {
				log.Printf("[QUOTA] Error saving quota usage: %v", err)
			}
		}
	}()
}
