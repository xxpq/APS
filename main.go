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
)

// ServerManager manages the lifecycle of multiple HTTP servers.
type ServerManager struct {
	servers       map[string]*http.Server
	mu            sync.Mutex
	wg            sync.WaitGroup
	config        *Config
	configFile    string
	dataStore     *DataStore
	harManager    *HarLoggerManager
	tunnelManager *TunnelManager
	scriptRunner  *ScriptRunner
	trafficShaper *TrafficShaper
	stats         *StatsCollector
	replayManager *ReplayManager
}

func NewServerManager(config *Config, configFile string, dataStore *DataStore, harManager *HarLoggerManager, tunnelManager *TunnelManager, scriptRunner *ScriptRunner, trafficShaper *TrafficShaper, stats *StatsCollector, replayManager *ReplayManager) *ServerManager {
	return &ServerManager{
		servers:       make(map[string]*http.Server),
		config:        config,
		configFile:    configFile,
		dataStore:     dataStore,
		harManager:    harManager,
		tunnelManager: tunnelManager,
		scriptRunner:  scriptRunner,
		trafficShaper: trafficShaper,
		stats:         stats,
		replayManager: replayManager,
	}
}

func (sm *ServerManager) Start(name string, serverConfig *ListenConfig) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, exists := sm.servers[name]; exists {
		log.Printf("Server '%s' is already running.", name)
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

	handler := createServerHandler(name, serverMappings[name], serverConfig, sm.config, sm.configFile, sm.dataStore, sm.harManager, sm.tunnelManager, sm.scriptRunner, sm.trafficShaper, sm.stats, sm.replayManager)
	server := startServer(name, serverConfig, handler)
	if server != nil {
		sm.servers[name] = server
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

	if server, exists := sm.servers[name]; exists {
		log.Printf("Stopping server '%s'...", name)
		// Use a context to allow for a graceful shutdown.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Error shutting down server '%s': %v", name, err)
		}
		delete(sm.servers, name)
		log.Printf("Server '%s' stopped.", name)
	}
}

func (sm *ServerManager) StopAll() {
	sm.mu.Lock()
	names := make([]string, 0, len(sm.servers))
	for name := range sm.servers {
		names = append(names, name)
	}
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

	dataStore, err := LoadDataStore(*dataFile)
	if err != nil {
		log.Fatalf("Failed to load data store: %v", err)
	}

	harManager := NewHarLoggerManager(config)
	defer harManager.Shutdown()

	tunnelManager := NewTunnelManager(config)
	scriptRunner := NewScriptRunner(config.Scripting)
	trafficShaper := NewTrafficShaper(dataStore.QuotaUsage)
	statsCollector := NewStatsCollector(config)
	replayManager := NewReplayManager(config)

	serverManager := NewServerManager(config, *configFile, dataStore, harManager, tunnelManager, scriptRunner, trafficShaper, statsCollector, replayManager)

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
	// 将 mappings 按 server name 分组
	serverMappings := make(map[string][]*Mapping)
	sm.config.mu.RLock()
	for i := range sm.config.Mappings {
		mapping := &sm.config.Mappings[i]
		for _, serverName := range mapping.serverNames {
			serverMappings[serverName] = append(serverMappings[serverName], mapping)
		}
	}
	sm.config.mu.RUnlock()

	// 为每个 server 创建并启动一个处理器
	for name := range sm.config.Servers {
		serverConfig := sm.config.Servers[name]
		if serverConfig == nil {
			continue
		}
		sm.Start(name, serverConfig)
	}
}

func createServerHandler(serverName string, mappings []*Mapping, serverConfig *ListenConfig, config *Config, configFile string, dataStore *DataStore, harManager *HarLoggerManager, tunnelManager *TunnelManager, scriptRunner *ScriptRunner, trafficShaper *TrafficShaper, stats *StatsCollector, replayManager *ReplayManager) http.Handler {
	mux := http.NewServeMux()
	proxy := NewMapRemoteProxy(config, dataStore, harManager, tunnelManager, scriptRunner, trafficShaper, stats, serverName)

	// 检查此 server 是否为 tunnel 接入点
	if tunnel := tunnelManager.GetTunnelForServer(serverName); tunnel != nil {
		mux.HandleFunc("/.tunnel", func(w http.ResponseWriter, r *http.Request) {
			log.Printf("[TUNNEL] Incoming WebSocket connection for tunnel '%s' on server '%s'", tunnel.name, serverName)
			tunnelManager.ServeWs(tunnel, w, r)
		})
	}

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
		adminHandlers.RegisterHandlers(mux)
	}

	// 创建一个统一的处理器来处理所有请求
	mainHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	return mainHandler
}

func startServer(name string, config *ListenConfig, handler http.Handler) *http.Server {
	// Determine bind address based on 'public' (default: true)
	host := "127.0.0.1"
	if config.Public == nil || *config.Public {
		host = "0.0.0.0"
	}
	addr := fmt.Sprintf("%s:%d", host, config.Port)
	server := &http.Server{Addr: addr, Handler: handler}

	log.Printf("Starting server '%s' on %s", name, addr)

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
			}

			listener, err := net.Listen("tcp", addr)
			if err != nil {
				log.Printf("Failed to listen on %s for server '%s': %v", addr, name, err)
				return
			}

			tlsListener := NewTlsListener(listener, tlsConfig)
			if err := server.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
				log.Printf("Server '%s' (HTTPS) failed: %v", name, err)
			}
		}()
	} else {
		// HTTP server
		go func() {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("Server '%s' (HTTP) failed: %v", name, err)
			}
		}()
	}
	return server
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