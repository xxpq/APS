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
	"strings"
	"os/signal"
	"sync"
	"syscall"
	"time"

	pb "aps/tunnelpb"
	"google.golang.org/grpc"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
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

func (sm *ServerManager) Start(name string, serverConfig *ListenConfig, isACMEEnabled bool) {
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

	handler := createServerHandler(name, serverMappings[name], serverConfig, sm.config, sm.configFile, sm.dataStore, sm.harManager, sm.tunnelManager, sm.scriptRunner, sm.trafficShaper, sm.stats, sm.replayManager, isACMEEnabled)
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

	InitACME(config)

	dataStore, err := LoadDataStore(*dataFile)
	if err != nil {
		log.Fatalf("Failed to load data store: %v", err)
	}

	harManager := NewHarLoggerManager(config)
	defer harManager.Shutdown()

	tunnelManager := NewTunnelManager(config, nil) // 先创建tunnelManager，statsCollector稍后再传入
	scriptRunner := NewScriptRunner(config.Scripting)
	trafficShaper := NewTrafficShaper(dataStore.QuotaUsage)
	statsCollector := NewStatsCollector(config)
	
	// 设置tunnelManager的statsCollector，实现端点统计的集中式管理
	tunnelManager.SetStatsCollector(statsCollector)
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

func createServerHandler(serverName string, mappings []*Mapping, serverConfig *ListenConfig, config *Config, configFile string, dataStore *DataStore, harManager *HarLoggerManager, tunnelManager *TunnelManager, scriptRunner *ScriptRunner, trafficShaper *TrafficShaper, stats *StatsCollector, replayManager *ReplayManager, isACMEEnabled bool) http.Handler {
	mux := http.NewServeMux()
	proxy := NewMapRemoteProxy(config, dataStore, harManager, tunnelManager, scriptRunner, trafficShaper, stats, serverName)

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
		adminHandlers.SetTunnelManager(tunnelManager)
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

	// 创建 gRPC 服务器
	grpcServer := grpc.NewServer()
	pb.RegisterTunnelServiceServer(grpcServer, &TunnelServiceServer{tunnelManager: tunnelManager})

	// 创建一个分流处理器，根据请求头判断流量导向 gRPC 隧道或 HTTP 处理器
	grpcOrHttpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 检查是否是 gRPC 隧道请求 (只检查是否存在 X-Aps-Tunnel header，具体版本验证在 gRPC handler 中进行)
		isGrpcTunnel := r.ProtoMajor == 2 &&
			strings.Contains(r.Header.Get("Content-Type"), "application/grpc") &&
			r.Header.Get("X-Aps-Tunnel") != ""

		if isGrpcTunnel {
			grpcServer.ServeHTTP(w, r)
		} else {
			baseHandler.ServeHTTP(w, r)
		}
	})

	// 使用 h2c 包裹处理器，以支持未加密的 HTTP/2 (h2c)
	return h2c.NewHandler(grpcOrHttpHandler, &http2.Server{})
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
			} else if config.Cert == "acme" {
				acmeTLSConfig := GetACMETLSConfig()
				if acmeTLSConfig == nil {
					log.Printf("ACME manager not initialized for server '%s', cannot start HTTPS server.", name)
					return
				}
				tlsConfig = acmeTLSConfig
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
