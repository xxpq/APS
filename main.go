package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	configFile := flag.String("config", "config.json", "Path to configuration file")
	flag.Parse()

	log.Println("===========================================")
	log.Println("  Cato Proxy Service")
	log.Println("===========================================")

	if err := InitCertificates(); err != nil {
		log.Fatalf("Failed to initialize certificates: %v", err)
	}

	config, err := LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	harManager := NewHarLoggerManager(config)
	defer harManager.Shutdown()

	// The main proxy logic is now handled by each server's handler
	// proxy := NewMapRemoteProxy(config, harLogger)

	watcher, err := NewConfigWatcher(*configFile, config)
	if err != nil {
		log.Fatalf("Failed to create config watcher: %v", err)
	}
	watcher.Start()
	defer watcher.Stop()

	startServers(config, harManager)

	log.Println("===========================================")
	log.Printf("Loaded %d mapping rules:", len(config.Mappings))
	for i, mapping := range config.Mappings {
		log.Printf("  [%d] %s -> %s (on %v)", i+1, mapping.GetFromURL(), mapping.GetToURL(), mapping.listenNames)
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
}

func startServers(config *Config, harManager *HarLoggerManager) {
	// 将 mappings 按 server name 分组
	serverMappings := make(map[string][]*Mapping)
	for i := range config.Mappings {
		mapping := &config.Mappings[i]
		for _, serverName := range mapping.listenNames {
			serverMappings[serverName] = append(serverMappings[serverName], mapping)
		}
	}

	// 为每个 server 创建并启动一个处理器
	for name, mappings := range serverMappings {
		serverConfig := config.Servers[name]
		if serverConfig == nil {
			continue
		}
		handler := createServerHandler(name, mappings, serverConfig, config, harManager)
		go startServer(name, serverConfig, handler)
	}
}

func createServerHandler(serverName string, mappings []*Mapping, serverConfig *ListenConfig, config *Config, harManager *HarLoggerManager) http.Handler {
	mux := http.NewServeMux()
	proxy := NewMapRemoteProxy(config, harManager, serverName)

	// 如果 cert 是 auto，注册证书下载处理器
	if certStr, ok := serverConfig.Cert.(string); ok && certStr == "auto" {
		certHandlers := &CertHandlers{}
		certHandlers.RegisterHandlers(mux)
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

func startServer(name string, config *ListenConfig, handler http.Handler) {
	addr := fmt.Sprintf(":%d", config.Port)
	server := &http.Server{Addr: addr, Handler: handler}

	log.Printf("Starting server '%s' on port %d", name, config.Port)

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
			if err := server.Serve(tlsListener); err != nil {
				log.Printf("Server '%s' (HTTPS) failed: %v", name, err)
			}
		}()
	} else {
		// HTTP server
		go func() {
			if err := server.ListenAndServe(); err != nil {
				log.Printf("Server '%s' (HTTP) failed: %v", name, err)
			}
		}()
	}
}