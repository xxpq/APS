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
	"strings"
	"syscall"
)

func main() {
	configFile := flag.String("config", "config.json", "Path to configuration file")
	proxyPort := flag.String("port", "8080", "Proxy server port")
	certPort := flag.String("cert-port", "9090", "Certificate download server port")
	dumpFile := flag.String("dump", "", "Path to HAR file to dump traffic")
	flag.StringVar(dumpFile, "d", "", "Path to HAR file to dump traffic (shorthand)")
	flag.Parse()

	log.Println("===========================================")
	log.Println("  Cato Proxy Service")
	log.Println("===========================================")

	if err := InitCertificates(); err != nil {
		log.Fatalf("Failed to initialize certificates: %v", err)
	}

	StartCertServer(*certPort)

	config, err := LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	var harLogger *HarLogger
	if *dumpFile != "" {
		harLogger = NewHarLogger()
		log.Printf("Dumping traffic to %s", *dumpFile)
	}

	proxy := NewMapRemoteProxy(config, harLogger)

	watcher, err := NewConfigWatcher(*configFile, config)
	if err != nil {
		log.Fatalf("Failed to create config watcher: %v", err)
	}
	watcher.Start()
	defer watcher.Stop()

	startServers(config)

	log.Println("===========================================")
	log.Printf("Proxy server: http://localhost:%s", *proxyPort)
	log.Printf("Certificate page: http://localhost:%s", *certPort)
	log.Println("===========================================")
	log.Printf("Loaded %d mapping rules:", len(config.Mappings))
	for i, mapping := range config.Mappings {
		log.Printf("  [%d] %s -> %s (on %v)", i+1, mapping.GetFromURL(), mapping.GetToURL(), mapping.listenNames)
	}

	log.Println("===========================================")
	fmt.Println()
	fmt.Println("🔐 HTTPS Interception Setup:")
	fmt.Printf("   1. Visit http://localhost:%s to download root certificate\n", *certPort)
	fmt.Println("   2. Install the certificate on your device")
	fmt.Printf("   3. Configure proxy: localhost:%s\n", *proxyPort)
	fmt.Println()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := http.ListenAndServe(":"+*proxyPort, proxy); err != nil {
			log.Fatalf("Proxy server failed: %v", err)
		}
	}()

	<-sigChan
	log.Println("\nShutting down proxy server...")

	if harLogger != nil {
		harLogger.SaveToFile(*dumpFile)
	}
}

func startServers(config *Config) {
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
		handler := createServerHandler(mappings, serverConfig.Port)
		go startServer(name, serverConfig, handler)
	}
}

func createServerHandler(mappings []*Mapping, port int) http.Handler {
	mux := http.NewServeMux()

	// 分离相对路径和绝对路径的 mapping
	var absoluteMappings []*Mapping
	for _, mapping := range mappings {
		fromURL := mapping.GetFromURL()
		if !strings.HasPrefix(fromURL, "http://") && !strings.HasPrefix(fromURL, "https://") {
			// 相对路径直接注册
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				proxy := NewDedicatedProxy(mapping, port)
				proxy.ServeHTTP(w, r)
			})
			mux.Handle(fromURL, handler)
			log.Printf("[SERVER] Registered mapping '%s' on port %d", fromURL, port)
		} else {
			absoluteMappings = append(absoluteMappings, mapping)
		}
	}

	// 为绝对路径创建一个统一的处理器
	if len(absoluteMappings) > 0 {
		absoluteHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 遍历绝对路径 mappings，找到匹配的
			for _, mapping := range absoluteMappings {
				// 简单的 host 匹配
				fromURL := mapping.GetFromURL()
				if strings.Contains(fromURL, r.Host) {
					proxy := NewDedicatedProxy(mapping, port)
					proxy.ServeHTTP(w, r)
					return
				}
			}
			// 如果没有匹配的，返回 404
			http.NotFound(w, r)
		})
		mux.Handle("/", absoluteHandler)
		log.Printf("[SERVER] Registered a catch-all handler on port %d for %d absolute URL mappings", port, len(absoluteMappings))
	}

	return mux
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