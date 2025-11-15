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

	log.Println("===========================================")
	log.Printf("Proxy server: http://localhost:%s", *proxyPort)
	log.Printf("Certificate page: http://localhost:%s", *certPort)
	log.Println("===========================================")
	log.Printf("Loaded %d mapping rules:", len(config.Mappings))

	// 收集相对路径的 mappings 用于公共服务器
	publicServerMappings := make([]*Mapping, 0)
	
	for i, mapping := range config.Mappings {
		log.Printf("  [%d] %s -> %s", i+1, mapping.From, mapping.To)
		
		// 判断是否为相对路径且没有独立的 listen 配置
		fromURL := mapping.GetFromURL()
		isRelativePath := len(fromURL) > 0 && fromURL[0] == '/'
		hasNoListen := mapping.Listen == nil || mapping.Listen.Port == 0
		
		if mapping.Listen != nil && mapping.Listen.Port > 0 {
			// 有独立 listen 配置，启动独立代理
			go startDedicatedProxy(&mapping)
		} else if isRelativePath && hasNoListen && config.Server != nil {
			// 相对路径且没有 listen，分配给公共服务器
			publicServerMappings = append(publicServerMappings, &config.Mappings[i])
			log.Printf("    -> Assigned to public server")
		}
	}
	
	// 如果有公共服务器配置且有相对路径的 mappings，启动公共服务器
	if config.Server != nil && len(publicServerMappings) > 0 {
		log.Println("===========================================")
		log.Printf("Starting public server on port %d with %d mappings", config.Server.Port, len(publicServerMappings))
		go startPublicServer(config.Server, publicServerMappings)
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

func startDedicatedProxy(mapping *Mapping) {
	proxy := NewDedicatedProxy(mapping)
	addr := fmt.Sprintf(":%d", mapping.Listen.Port)
	server := &http.Server{Addr: addr, Handler: proxy}

	if mapping.Listen.Cert != nil {
		log.Printf("Starting dedicated HTTPS/HTTP proxy for %s on port %d", mapping.From, mapping.Listen.Port)

		go func() {
			tlsConfig := &tls.Config{}
			var err error

			if cert, ok := mapping.Listen.Cert.(CertFiles); ok {
				tlsConfig.Certificates = make([]tls.Certificate, 1)
				tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(cert.Cert, cert.Key)
				if err != nil {
					log.Printf("Failed to load certificate for %s: %v", mapping.From, err)
					return
				}
			} else if mapping.Listen.Cert == "auto" {
				tlsConfig.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
					return GenerateCertForHost(info.ServerName)
				}
			}

			listener, err := net.Listen("tcp", addr)
			if err != nil {
				log.Printf("Failed to listen on %s: %v", addr, err)
				return
			}

			tlsListener := NewTlsListener(listener, tlsConfig)
			if err := server.Serve(tlsListener); err != nil {
				log.Printf("Dedicated HTTPS/HTTP proxy for %s failed: %v", mapping.From, err)
			}
		}()
	} else {
		log.Printf("Starting dedicated HTTP proxy for %s on port %d", mapping.From, mapping.Listen.Port)
		go func() {
			if err := server.ListenAndServe(); err != nil {
				log.Printf("Dedicated HTTP proxy for %s failed: %v", mapping.From, err)
			}
		}()
	}
}

// startPublicServer 启动公共服务器，处理相对路径的 mappings
func startPublicServer(listenConfig *ListenConfig, mappings []*Mapping) {
	// 创建一个路由处理器
	mux := http.NewServeMux()
	
	// 为公共服务器创建一个专用的代理实例
	publicProxy := NewDedicatedProxy(nil)
	
	for _, mapping := range mappings {
		fromURL := mapping.GetFromURL()
		localPath := mapping.Local
		toURL := mapping.GetToURL()
		
		if localPath != "" {
			// 本地文件服务
			if len(fromURL) > 0 && fromURL[len(fromURL)-1] == '*' {
				// 通配符路径
				prefix := fromURL[:len(fromURL)-1]
				log.Printf("[PUBLIC SERVER] Registering file handler: %s -> %s", fromURL, localPath)
				
				mux.HandleFunc(prefix, func(w http.ResponseWriter, r *http.Request) {
					servePublicFile(w, r, mapping)
				})
			} else {
				// 精确路径
				log.Printf("[PUBLIC SERVER] Registering file handler: %s -> %s", fromURL, localPath)
				mux.HandleFunc(fromURL, func(w http.ResponseWriter, r *http.Request) {
					servePublicFile(w, r, mapping)
				})
			}
		} else if toURL != "" {
			// 代理转发服务
			if len(fromURL) > 0 && fromURL[len(fromURL)-1] == '*' {
				// 通配符路径
				prefix := fromURL[:len(fromURL)-1]
				log.Printf("[PUBLIC SERVER] Registering proxy handler: %s -> %s", fromURL, toURL)
				
				mux.HandleFunc(prefix, func(w http.ResponseWriter, r *http.Request) {
					servePublicProxy(w, r, mapping, publicProxy)
				})
			} else {
				// 精确路径
				log.Printf("[PUBLIC SERVER] Registering proxy handler: %s -> %s", fromURL, toURL)
				mux.HandleFunc(fromURL, func(w http.ResponseWriter, r *http.Request) {
					servePublicProxy(w, r, mapping, publicProxy)
				})
			}
		}
	}
	
	addr := fmt.Sprintf(":%d", listenConfig.Port)
	server := &http.Server{Addr: addr, Handler: mux}
	
	if listenConfig.Cert != nil {
		log.Printf("Starting public HTTPS/HTTP server on port %d with %d mappings", listenConfig.Port, len(mappings))
		
		tlsConfig := &tls.Config{}
		var err error
		
		if cert, ok := listenConfig.Cert.(CertFiles); ok {
			tlsConfig.Certificates = make([]tls.Certificate, 1)
			tlsConfig.Certificates[0], err = tls.LoadX509KeyPair(cert.Cert, cert.Key)
			if err != nil {
				log.Printf("Failed to load certificate for public server: %v", err)
				return
			}
		} else if listenConfig.Cert == "auto" {
			tlsConfig.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return GenerateCertForHost(info.ServerName)
			}
		}
		
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			log.Printf("Failed to listen on %s for public server: %v", addr, err)
			return
		}
		
		tlsListener := NewTlsListener(listener, tlsConfig)
		if err := server.Serve(tlsListener); err != nil {
			log.Printf("Public HTTPS/HTTP server failed: %v", err)
		}
	} else {
		log.Printf("Starting public HTTP server on port %d with %d mappings", listenConfig.Port, len(mappings))
		if err := server.ListenAndServe(); err != nil {
			log.Printf("Public HTTP server failed: %v", err)
		}
	}
}

// servePublicFile 为公共服务器提供文件服务
func servePublicFile(w http.ResponseWriter, r *http.Request, mapping *Mapping) {
	// 处理 OPTIONS 请求
	if r.Method == http.MethodOptions {
		setCorsHeaders(w.Header())
		
		// 如果有 to 配置的自定义 headers，也应用到 OPTIONS 响应
		toConfig := mapping.GetToConfig()
		if toConfig != nil && len(toConfig.Headers) > 0 {
			headers, _ := toConfig.GetAllHeaders()
			for key, value := range headers {
				w.Header().Set(key, value)
			}
		}
		
		w.WriteHeader(http.StatusOK)
		log.Printf("[PUBLIC SERVER OPTIONS] %s - Handled with CORS headers", r.URL.Path)
		return
	}
	
	localPath := mapping.Local
	fromURL := mapping.GetFromURL()
	
	// 处理通配符路径
	if len(fromURL) > 0 && fromURL[len(fromURL)-1] == '*' && len(localPath) > 0 && localPath[len(localPath)-1] == '*' {
		basePath := fromURL[:len(fromURL)-1]
		localBase := localPath[:len(localPath)-1]
		requestedPath := r.URL.Path[len(basePath):]
		localPath = localBase + requestedPath
	}
	
	// 尝试查找 index 文件
	localPath = findIndexFileForPublicServer(localPath)
	
	log.Printf("[PUBLIC SERVER] Serving file: %s -> %s", r.URL.Path, localPath)
	
	content, err := os.ReadFile(localPath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		log.Printf("[PUBLIC SERVER] Error reading file %s: %v", localPath, err)
		return
	}
	
	contentType := getMimeType(localPath)
	w.Header().Set("Content-Type", contentType)
	setCorsHeaders(w.Header())
	w.WriteHeader(http.StatusOK)
	w.Write(content)
}

// servePublicProxy 为公共服务器提供代理转发服务
func servePublicProxy(w http.ResponseWriter, r *http.Request, mapping *Mapping, proxy *DedicatedProxy) {
	// 处理 OPTIONS 请求
	if r.Method == http.MethodOptions {
		setCorsHeaders(w.Header())
		
		// 如果有 to 配置的自定义 headers，也应用到 OPTIONS 响应
		toConfig := mapping.GetToConfig()
		if toConfig != nil && len(toConfig.Headers) > 0 {
			headers, _ := toConfig.GetAllHeaders()
			for key, value := range headers {
				w.Header().Set(key, value)
			}
		}
		
		w.WriteHeader(http.StatusOK)
		log.Printf("[PUBLIC SERVER OPTIONS] %s - Handled with CORS headers", r.URL.Path)
		return
	}
	
	// 临时设置 mapping 到 proxy
	oldMapping := proxy.mapping
	proxy.mapping = mapping
	defer func() { proxy.mapping = oldMapping }()
	
	// 使用 DedicatedProxy 的 ServeHTTP 处理请求
	proxy.ServeHTTP(w, r)
}

// findIndexFileForPublicServer 如果路径是目录，尝试查找 index.html 或 index.htm
func findIndexFileForPublicServer(path string) string {
	// 检查路径是否为目录
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return path
	}

	// 按优先级尝试 index 文件
	indexFiles := []string{"index.html", "index.htm"}
	for _, indexFile := range indexFiles {
		indexPath := path + string(os.PathSeparator) + indexFile
		if _, err := os.Stat(indexPath); err == nil {
			log.Printf("[PUBLIC SERVER] Found %s for directory %s", indexFile, path)
			return indexPath
		}
	}

	// 没找到 index 文件，返回原路径
	return path
}
