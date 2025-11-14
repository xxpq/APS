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

	for i, mapping := range config.Mappings {
		log.Printf("  [%d] %s -> %s", i+1, mapping.From, mapping.To)
		if mapping.Listen != nil && mapping.Listen.Port > 0 {
			go startDedicatedProxy(&mapping)
		}
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
