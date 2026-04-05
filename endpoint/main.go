package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kardianos/service"
)

var (
	// New flags (recommended)
	configID = flag.String("cid", "", "Configuration ID to fetch from APS (recommended)")

	// Legacy flags (deprecated but supported)
	serverAddr     = flag.String("server", "", "APS server address(es) - single address or comma-separated list (addr:port,addr:port,...)")
	name           = flag.String("name", "default-endpoint", "[DEPRECATED] unique name for this endpoint client")
	tunnelName     = flag.String("tunnel", "", "[DEPRECATED] name of the tunnel to connect to")
	tunnelPassword = flag.String("password", "", "[DEPRECATED] tunnel password for encryption")
	mtlsCertFile   = flag.String("mtls-cert", "", "Client certificate PEM path for mTLS tunnel")
	mtlsKeyFile    = flag.String("mtls-key", "", "Client private key PEM path for mTLS tunnel")
	mtlsCAFile     = flag.String("mtls-ca", "", "Custom CA PEM bundle for APS tunnel TLS verification")
	debug          = flag.Bool("debug", false, "enable debug logging")
	logPath        = flag.String("log", "", "path to log file (optional)")

	install   = flag.Bool("install", false, "install system service")
	uninstall = flag.Bool("uninstall", false, "uninstall system service")
	reinstall = flag.Bool("reinstall", false, "reinstall system service")
	start     = flag.Bool("start", false, "start system service")
	stop      = flag.Bool("stop", false, "stop system service")
	restart   = flag.Bool("restart", false, "restart system service")

	proxyConnections sync.Map // Stores map[string]net.Conn for proxy connections
	logger           service.Logger
	logOutputFile    *os.File

	// Runtime configuration (loaded from APS when using -cid)
	runtimeConfig   *EndpointRuntimeConfig
	runtimeConfigMu sync.RWMutex
	usingLegacyMode bool

	portMapper        *PortMapper
	connectionManager *ConnectionManager // Manages multiple APS connections
)

var sharedClient = newSharedBackendHTTPClient()

const (
	endpointVersion    = "1.0.0"
	reconnectDelay     = 5 * time.Second
	windowsServicePath = "C:\\Windows\\System32\\apse.exe"
	unixServicePath    = "/usr/local/bin/apse"
)

type program struct {
	exit chan struct{}
}

func (p *program) Start(s service.Service) error {
	p.exit = make(chan struct{})
	go p.run()
	return nil
}

func (p *program) run() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer endpointSSHManager.Stop()

	// When running as a service, flags are passed as arguments.
	// We need to re-parse them for the service process.
	flag.CommandLine.Parse(os.Args[1:])

	// Initialize configuration based on mode
	if err := initializeConfiguration(); err != nil {
		if logger != nil {
			logger.Error(err)
		} else {
			log.Println(err)
		}
		return
	}

	// Service mode now follows the same multi-seed concurrent model as interactive mode.
	serverAddrs := parseServerAddresses(*serverAddr)
	if len(serverAddrs) == 0 {
		if logger != nil {
			logger.Error("No server addresses specified")
		} else {
			log.Println("No server addresses specified")
		}
		return
	}

	globalCID := ""
	if *configID != "" {
		globalCID = *configID
	}

	connectionManager = NewConnectionManager(globalCID)
	for _, addr := range serverAddrs {
		cfg := connectionManager.ParseServerAddress(addr, true)
		connectionManager.AddSeedServer(cfg)
	}

	// Prime TLS pin cache for all seed servers before starting any APS requests.
	for _, addr := range connectionManager.GetAllServers() {
		if err := PrimeTLSPinForServer(addr); err != nil {
			if logger != nil {
				logger.Errorf("Failed to initialize TLS pin for server %s: %v", addr, err)
			} else {
				log.Printf("Failed to initialize TLS pin for server %s: %v", addr, err)
			}
			return
		}
	}

	if logger != nil {
		logger.Infof("Connecting to %d seed server(s)", len(connectionManager.GetAllServers()))
	} else {
		log.Printf("Connecting to %d seed server(s)", len(connectionManager.GetAllServers()))
	}

	var wg sync.WaitGroup
	for _, addr := range connectionManager.GetAllServers() {
		wg.Add(1)
		go func(serverAddress string) {
			defer wg.Done()
			runServerConnection(ctx, serverAddress)
		}(addr)
	}

	<-p.exit
	cancel()
	if connectionManager != nil {
		connectionManager.CloseAll()
	}
	wg.Wait()
}

func (p *program) Stop(s service.Service) error {
	close(p.exit)
	return nil
}

func configureLogging() error {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetPrefix(fmt.Sprintf("[pid=%d] ", os.Getpid()))

	resolvedLogPath := strings.TrimSpace(*logPath)
	if resolvedLogPath == "" {
		return nil
	}

	logDir := filepath.Dir(resolvedLogPath)
	if logDir != "" && logDir != "." {
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return fmt.Errorf("failed to create log directory %s: %w", logDir, err)
		}
	}

	file, err := os.OpenFile(resolvedLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file %s: %w", resolvedLogPath, err)
	}

	log.SetOutput(file)
	logOutputFile = file
	log.Printf("Logging to file: %s", resolvedLogPath)
	return nil
}

func closeLogOutputFile() {
	if logOutputFile != nil {
		_ = logOutputFile.Close()
		logOutputFile = nil
	}
}

func main() {
	flag.Parse()
	if err := configureLogging(); err != nil {
		log.Fatalf("Failed to configure logging: %v", err)
	}
	defer closeLogOutputFile()

	if *install {
		err := installService()
		if err != nil {
			log.Fatalf("Failed to install service: %v", err)
		}
		log.Println("Service installed and started successfully.")
		return
	}

	cfg, err := createServiceConfig()
	if err != nil {
		log.Fatalf("Failed to create service config: %v", err)
	}

	prg := &program{}
	s, err := service.New(prg, cfg)
	if err != nil {
		log.Fatal(err)
	}

	if *uninstall {
		err := uninstallService(s)
		if err != nil {
			log.Fatalf("Failed to uninstall service: %v", err)
		}
		log.Println("Service uninstalled successfully.")
		return
	}

	if *reinstall {
		err := uninstallService(s)
		if err != nil {
			log.Printf("Failed to uninstall service: %v", err)
			log.Println("Continuing with reinstallation...")
		} else {
			log.Println("Service uninstalled successfully.")
		}
		err = installService()
		if err != nil {
			log.Fatalf("Failed to reinstall service: %v", err)
		}
		log.Println("Service reinstalled and started successfully.")
		return
	}

	if *start {
		err := s.Start()
		if err != nil {
			log.Fatalf("Failed to start service: %v", err)
		}
		log.Println("Service started successfully.")
		return
	}

	if *stop {
		err := s.Stop()
		if err != nil {
			log.Fatalf("Failed to stop service: %v", err)
		}
		log.Println("Service stopped successfully.")
		return
	}

	if *restart {
		err := s.Restart()
		if err != nil {
			log.Fatalf("Failed to restart service: %v", err)
		}
		log.Println("Service restarted successfully.")
		return
	}

	logger, err = s.Logger(nil)
	if err != nil {
		log.Fatal(err)
	}

	if !service.Interactive() {
		err = s.Run()
		if err != nil {
			logger.Error(err)
		}
		return
	}

	log.Println("Running in interactive mode")

	// Initialize configuration based on mode
	if err := initializeConfiguration(); err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())

	// Parse server addresses and initialize connection manager
	serverAddrs := parseServerAddresses(*serverAddr)
	if len(serverAddrs) == 0 {
		log.Fatalf("No server addresses specified")
	}

	// Determine global CID
	globalCID := ""
	if *configID != "" {
		globalCID = *configID
	}

	// Initialize connection manager
	connectionManager = NewConnectionManager(globalCID)

	// Add seed servers
	for _, addr := range serverAddrs {
		cfg := connectionManager.ParseServerAddress(addr, true)
		connectionManager.AddSeedServer(cfg)
	}

	// Prime TLS pin cache for all seed servers before starting any APS requests.
	for _, addr := range connectionManager.GetAllServers() {
		if err := PrimeTLSPinForServer(addr); err != nil {
			log.Fatalf("Failed to initialize TLS pin for server %s: %v", addr, err)
		}
	}

	log.Printf("Connecting to %d seed server(s)", len(serverAddrs))

	// Start a goroutine for each seed server connection
	var wg sync.WaitGroup
	for _, addr := range connectionManager.GetAllServers() {
		wg.Add(1)
		go func(serverAddress string) {
			defer wg.Done()
			runServerConnection(ctx, serverAddress)
		}(addr)
	}

	<-interrupt
	log.Println("Interrupt received, shutting down.")
	cancel()

	// Close all connections
	if connectionManager != nil {
		connectionManager.CloseAll()
	}
	endpointSSHManager.Stop()

	// Wait for all connections to close
	wg.Wait()
	time.Sleep(1 * time.Second)
	log.Println("Exiting.")
}

func createServiceConfig() (*service.Config, error) {
	var serviceNameSuffix string

	// Check if -name flag was explicitly set
	var isNameSet bool
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "name" {
			isNameSet = true
		}
	})

	// If using CID, try to fetch config to get the real endpoint name
	if *configID != "" {
		var fetchedName string
		if *serverAddr != "" {
			fmt.Println("Fetching configuration from APS...")

			var config *EndpointRuntimeConfig
			var err error
			for {
				config, err = FetchConfigFromAPS(*serverAddr, *configID)
				if err == nil && config != nil {
					fetchedName = config.EndpointName
					fmt.Printf("Successfully fetched configuration for endpoint: %s\n", fetchedName)
					break
				}
				fmt.Printf("Warning: Failed to fetch configuration: %v. Retrying in 10 seconds...\n", err)
				time.Sleep(10 * time.Second)
			}
		}

		if isNameSet {
			// User provided -name, use it for service name suffix (as requested)
			serviceNameSuffix = *name
		} else {
			// User didn't provide -name
			if fetchedName != "" {
				// Use fetched name
				serviceNameSuffix = fetchedName
			} else {
				// Fetch failed and no name provided
				return nil, fmt.Errorf("failed to fetch configuration and no -name specified. Please use -name to specify a service name suffix")
			}
		}
	} else {
		// Legacy mode (no CID), use -name (default or provided)
		serviceNameSuffix = *name
	}

	// Sanitize service name suffix to be safe for service name
	serviceNameSuffix = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return -1
	}, serviceNameSuffix)

	if serviceNameSuffix == "" {
		return nil, fmt.Errorf("service name suffix is empty after sanitization")
	}

	serviceName := fmt.Sprintf("APS-Endpoint-%s", serviceNameSuffix)
	displayName := fmt.Sprintf("APS Endpoint (%s)", serviceNameSuffix)
	description := fmt.Sprintf("APS Endpoint service for endpoint '%s'.", serviceNameSuffix)

	var args []string
	for _, arg := range os.Args[1:] {
		if arg != "-install" && arg != "-uninstall" && arg != "-reinstall" && arg != "-start" && arg != "-stop" && arg != "-restart" {
			args = append(args, arg)
		}
	}

	return &service.Config{
		Name:        serviceName,
		DisplayName: displayName,
		Description: description,
		Arguments:   args,
	}, nil
}

func installService() error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not get executable path: %w", err)
	}

	targetPath := getServiceTargetPath()
	if _, err := os.Stat(targetPath); os.IsNotExist(err) || !strings.EqualFold(execPath, targetPath) {
		fmt.Printf("Copying executable from %s to %s\n", execPath, targetPath)
		if err := copyFile(execPath, targetPath); err != nil {
			return fmt.Errorf("failed to copy executable to %s: %w", targetPath, err)
		}
	}

	cfg, err := createServiceConfig()
	if err != nil {
		return fmt.Errorf("failed to create service config: %w", err)
	}
	cfg.Executable = targetPath // Set the correct executable path for the service

	prg := &program{}
	s, err := service.New(prg, cfg)
	if err != nil {
		return fmt.Errorf("failed to create new service for install: %w", err)
	}

	if err := s.Install(); err != nil {
		return err
	}

	return s.Start()
}

func uninstallService(s service.Service) error {
	if err := s.Stop(); err != nil {
		// Ignore errors if the service is not running
	}
	if err := s.Uninstall(); err != nil {
		return fmt.Errorf("failed to uninstall service: %w", err)
	}

	targetPath := getServiceTargetPath()
	if _, err := os.Stat(targetPath); err == nil {
		fmt.Printf("Removing executable from %s\n", targetPath)
		if err := os.Remove(targetPath); err != nil {
			return fmt.Errorf("failed to remove executable from %s: %w", targetPath, err)
		}
	}
	return nil
}

func getServiceTargetPath() string {
	if runtime.GOOS == "windows" {
		return windowsServicePath
	}
	return unixServicePath
}

func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, sourceFile); err != nil {
		return err
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(dst, 0755); err != nil {
			return err
		}
	}
	return destFile.Sync()
}

func runClientSession(ctx context.Context) bool {
	connCtx, err := BuildImmutableConnectionContext(*serverAddr, *configID)
	if err != nil {
		log.Printf("Failed to build immutable connection context: %v", err)
		return true
	}
	// Use TCP tunnel by default
	return runTCPTunnelSession(ctx, *connCtx)
}

// parseServerAddresses parses comma-separated server addresses
func parseServerAddresses(serverAddrStr string) []string {
	if serverAddrStr == "" {
		return nil
	}

	// Split by comma and trim whitespace
	addrs := strings.Split(serverAddrStr, ",")
	var result []string
	for _, addr := range addrs {
		trimmed := strings.TrimSpace(addr)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// runServerConnection manages connection to a single APS server with retry logic
func runServerConnection(ctx context.Context, serverAddress string) {
	cfg := connectionManager.GetServerConfig(serverAddress)
	if cfg == nil {
		log.Printf("[%s] Server config not found", serverAddress)
		return
	}

	for {
		select {
		case <-ctx.Done():
			DebugLog("[%s] Context cancelled, shutting down.", serverAddress)
			return
		default:
			// Check if we should retry
			if !connectionManager.ShouldRetry(serverAddress) {
				log.Printf("[%s] Max retries reached, stopping.", serverAddress)
				connectionManager.RemoveServer(serverAddress)
				return
			}

			// Create context for this connection
			connCtx, connCancel := context.WithCancel(ctx)
			connectionManager.SetActive(serverAddress, connCancel)

			immutableCtx, buildErr := BuildImmutableConnectionContext(cfg.Address, cfg.ConfigID)
			if buildErr != nil {
				connectionManager.CloseConnection(serverAddress)
				connectionManager.IncrementRetry(serverAddress)
				log.Printf("[%s] Failed to build immutable connection context: %v", cfg.Address, buildErr)
				time.Sleep(reconnectDelay)
				continue
			}

			// Run the session with immutable context
			shouldReconnect := runTCPTunnelSession(connCtx, *immutableCtx)

			connectionManager.CloseConnection(serverAddress)
			if ctx.Err() != nil {
				DebugLog("[%s] Context cancelled after session exit, stop reconnect loop.", cfg.Address)
				return
			}

			if !shouldReconnect {
				log.Printf("[%s] Permanent error detected, stopping.", cfg.Address)
				if !cfg.IsSeed {
					connectionManager.RemoveServer(serverAddress)
				}
				return
			}

			// Increment retry counter
			connectionManager.IncrementRetry(serverAddress)

			// Log and sleep before retry
			retryInfo := ""
			if cfg.IsSeed {
				retryInfo = "seed - infinite retries"
			} else {
				retryInfo = fmt.Sprintf("dynamic - retry %d/5", cfg.RetryCount)
			}
			log.Printf("[%s] Session ended (%s). Reconnecting in %v...", cfg.Address, retryInfo, reconnectDelay)
			time.Sleep(reconnectDelay)
		}
	}
}

// runClientSessionWithServer runs a client session with a specific server address
func runClientSessionWithServer(ctx context.Context, serverAddress string) bool {
	connCtx, err := BuildImmutableConnectionContext(serverAddress, *configID)
	if err != nil {
		log.Printf("[%s] Failed to build immutable connection context: %v", serverAddress, err)
		return true
	}
	return runTCPTunnelSession(ctx, *connCtx)
}

func isPermanentError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	permanentErrors := []string{
		"Unauthenticated",
		"invalid tunnel password",
		"NotFound",
		"already exists",
		"permission denied",
	}
	for _, permErr := range permanentErrors {
		if strings.Contains(errStr, permErr) {
			return true
		}
	}
	return false
}

func createKey(password string) []byte {
	hash := sha256.Sum256([]byte(password))
	return hash[:]
}

func encrypt(data []byte, password string) ([]byte, error) {
	if password == "" {
		return data, nil
	}
	key := createKey(password)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func decrypt(data []byte, password string) ([]byte, error) {
	if password == "" {
		return data, nil
	}
	key := createKey(password)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
