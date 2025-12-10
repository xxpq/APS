package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
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
	serverAddr     = flag.String("server", "localhost:8081", "gRPC server address (e.g., 'your_proxy.com:8081')")
	name           = flag.String("name", "default-endpoint", "unique name for this endpoint client")
	tunnelName     = flag.String("tunnel", "", "name of the tunnel to connect to (must be defined in server config)")
	tunnelPassword = flag.String("password", "", "tunnel password for encryption")
	debug          = flag.Bool("debug", false, "enable debug logging")

	install   = flag.Bool("install", false, "install system service")
	uninstall = flag.Bool("uninstall", false, "uninstall system service")
	start     = flag.Bool("start", false, "start system service")
	stop      = flag.Bool("stop", false, "stop system service")
	restart   = flag.Bool("restart", false, "restart system service")
	protocol  = flag.String("protocol", "tcp", "tunnel protocol: tcp (default: tcp)")

	proxyConnections sync.Map // Stores map[string]net.Conn for proxy connections
	logger           service.Logger
)

var sharedClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:          1000,             // 最大空闲连接数
		MaxIdleConnsPerHost:   100,              // 每个主机最大空闲连接
		MaxConnsPerHost:       0,                // 0表示无限制
		IdleConnTimeout:       90 * time.Second, // 空闲连接超时
		TLSHandshakeTimeout:   10 * time.Second, // TLS握手超时
		ExpectContinueTimeout: 1 * time.Second,  // 100-continue超时
		DisableCompression:    true,             // 禁用压缩减少CPU开销
		ForceAttemptHTTP2:     true,             // 启用HTTP/2
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Timeout: 5 * time.Minute, // 请求总超时
}

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

	// When running as a service, flags are passed as arguments.
	// We need to re-parse them for the service process.
	flag.CommandLine.Parse(os.Args[1:])

	if *tunnelName == "" {
		if logger != nil {
			logger.Error("-tunnel flag is required")
		} else {
			log.Println("-tunnel flag is required")
		}
		return
	}

	go func() {
		for {
			select {
			case <-p.exit:
				cancel()
				return
			default:
				shouldReconnect := runClientSession(ctx)
				if !shouldReconnect {
					if logger != nil {
						logger.Info("Permanent error detected, stopping reconnection attempts.")
					} else {
						log.Println("Permanent error detected, stopping reconnection attempts.")
					}
					return
				}
				if logger != nil {
					logger.Infof("Session ended. Reconnecting in %v...", reconnectDelay)
				} else {
					log.Printf("Session ended. Reconnecting in %v...", reconnectDelay)
				}
				time.Sleep(reconnectDelay)
			}
		}
	}()

	<-p.exit
}

func (p *program) Stop(s service.Service) error {
	close(p.exit)
	return nil
}

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lshortfile)

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
	if *tunnelName == "" {
		log.Fatal("-tunnel flag is required in interactive mode")
	}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		for {
			select {
			case <-ctx.Done():
				log.Println("Context cancelled, shutting down.")
				return
			default:
				shouldReconnect := runClientSession(ctx)
				if !shouldReconnect {
					log.Printf("Permanent error detected, stopping reconnection attempts.")
					cancel()
					return
				}
				log.Printf("Session ended. Reconnecting in %v...", reconnectDelay)
				time.Sleep(reconnectDelay)
			}
		}
	}()

	<-interrupt
	log.Println("Interrupt received, shutting down.")
	cancel()

	time.Sleep(1 * time.Second)
	log.Println("Exiting.")
}

func createServiceConfig() (*service.Config, error) {
	serviceName := fmt.Sprintf("APS-Endpoint-%s", *name)
	displayName := fmt.Sprintf("APS Endpoint (%s)", *name)
	description := fmt.Sprintf("APS Endpoint service for endpoint '%s'.", *name)

	var args []string
	for _, arg := range os.Args[1:] {
		if arg != "-install" && arg != "-uninstall" && arg != "-start" && arg != "-stop" && arg != "-restart" {
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
	// Use TCP tunnel by default
	return runTCPTunnelSession(ctx)
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
