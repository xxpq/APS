package main

import (
	"bufio"
	"bytes"
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
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	pb "aps/tunnelpb"

	"github.com/kardianos/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

var (
	serverAddr     = flag.String("server", "localhost:8081", "gRPC server address (e.g., 'your_proxy.com:8081')")
	name           = flag.String("name", "default-endpoint", "unique name for this endpoint client")
	tunnelName     = flag.String("tunnel", "", "name of the tunnel to connect to (must be defined in server config)")
	tunnelPassword = flag.String("password", "", "tunnel password for encryption")
	debug          = flag.Bool("debug", false, "enable debug logging")
	relayMode      = flag.String("relay-mode", "direct", "relay mode: direct, relay, or hybrid (default: direct)")
	relayEndpoints = flag.String("relays", "", "comma-separated list of relay endpoints (e.g., 'relay1:18081,relay2:18081')")
	install        = flag.Bool("install", false, "install system service")
	uninstall      = flag.Bool("uninstall", false, "uninstall system service")
	start          = flag.Bool("start", false, "start system service")
	stop           = flag.Bool("stop", false, "stop system service")
	restart        = flag.Bool("restart", false, "restart system service")

	activeRequests   sync.Map   // Stores map[string]context.CancelFunc
	proxyConnections sync.Map   // Stores map[string]net.Conn for proxy connections
	streamMu         sync.Mutex // 保护gRPC stream.Send的并发调用
	relayManager     *RelayManager
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

	if *relayMode != "direct" {
		relayManager = NewRelayManager(*name, *serverAddr, RelayMode(*relayMode))
		if *relayEndpoints != "" {
			relays := strings.Split(*relayEndpoints, ",")
			for _, relay := range relays {
				relay = strings.TrimSpace(relay)
				if relay != "" {
					endpoint := &RelayEndpoint{
						Name:      relay,
						Address:   relay,
						Mode:      RelayModeRelay,
						Priority:  1,
						Available: true,
						LastCheck: time.Now(),
					}
					relayManager.AddRelayEndpoint(endpoint)
				}
			}
		}
		ctx := context.Background()
		if err := relayManager.Initialize(ctx); err != nil {
			log.Printf("Failed to initialize relay manager: %v", err)
		}
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

	if relayManager != nil {
		relayManager.Shutdown()
	}
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
	if *relayMode != "direct" && relayManager != nil {
		if err := relayManager.ConnectToServer(ctx); err == nil {
			log.Printf("Connected via relay mode: %s", *relayMode)
			return runRelayClientSession(ctx)
		}
		log.Printf("Relay connection failed, falling back to direct connection")
	}

	return runGRPCSession(ctx)
}

func runGRPCSession(ctx context.Context) bool {
	log.Printf("Connecting to gRPC server at %s", *serverAddr)
	conn, err := grpc.Dial(*serverAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(math.MaxInt64),
			grpc.MaxCallSendMsgSize(math.MaxInt64),
		),
	)
	if err != nil {
		log.Printf("Failed to connect: %v", err)
		return true
	}
	defer conn.Close()

	client := pb.NewTunnelServiceClient(conn)
	md := metadata.New(map[string]string{
		"tunnel-name":   *tunnelName,
		"endpoint-name": *name,
		"password":      *tunnelPassword,
		"x-aps-tunnel":  endpointVersion,
	})
	if *debug {
		log.Printf("[DEBUG] Connecting with metadata: %+v", md)
	}
	ctx = metadata.NewOutgoingContext(ctx, md)

	stream, err := client.Establish(ctx)
	if err != nil {
		log.Printf("Failed to establish stream: %v", err)
		if isPermanentError(err) {
			log.Printf("Permanent error detected, stopping reconnection attempts.")
			return false
		}
		return true
	}
	log.Println("Successfully established gRPC stream.")

	permanentErrorChan := make(chan error, 1)
	streamEnded := make(chan struct{})

	go func() {
		defer close(streamEnded)
		for {
			msg, err := stream.Recv()
			if err == io.EOF {
				log.Println("Server closed the stream.")
				return
			}
			if err != nil {
				log.Printf("Error receiving from stream: %v", err)
				if isPermanentError(err) {
					log.Printf("Permanent error detected in receive loop, stopping reconnection attempts.")
					select {
					case permanentErrorChan <- err:
					default:
					}
				}
				return
			}
			go handleServerMessage(stream, msg)
		}
	}()

	select {
	case err := <-permanentErrorChan:
		log.Printf("Received permanent error from receive loop: %v", err)
		return false
	case <-streamEnded:
		log.Printf("Stream ended.")
		select {
		case err := <-permanentErrorChan:
			log.Printf("Found permanent error after stream end: %v", err)
			return false
		default:
			return true
		}
	}
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

func handleServerMessage(stream pb.TunnelService_EstablishClient, msg *pb.ServerToEndpoint) {
	requestID := msg.GetId()
	switch payload := msg.Payload.(type) {
	case *pb.ServerToEndpoint_Request:
		// 使用goroutine异步处理请求，避免串行阻塞
		go handleRequest(stream, requestID, payload.Request)
	case *pb.ServerToEndpoint_Cancel:
		log.Printf("[CANCEL] Received cancellation for request %s", requestID)
		if cancelFunc, ok := activeRequests.Load(requestID); ok {
			cancelFunc.(context.CancelFunc)()
			activeRequests.Delete(requestID)
		}
	case *pb.ServerToEndpoint_ProxyConnect:
		// Handle proxy connection request from APS
		go handleProxyConnect(stream, payload.ProxyConnect)
	case *pb.ServerToEndpoint_ProxyData:
		// Handle proxy data from APS
		handleProxyData(payload.ProxyData)
	case *pb.ServerToEndpoint_ProxyClose:
		// Handle proxy close from APS
		handleProxyClose(payload.ProxyClose)
	}
}

func handleRequest(stream pb.TunnelService_EstablishClient, requestID string, reqPayload *pb.Request) {
	ctx, cancel := context.WithCancel(context.Background())
	activeRequests.Store(requestID, cancel)
	defer func() {
		cancel()
		activeRequests.Delete(requestID)
	}()

	if *debug {
		log.Printf("[DEBUG %s] Handling request, URL: %s, DataLen: %d", requestID, reqPayload.GetUrl(), len(reqPayload.GetData()))
	}

	decryptedData, err := decrypt(reqPayload.GetData(), *tunnelPassword)
	if err != nil {
		log.Printf("[ERROR %s] Error decrypting request: %v", requestID, err)
		sendStreamErrorResponse(stream, requestID, "decryption failed")
		return
	}

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(decryptedData)))
	if err != nil {
		log.Printf("[ERROR %s] Error reading request: %v", requestID, err)
		sendStreamErrorResponse(stream, requestID, "cannot read request")
		return
	}

	if *debug {
		var headers bytes.Buffer
		req.Header.Write(&headers)
		log.Printf("[DEBUG %s] Decrypted request headers:\n%s", requestID, headers.String())
	}

	targetURL, err := url.Parse(reqPayload.GetUrl())
	if err != nil {
		log.Printf("[ERROR %s] Error parsing target URL: %v", requestID, err)
		sendStreamErrorResponse(stream, requestID, "invalid target URL")
		return
	}
	req.URL = targetURL
	// req.Host is already correctly set by http.ReadRequest from the Host header.
	// We should not overwrite it with the IP address from targetURL.Host.
	req.RequestURI = ""
	req = req.WithContext(ctx)

	log.Printf("Forwarding request %s to %s (Host: %s)", requestID, req.URL.String(), req.Host)

	// Create a custom client to handle SNI and insecure connections for HTTPS requests.
	client := sharedClient
	if req.URL.Scheme == "https" {
		customTransport := sharedClient.Transport.(*http.Transport).Clone()
		if customTransport.TLSClientConfig != nil {
			customTransport.TLSClientConfig = customTransport.TLSClientConfig.Clone()
		} else {
			customTransport.TLSClientConfig = &tls.Config{}
		}

		// Set SNI from the Host header
		serverName := req.Host
		if strings.Contains(serverName, ":") {
			serverName = strings.Split(serverName, ":")[0]
		}
		customTransport.TLSClientConfig.ServerName = serverName

		// Check for an "X-Aps-Insecure" header to control InsecureSkipVerify.
		// This header is added by the proxy if "insecure: true" is set in the mapping.
		if insecureHeader := req.Header.Get("X-Aps-Insecure"); insecureHeader == "true" {
			customTransport.TLSClientConfig.InsecureSkipVerify = true
			if *debug {
				log.Printf("[DEBUG %s] InsecureSkipVerify enabled by X-Aps-Insecure header.", requestID)
			}
		}
		// We can now remove the header as it's served its purpose
		req.Header.Del("X-Aps-Insecure")

		client = &http.Client{
			Transport:     customTransport,
			CheckRedirect: sharedClient.CheckRedirect,
		}
		if *debug {
			log.Printf("[DEBUG %s] Custom TLS configured for host: %s, Insecure: %v", requestID, serverName, customTransport.TLSClientConfig.InsecureSkipVerify)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			log.Printf("[CANCEL %s] Request was cancelled locally.", requestID)
			return
		}
		log.Printf("[ERROR %s] Error executing request: %v", requestID, err)
		sendStreamErrorResponse(stream, requestID, err.Error())
		return
	}
	defer resp.Body.Close()

	if *debug {
		log.Printf("[DEBUG %s] Received response: %s", requestID, resp.Status)
		var headers bytes.Buffer
		resp.Header.Write(&headers)
		log.Printf("[DEBUG %s] Response headers:\n%s", requestID, headers.String())
	}

	// --- Start of Streaming Logic ---

	// 1. Send the response header first.
	headerBytes, err := httputil.DumpResponse(resp, false) // false means do not include body
	if err != nil {
		log.Printf("[ERROR %s] Error dumping response headers: %v", requestID, err)
		sendStreamErrorResponse(stream, requestID, "cannot dump response headers")
		return
	}

	encryptedHeader, err := encrypt(headerBytes, *tunnelPassword)
	if err != nil {
		log.Printf("[ERROR %s] Error encrypting response header: %v", requestID, err)
		sendStreamErrorResponse(stream, requestID, "header encryption failed")
		return
	}

	if err := sendResponsePart(stream, requestID, &pb.Response{
		Id:      requestID,
		Content: &pb.Response_Header{Header: &pb.ResponseHeader{Header: encryptedHeader}},
	}); err != nil {
		log.Printf("[ERROR %s] Error sending response header: %v", requestID, err)
		return
	}
	if *debug {
		log.Printf("[DEBUG %s] Sent response header, len: %d", requestID, len(encryptedHeader))
	}

	// 2. Stream the response body in chunks.
	buf := make([]byte, 128*1024) // 128KB chunks for better throughput
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			encryptedChunk, encErr := encrypt(buf[:n], *tunnelPassword)
			if encErr != nil {
				log.Printf("[ERROR %s] Error encrypting response chunk: %v", requestID, encErr)
				sendStreamErrorResponse(stream, requestID, "chunk encryption failed")
				return
			}
			if err := sendResponsePart(stream, requestID, &pb.Response{
				Id:      requestID,
				Content: &pb.Response_Chunk{Chunk: &pb.DataChunk{Data: encryptedChunk}},
			}); err != nil {
				log.Printf("[ERROR %s] Error sending response chunk: %v", requestID, err)
				return // Stop streaming if we can't send
			}
			if *debug {
				log.Printf("[DEBUG %s] Sent response chunk, len: %d", requestID, len(encryptedChunk))
			}
		}
		if err == io.EOF {
			break // End of body
		}
		if err != nil {
			log.Printf("[ERROR %s] Error reading response body: %v", requestID, err)
			sendStreamErrorResponse(stream, requestID, "error reading response body")
			return
		}
	}

	// 3. Send the end-of-stream message.
	if err := sendResponsePart(stream, requestID, &pb.Response{
		Id:      requestID,
		Content: &pb.Response_End{End: &pb.StreamEnd{}},
	}); err != nil {
		log.Printf("[ERROR %s] Error sending end-of-stream: %v", requestID, err)
		return
	}
	if *debug {
		log.Printf("[DEBUG %s] Sent end-of-stream message.", requestID)
	}
	// --- End of Streaming Logic ---
}

func sendResponsePart(stream pb.TunnelService_EstablishClient, requestID string, respPayload *pb.Response) error {
	msg := &pb.EndpointToServer{
		Payload: &pb.EndpointToServer_Response{
			Response: respPayload,
		},
	}
	// 使用互斥锁保护stream.Send，因为gRPC stream不是线程安全的
	streamMu.Lock()
	err := stream.Send(msg)
	streamMu.Unlock()
	if err != nil {
		log.Printf("Error sending response part for request %s: %v", requestID, err)
		return err
	}
	return nil
}

func sendStreamErrorResponse(stream pb.TunnelService_EstablishClient, requestID string, errorMsg string) {
	log.Printf("Sending stream error for request %s: %s", requestID, errorMsg)
	err := sendResponsePart(stream, requestID, &pb.Response{
		Id:      requestID,
		Content: &pb.Response_End{End: &pb.StreamEnd{Error: errorMsg}},
	})
	if err != nil {
		log.Printf("Failed to send stream error response for %s: %v", requestID, err)
	}
}

// Deprecated: use sendStreamErrorResponse instead for streaming.
func sendErrorResponse(stream pb.TunnelService_EstablishClient, requestID string, errorMsg string) {
	log.Printf("Sending error response for request %s: %s", requestID, errorMsg)
	err := sendResponsePart(stream, requestID, &pb.Response{Id: requestID, Content: &pb.Response_Error{Error: errorMsg}})
	if err != nil {
		log.Printf("Failed to send error response for %s: %v", requestID, err)
	}
}

// ===== Proxy Connection Handlers =====

// handleProxyConnect establishes a TCP connection to the target server
func handleProxyConnect(stream pb.TunnelService_EstablishClient, req *pb.ProxyConnect) {
	connID := req.GetConnectionId()
	host := req.GetHost()
	port := req.GetPort()
	// Note: tls field is ignored - endpoint is a pure TCP proxy
	// TLS handling is done by APS, not endpoint

	address := fmt.Sprintf("%s:%d", host, port)
	log.Printf("[PROXY %s] Connecting to %s (pure TCP proxy)", connID, address)

	// Establish raw TCP connection to target
	// Endpoint acts as a pure TCP proxy like SOCKS5 - no TLS handling
	conn, err := net.DialTimeout("tcp", address, 30*time.Second)

	// Send connection acknowledgement
	ack := &pb.ProxyConnectAck{
		ConnectionId: connID,
		Success:      err == nil,
	}
	if err != nil {
		ack.Error = err.Error()
		log.Printf("[PROXY %s] Connection failed: %v", connID, err)
	} else {
		log.Printf("[PROXY %s] Connection established to %s", connID, address)
		// Store the connection
		proxyConnections.Store(connID, conn)

		// Start reading from the connection
		go proxyReadLoop(stream, connID, conn)
	}

	// Send ack message
	streamMu.Lock()
	sendErr := stream.Send(&pb.EndpointToServer{
		Payload: &pb.EndpointToServer_ProxyConnectAck{
			ProxyConnectAck: ack,
		},
	})
	streamMu.Unlock()

	if sendErr != nil {
		log.Printf("[PROXY %s] Failed to send connect ack: %v", connID, sendErr)
		if conn != nil {
			conn.Close()
			proxyConnections.Delete(connID)
		}
	}
}

// handleProxyData writes data to the target connection
func handleProxyData(data *pb.ProxyData) {
	connID := data.GetConnectionId()

	log.Printf("[PROXY %s] Received %d bytes from APS to write to target", connID, len(data.GetData()))

	connVal, ok := proxyConnections.Load(connID)
	if !ok {
		log.Printf("[PROXY %s] Connection not found for data", connID)
		return
	}

	conn := connVal.(net.Conn)
	n, err := conn.Write(data.GetData())
	if err != nil {
		log.Printf("[PROXY %s] Write error: %v", connID, err)
		conn.Close()
		proxyConnections.Delete(connID)
	} else {
		log.Printf("[PROXY %s] Wrote %d bytes to target", connID, n)
	}
}

// handleProxyClose closes a proxy connection
func handleProxyClose(close *pb.ProxyClose) {
	connID := close.GetConnectionId()
	reason := close.GetReason()

	log.Printf("[PROXY %s] Closing connection: %s", connID, reason)

	connVal, ok := proxyConnections.Load(connID)
	if ok {
		conn := connVal.(net.Conn)
		conn.Close()
		proxyConnections.Delete(connID)
	}
}

// proxyReadLoop reads data from target connection and sends to APS
func proxyReadLoop(stream pb.TunnelService_EstablishClient, connID string, conn net.Conn) {
	log.Printf("[PROXY %s] Starting read loop for target connection", connID)

	defer func() {
		log.Printf("[PROXY %s] Read loop ended", connID)
		conn.Close()
		proxyConnections.Delete(connID)

		// Notify APS that connection is closed
		streamMu.Lock()
		stream.Send(&pb.EndpointToServer{
			Payload: &pb.EndpointToServer_ProxyClose{
				ProxyClose: &pb.ProxyClose{
					ConnectionId: connID,
					Reason:       "connection closed by endpoint",
				},
			},
		})
		streamMu.Unlock()
	}()

	buf := make([]byte, 32*1024) // 32KB buffer
	readCount := 0
	for {
		n, err := conn.Read(buf)
		readCount++
		if n > 0 {
			log.Printf("[PROXY %s] Read %d bytes from target (read #%d)", connID, n, readCount)
			data := &pb.ProxyData{
				ConnectionId: connID,
				Data:         buf[:n],
			}

			streamMu.Lock()
			sendErr := stream.Send(&pb.EndpointToServer{
				Payload: &pb.EndpointToServer_ProxyData{
					ProxyData: data,
				},
			})
			streamMu.Unlock()

			if sendErr != nil {
				log.Printf("[PROXY %s] Send error: %v", connID, sendErr)
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("[PROXY %s] Read error (read #%d): %v", connID, readCount, err)
			} else {
				log.Printf("[PROXY %s] Target connection closed (EOF) at read #%d", connID, readCount)
			}
			return
		}
	}
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

func runRelayClientSession(ctx context.Context) bool {
	log.Printf("Starting relay client session")
	stream := relayManager.relayClient.GetStream()
	if stream == nil {
		log.Printf("No relay stream available")
		return true
	}

	permanentErrorChan := make(chan error, 1)
	streamEnded := make(chan struct{})

	go func() {
		defer close(streamEnded)
		for {
			select {
			case <-ctx.Done():
				log.Println("Context cancelled, stopping relay receive loop.")
				return
			default:
				msg, err := stream.Recv()
				if err == io.EOF {
					log.Println("Relay server closed the stream.")
					return
				}
				if err != nil {
					log.Printf("Error receiving from relay stream: %v", err)
					if isPermanentError(err) {
						log.Printf("Permanent error detected in relay receive loop, stopping reconnection attempts.")
						select {
						case permanentErrorChan <- err:
						default:
						}
					}
					return
				}
				go handleServerMessage(stream, msg)
			}
		}
	}()

	select {
	case <-permanentErrorChan:
		return false
	case <-streamEnded:
		log.Printf("Relay stream ended.")
		select {
		case err := <-permanentErrorChan:
			log.Printf("Found permanent error after relay stream end: %v", err)
			return false
		default:
			return true
		}
	case <-ctx.Done():
		log.Printf("Context cancelled, closing relay connection.")
		return false
	}
}
