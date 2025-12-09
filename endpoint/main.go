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
	"google.golang.org/protobuf/proto"
)

var (
	serverAddr     = flag.String("server", "localhost:8081", "gRPC server address (e.g., 'your_proxy.com:8081')")
	name           = flag.String("name", "default-endpoint", "unique name for this endpoint client")
	tunnelName     = flag.String("tunnel", "", "name of the tunnel to connect to (must be defined in server config)")
	tunnelPassword = flag.String("password", "", "tunnel password for encryption")
	debug          = flag.Bool("debug", false, "enable debug logging")
	transportMode  = flag.String("transport", "mix", "transport mode: grpc, ws, or mix (default: mix)")
	relayMode      = flag.String("relay-mode", "direct", "relay mode: direct, relay, or hybrid (default: direct)")
	relayEndpoints = flag.String("relays", "", "comma-separated list of relay endpoints (e.g., 'relay1:18081,relay2:18081')")
	install        = flag.Bool("install", false, "install system service")
	uninstall      = flag.Bool("uninstall", false, "uninstall system service")
	start          = flag.Bool("start", false, "start system service")
	stop           = flag.Bool("stop", false, "stop system service")
	restart        = flag.Bool("restart", false, "restart system service")

	activeRequests sync.Map // Stores map[string]context.CancelFunc
	relayManager   *RelayManager
	logger         service.Logger
)

var sharedClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
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

	switch *transportMode {
	case "grpc":
		return runGRPCSession(ctx)
	case "ws":
		return runWebSocketSession(ctx)
	case "mix":
		if success := runGRPCSession(ctx); !success {
			log.Printf("gRPC connection failed, falling back to WebSocket")
			return runWebSocketSession(ctx)
		}
		return true
	default:
		log.Printf("Invalid transport mode: %s, using mix mode", *transportMode)
		return runGRPCSession(ctx)
	}
}

func runGRPCSession(ctx context.Context) bool {
	log.Printf("Connecting to gRPC server at %s", *serverAddr)
	conn, err := grpc.Dial(*serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
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

func runWebSocketSession(ctx context.Context) bool {
	log.Printf("Connecting to WebSocket server at %s", *serverAddr)
	wsClient := NewWebSocketClient(*serverAddr, *tunnelName, *name, *tunnelPassword, *debug)
	if err := wsClient.Connect(); err != nil {
		log.Printf("Failed to connect to WebSocket: %v", err)
		return true
	}
	defer wsClient.Disconnect()
	log.Println("Successfully established WebSocket connection.")

	permanentErrorChan := make(chan error, 1)
	streamEnded := make(chan struct{})

	go func() {
		defer close(streamEnded)
		pingTicker := time.NewTicker(30 * time.Second)
		defer pingTicker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Println("Context cancelled, stopping WebSocket receive loop.")
				return
			case <-pingTicker.C:
				if !wsClient.IsConnected() {
					log.Printf("WebSocket connection detected as disconnected, stopping receive loop.")
					return
				}
				if err := wsClient.Send([]byte("ping")); err != nil {
					log.Printf("WebSocket ping failed, connection likely broken: %v", err)
					return
				}
			default:
				messageChan := make(chan []byte, 1)
				errChan := make(chan error, 1)
				go func() {
					message, err := wsClient.Receive()
					if err != nil {
						errChan <- err
						return
					}
					messageChan <- message
				}()

				select {
				case message := <-messageChan:
					var msg pb.ServerToEndpoint
					if err := proto.Unmarshal(message, &msg); err != nil {
						log.Printf("Error unmarshaling WebSocket message: %v", err)
						continue
					}
					go handleServerMessageWebSocket(wsClient, &msg)
				case err := <-errChan:
					if err.Error() == "context cancelled" {
						return
					}
					log.Printf("Error receiving from WebSocket: %v", err)
					return
				case <-time.After(5 * time.Second):
					if !wsClient.IsConnected() {
						log.Printf("WebSocket connection timeout and not connected, stopping receive loop.")
						return
					}
				}
			}
		}
	}()

	select {
	case <-permanentErrorChan:
		return false
	case <-streamEnded:
		log.Printf("WebSocket connection ended.")
		return true
	case <-ctx.Done():
		log.Printf("Context cancelled, closing WebSocket connection.")
		return false
	}
}

func handleServerMessageWebSocket(wsClient *WebSocketClient, msg *pb.ServerToEndpoint) {
	requestID := msg.GetId()
	switch payload := msg.Payload.(type) {
	case *pb.ServerToEndpoint_Request:
		handleRequestWebSocket(wsClient, requestID, payload.Request)
	case *pb.ServerToEndpoint_Cancel:
		log.Printf("[CANCEL] Received cancellation for request %s", requestID)
		if cancelFunc, ok := activeRequests.Load(requestID); ok {
			cancelFunc.(context.CancelFunc)()
			activeRequests.Delete(requestID)
		}
	}
}

func handleRequestWebSocket(wsClient *WebSocketClient, requestID string, reqPayload *pb.Request) {
	ctx, cancel := context.WithCancel(context.Background())
	activeRequests.Store(requestID, cancel)
	defer func() {
		cancel()
		activeRequests.Delete(requestID)
	}()

	if *debug {
		log.Printf("[DEBUG %s] Handling WebSocket request, URL: %s, DataLen: %d", requestID, reqPayload.GetUrl(), len(reqPayload.GetData()))
	}

	decryptedData, err := decrypt(reqPayload.GetData(), *tunnelPassword)
	if err != nil {
		log.Printf("[ERROR %s] Error decrypting request: %v", requestID, err)
		sendErrorResponseWebSocket(wsClient, requestID, "decryption failed")
		return
	}

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(decryptedData)))
	if err != nil {
		log.Printf("[ERROR %s] Error reading request: %v", requestID, err)
		sendErrorResponseWebSocket(wsClient, requestID, "cannot read request")
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
		sendErrorResponseWebSocket(wsClient, requestID, "invalid target URL")
		return
	}
	req.URL = targetURL
	// req.Host is already correctly set by http.ReadRequest from the Host header.
	// We should not overwrite it with the IP address from targetURL.Host.
	req.RequestURI = ""
	req = req.WithContext(ctx)

	log.Printf("Forwarding WebSocket request %s to %s (Host: %s)", requestID, req.URL.String(), req.Host)

	// Create a custom client to handle SNI for HTTPS requests to an IP address.
	// We need to set the ServerName in TLSClientConfig to the original hostname.
	client := sharedClient
	if req.URL.Scheme == "https" {
		// Clone the shared transport and customize it for this request.
		customTransport := sharedClient.Transport.(*http.Transport).Clone()

		// Since Transport.Clone performs a shallow copy of TLSClientConfig,
		// we must clone it to avoid modifying the shared client's config.
		if customTransport.TLSClientConfig != nil {
			customTransport.TLSClientConfig = customTransport.TLSClientConfig.Clone()
		} else {
			customTransport.TLSClientConfig = &tls.Config{}
		}

		// The original hostname is in req.Host. We need to strip the port if it exists.
		serverName := req.Host
		if strings.Contains(serverName, ":") {
			serverName = strings.Split(serverName, ":")[0]
		}
		customTransport.TLSClientConfig.ServerName = serverName

		client = &http.Client{
			Transport:     customTransport,
			CheckRedirect: sharedClient.CheckRedirect,
		}
		if *debug {
			log.Printf("[DEBUG %s] Custom TLS SNI configured for host: %s", requestID, serverName)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			log.Printf("[CANCEL %s] Request was cancelled locally.", requestID)
			return
		}
		log.Printf("[ERROR %s] Error executing request: %v", requestID, err)
		sendErrorResponseWebSocket(wsClient, requestID, err.Error())
		return
	}
	defer resp.Body.Close()

	if *debug {
		log.Printf("[DEBUG %s] Received response: %s", requestID, resp.Status)
		var headers bytes.Buffer
		resp.Header.Write(&headers)
		log.Printf("[DEBUG %s] Response headers:\n%s", requestID, headers.String())
	}

	respData, err := httputil.DumpResponse(resp, true)
	if err != nil {
		log.Printf("[ERROR %s] Error dumping response: %v", requestID, err)
		sendErrorResponseWebSocket(wsClient, requestID, "cannot dump response")
		return
	}

	encryptedData, err := encrypt(respData, *tunnelPassword)
	if err != nil {
		log.Printf("[ERROR %s] Error encrypting response: %v", requestID, err)
		sendErrorResponseWebSocket(wsClient, requestID, "encryption failed")
		return
	}

	sendSuccessResponseWebSocket(wsClient, requestID, encryptedData)
}

func sendResponseWebSocket(wsClient *WebSocketClient, requestID string, respPayload *pb.Response) {
	msg := &pb.EndpointToServer{
		Payload: &pb.EndpointToServer_Response{
			Response: respPayload,
		},
	}
	data, err := proto.Marshal(msg)
	if err != nil {
		log.Printf("Error marshaling WebSocket response for request %s: %v", requestID, err)
		return
	}
	if err := wsClient.Send(data); err != nil {
		log.Printf("Error sending WebSocket response for request %s: %v", requestID, err)
	}
}

func sendSuccessResponseWebSocket(wsClient *WebSocketClient, requestID string, data []byte) {
	if *debug {
		log.Printf("[DEBUG %s] Sending WebSocket success response, len: %d", requestID, len(data))
	}
	sendResponseWebSocket(wsClient, requestID, &pb.Response{Id: requestID, Content: &pb.Response_Data{Data: data}})
}

func sendErrorResponseWebSocket(wsClient *WebSocketClient, requestID string, errorMsg string) {
	log.Printf("Sending WebSocket error response for request %s: %s", requestID, errorMsg)
	sendResponseWebSocket(wsClient, requestID, &pb.Response{Id: requestID, Content: &pb.Response_Error{Error: errorMsg}})
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
		handleRequest(stream, requestID, payload.Request)
	case *pb.ServerToEndpoint_Cancel:
		log.Printf("[CANCEL] Received cancellation for request %s", requestID)
		if cancelFunc, ok := activeRequests.Load(requestID); ok {
			cancelFunc.(context.CancelFunc)()
			activeRequests.Delete(requestID)
		}
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
		sendErrorResponse(stream, requestID, "decryption failed")
		return
	}

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(decryptedData)))
	if err != nil {
		log.Printf("[ERROR %s] Error reading request: %v", requestID, err)
		sendErrorResponse(stream, requestID, "cannot read request")
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
		sendErrorResponse(stream, requestID, "invalid target URL")
		return
	}
	req.URL = targetURL
	// req.Host is already correctly set by http.ReadRequest from the Host header.
	// We should not overwrite it with the IP address from targetURL.Host.
	req.RequestURI = ""
	req = req.WithContext(ctx)

	log.Printf("Forwarding request %s to %s (Host: %s)", requestID, req.URL.String(), req.Host)

	// Create a custom client to handle SNI for HTTPS requests to an IP address.
	// We need to set the ServerName in TLSClientConfig to the original hostname.
	client := sharedClient
	if req.URL.Scheme == "https" {
		// Clone the shared transport and customize it for this request.
		customTransport := sharedClient.Transport.(*http.Transport).Clone()

		// Since Transport.Clone performs a shallow copy of TLSClientConfig,
		// we must clone it to avoid modifying the shared client's config.
		if customTransport.TLSClientConfig != nil {
			customTransport.TLSClientConfig = customTransport.TLSClientConfig.Clone()
		} else {
			customTransport.TLSClientConfig = &tls.Config{}
		}

		// The original hostname is in req.Host. We need to strip the port if it exists.
		serverName := req.Host
		if strings.Contains(serverName, ":") {
			serverName = strings.Split(serverName, ":")[0]
		}
		customTransport.TLSClientConfig.ServerName = serverName

		client = &http.Client{
			Transport:     customTransport,
			CheckRedirect: sharedClient.CheckRedirect,
		}
		if *debug {
			log.Printf("[DEBUG %s] Custom TLS SNI configured for host: %s", requestID, serverName)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			log.Printf("[CANCEL %s] Request was cancelled locally.", requestID)
			return
		}
		log.Printf("[ERROR %s] Error executing request: %v", requestID, err)
		sendErrorResponse(stream, requestID, err.Error())
		return
	}
	defer resp.Body.Close()

	if *debug {
		log.Printf("[DEBUG %s] Received response: %s", requestID, resp.Status)
		var headers bytes.Buffer
		resp.Header.Write(&headers)
		log.Printf("[DEBUG %s] Response headers:\n%s", requestID, headers.String())
	}

	respData, err := httputil.DumpResponse(resp, true)
	if err != nil {
		log.Printf("[ERROR %s] Error dumping response: %v", requestID, err)
		sendErrorResponse(stream, requestID, "cannot dump response")
		return
	}

	encryptedData, err := encrypt(respData, *tunnelPassword)
	if err != nil {
		log.Printf("[ERROR %s] Error encrypting response: %v", requestID, err)
		sendErrorResponse(stream, requestID, "encryption failed")
		return
	}

	sendSuccessResponse(stream, requestID, encryptedData)
}

func sendResponse(stream pb.TunnelService_EstablishClient, requestID string, respPayload *pb.Response) {
	msg := &pb.EndpointToServer{
		Payload: &pb.EndpointToServer_Response{
			Response: respPayload,
		},
	}
	if err := stream.Send(msg); err != nil {
		log.Printf("Error sending response for request %s: %v", requestID, err)
	}
}

func sendSuccessResponse(stream pb.TunnelService_EstablishClient, requestID string, data []byte) {
	if *debug {
		log.Printf("[DEBUG %s] Sending success response, len: %d", requestID, len(data))
	}
	sendResponse(stream, requestID, &pb.Response{Id: requestID, Content: &pb.Response_Data{Data: data}})
}

func sendErrorResponse(stream pb.TunnelService_EstablishClient, requestID string, errorMsg string) {
	log.Printf("Sending error response for request %s: %s", requestID, errorMsg)
	sendResponse(stream, requestID, &pb.Response{Id: requestID, Content: &pb.Response_Error{Error: errorMsg}})
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