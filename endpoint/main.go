package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	pb "aps/tunnelpb"

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

	activeRequests sync.Map // Stores map[string]context.CancelFunc
	relayManager   *RelayManager
)

var sharedClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

const (
	endpointVersion = "1.0.0"
	reconnectDelay  = 5 * time.Second
)

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if *tunnelName == "" {
		log.Fatal("-tunnel flag is required")
	}

	// 初始化中继管理器
	if *relayMode != "direct" {
		relayManager = NewRelayManager(*name, *serverAddr, RelayMode(*relayMode))
		
		// 解析中继端点
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
					cancel() // 通知主循环退出
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
	
	// 关闭中继管理器
	if relayManager != nil {
		relayManager.Shutdown()
	}
	
	// Give time for the session to close gracefully
	time.Sleep(1 * time.Second)
	log.Println("Exiting.")
}

// runClientSession 运行一个客户端会话，返回是否应该重连
func runClientSession(ctx context.Context) bool {
	// 如果使用中继模式，先尝试中继连接
	if *relayMode != "direct" && relayManager != nil {
		if err := relayManager.ConnectToServer(ctx); err == nil {
			log.Printf("Connected via relay mode: %s", *relayMode)
			return runRelayClientSession(ctx)
		}
		log.Printf("Relay connection failed, falling back to direct connection")
	}

	// 使用原有的传输模式
	switch *transportMode {
	case "grpc":
		return runGRPCSession(ctx)
	case "ws":
		return runWebSocketSession(ctx)
	case "mix":
		// 先尝试gRPC，失败后再尝试WebSocket
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

// runGRPCSession 运行gRPC会话
func runGRPCSession(ctx context.Context) bool {
	log.Printf("Connecting to gRPC server at %s", *serverAddr)
	conn, err := grpc.Dial(*serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Printf("Failed to connect: %v", err)
		return false // gRPC连接失败，让上层处理fallback
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
		// 检查是否为永久性错误，如果是则不再重连
		if isPermanentError(err) {
			log.Printf("Permanent error detected, stopping reconnection attempts.")
			return false
		}
		return false // gRPC连接失败，让上层处理fallback
	}
	log.Println("Successfully established gRPC stream.")

	// 用于通知发生永久性错误的通道
	permanentErrorChan := make(chan error, 1)
	streamEnded := make(chan struct{})

	// Goroutine to receive messages from the server
	go func() {
		defer close(streamEnded) // 确保流结束时会通知
		for {
			msg, err := stream.Recv()
			if err == io.EOF {
				log.Println("Server closed the stream.")
				return
			}
			if err != nil {
				log.Printf("Error receiving from stream: %v", err)
				// 检查是否为永久性错误
				if isPermanentError(err) {
					log.Printf("Permanent error detected in receive loop, stopping reconnection attempts.")
					select {
					case permanentErrorChan <- err:
						// 成功发送永久性错误
					default:
						// 通道已有值，避免阻塞
					}
				}
				return
			}
			go handleServerMessage(stream, msg)
		}
	}()

	// 等待流结束或永久性错误
	select {
	case <-permanentErrorChan:
		// log.Printf("Received permanent error from receive loop: %v", err)
		os.Exit(1)
		return false // 永久性错误，不应该重试
	case <-streamEnded:
		log.Printf("Stream ended.")
		// 检查是否在流结束时还有永久性错误
		select {
		case err := <-permanentErrorChan:
			log.Printf("Found permanent error after stream end: %v", err)
			return false
		default:
			return true // 正常结束，应该重试
		}
	}
}

// isPermanentError 判断错误是否为永久性错误（如认证失败、隧道不存在等）
// runWebSocketSession 运行WebSocket会话
func runWebSocketSession(ctx context.Context) bool {
	log.Printf("Connecting to WebSocket server at %s", *serverAddr)
	
	// 创建WebSocket客户端
	wsClient := NewWebSocketClient(*serverAddr, *tunnelName, *name, *tunnelPassword, *debug)
	
	// 尝试连接
	if err := wsClient.Connect(); err != nil {
		log.Printf("Failed to connect to WebSocket: %v", err)
		return true // WebSocket连接失败，应该重试
	}
	defer wsClient.Disconnect()
	
	log.Println("Successfully established WebSocket connection.")
	
	// 用于通知发生永久性错误的通道
	permanentErrorChan := make(chan error, 1)
	streamEnded := make(chan struct{})
	
	// Goroutine to receive messages from the server
	go func() {
		defer close(streamEnded)
		
		// 设置ping ticker来检测连接状态
		pingTicker := time.NewTicker(30 * time.Second)
		defer pingTicker.Stop()
		
		for {
			select {
			case <-ctx.Done():
				log.Println("Context cancelled, stopping WebSocket receive loop.")
				return
			case <-pingTicker.C:
				// 定期发送ping消息来检测连接状态
				if !wsClient.IsConnected() {
					log.Printf("WebSocket connection detected as disconnected, stopping receive loop.")
					return
				}
				// 尝试发送ping消息
				if err := wsClient.Send([]byte("ping")); err != nil {
					log.Printf("WebSocket ping failed, connection likely broken: %v", err)
					return
				}
			default:
				// 接收WebSocket消息（带超时）
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
					// 解析消息
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
					// 接收超时，检查连接状态
					if !wsClient.IsConnected() {
						log.Printf("WebSocket connection timeout and not connected, stopping receive loop.")
						return
					}
				}
			}
		}
	}()
	
	// 等待流结束或永久性错误
	select {
	case <-permanentErrorChan:
		return false // 永久性错误，不应该重试
	case <-streamEnded:
		log.Printf("WebSocket connection ended.")
		return true // 正常结束，应该重试
	case <-ctx.Done():
		log.Printf("Context cancelled, closing WebSocket connection.")
		return false
	}
}

// handleServerMessageWebSocket 处理WebSocket服务器消息
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

// handleRequestWebSocket 处理WebSocket请求
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

	// 处理请求逻辑与gRPC版本相同
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
		// Log headers for debugging
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
	req.Host = targetURL.Host
	req.RequestURI = ""
	req = req.WithContext(ctx)

	log.Printf("Forwarding WebSocket request %s to %s", requestID, req.URL.String())

	resp, err := sharedClient.Do(req)
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

// sendResponseWebSocket 发送WebSocket响应
func sendResponseWebSocket(wsClient *WebSocketClient, requestID string, respPayload *pb.Response) {
	msg := &pb.EndpointToServer{
		Payload: &pb.EndpointToServer_Response{
			Response: respPayload,
		},
	}
	
	// 序列化消息
	data, err := proto.Marshal(msg)
	if err != nil {
		log.Printf("Error marshaling WebSocket response for request %s: %v", requestID, err)
		return
	}
	
	if err := wsClient.Send(data); err != nil {
		log.Printf("Error sending WebSocket response for request %s: %v", requestID, err)
	}
}

// sendSuccessResponseWebSocket 发送成功响应
func sendSuccessResponseWebSocket(wsClient *WebSocketClient, requestID string, data []byte) {
	if *debug {
		log.Printf("[DEBUG %s] Sending WebSocket success response, len: %d", requestID, len(data))
	}
	sendResponseWebSocket(wsClient, requestID, &pb.Response{Id: requestID, Content: &pb.Response_Data{Data: data}})
}

// sendErrorResponseWebSocket 发送错误响应
func sendErrorResponseWebSocket(wsClient *WebSocketClient, requestID string, errorMsg string) {
	log.Printf("Sending WebSocket error response for request %s: %s", requestID, errorMsg)
	sendResponseWebSocket(wsClient, requestID, &pb.Response{Id: requestID, Content: &pb.Response_Error{Error: errorMsg}})
}

func isPermanentError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	// 检查常见的永久性错误关键字
	permanentErrors := []string{
		"Unauthenticated",         // 认证失败
		"invalid tunnel password", // 密码错误
		"NotFound",                // 资源未找到（如隧道不存在）
		"already exists",          // 名称冲突
		"permission denied",       // 权限被拒绝
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
		// Log headers for debugging
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
	req.Host = targetURL.Host
	req.RequestURI = ""
	req = req.WithContext(ctx)

	log.Printf("Forwarding request %s to %s", requestID, req.URL.String())

	resp, err := sharedClient.Do(req)
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

// runRelayClientSession 运行中继客户端会话
func runRelayClientSession(ctx context.Context) bool {
	log.Printf("Starting relay client session")

	// 使用relayClient的流进行通信
	stream := relayManager.relayClient.GetStream()
	if stream == nil {
		log.Printf("No relay stream available")
		return true
	}

	// 用于通知发生永久性错误的通道
	permanentErrorChan := make(chan error, 1)
	streamEnded := make(chan struct{})

	// Goroutine to receive messages from the relay
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
					// 检查是否为永久性错误
					if isPermanentError(err) {
						log.Printf("Permanent error detected in relay receive loop, stopping reconnection attempts.")
						select {
						case permanentErrorChan <- err:
							// 成功发送永久性错误
						default:
							// 通道已有值，避免阻塞
						}
					}
					return
				}
				go handleServerMessage(stream, msg)
			}
		}
	}()

	// 等待流结束或永久性错误
	select {
	case <-permanentErrorChan:
		return false // 永久性错误，不应该重试
	case <-streamEnded:
		log.Printf("Relay stream ended.")
		// 检查是否在流结束时还有永久性错误
		select {
		case err := <-permanentErrorChan:
			log.Printf("Found permanent error after relay stream end: %v", err)
			return false
		default:
			return true // 正常结束，应该重试
		}
	case <-ctx.Done():
		log.Printf("Context cancelled, closing relay connection.")
		return false
	}
}
