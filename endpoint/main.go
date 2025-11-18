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
)

var (
	serverAddr     = flag.String("server", "localhost:8081", "gRPC server address (e.g., 'your_proxy.com:8081')")
	name           = flag.String("name", "default-endpoint", "unique name for this endpoint client")
	tunnelName     = flag.String("tunnel", "", "name of the tunnel to connect to (must be defined in server config)")
	tunnelPassword = flag.String("password", "", "tunnel password for encryption")
	debug          = flag.Bool("debug", false, "enable debug logging")

	activeRequests sync.Map // Stores map[string]context.CancelFunc
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
	// Give time for the session to close gracefully
	time.Sleep(1 * time.Second)
	log.Println("Exiting.")
}

// runClientSession 运行一个客户端会话，返回是否应该重连
func runClientSession(ctx context.Context) bool {
	log.Printf("Connecting to gRPC server at %s", *serverAddr)
	conn, err := grpc.Dial(*serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Printf("Failed to connect: %v", err)
		return true // 连接失败可能是网络问题，应该重试
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
		return true // 其他错误可能是暂时的，应该重试
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
