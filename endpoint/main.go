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
				runClientSession(ctx)
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

func runClientSession(ctx context.Context) {
	log.Printf("Connecting to gRPC server at %s", *serverAddr)
	conn, err := grpc.Dial(*serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Printf("Failed to connect: %v", err)
		return
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
		return
	}
	log.Println("Successfully established gRPC stream.")

	// Goroutine to receive messages from the server
	go func() {
		for {
			msg, err := stream.Recv()
			if err == io.EOF {
				log.Println("Server closed the stream.")
				return
			}
			if err != nil {
				log.Printf("Error receiving from stream: %v", err)
				return
			}
			go handleServerMessage(stream, msg)
		}
	}()

	<-stream.Context().Done()
	log.Printf("Stream context done: %v", stream.Context().Err())
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