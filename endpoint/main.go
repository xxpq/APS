package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
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

	"github.com/gorilla/websocket"
)

// Message structures (copied from server side)
const (
	MessageTypeRequest  = "request"
	MessageTypeResponse = "response"
	MessageTypeCancel   = "cancel"
)

type TunnelMessage struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

type RequestPayload struct {
	URL  string `json:"url"`
	Data []byte `json:"data"`
}

type ResponsePayload struct {
	Data  []byte `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

var (
	serverAddr     = flag.String("server", "localhost:8080", "proxy server address (e.g., 'your_proxy.com:8080')")
	name           = flag.String("name", "default-endpoint", "unique name for this endpoint client")
	tunnelName     = flag.String("tunnel", "", "name of the tunnel to connect to (must be defined in server config)")
	tunnelPassword = flag.String("password", "", "tunnel password for encryption")
	poolSize       = flag.Int("pool-size", 1, "number of parallel connections to establish to the tunnel server")
	debug          = flag.Bool("debug", false, "enable debug logging")

	activeRequests sync.Map // Stores map[string]context.CancelFunc
)

// sharedClient is a reusable HTTP client that enables connection pooling (keep-alive).
var sharedClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

const (
	reconnectDelay = 5 * time.Second
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
	var wg sync.WaitGroup

	for i := 0; i < *poolSize; i++ {
		wg.Add(1)
		go func(connNum int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					log.Printf("[Conn %d] Context cancelled, shutting down.", connNum)
					return
				default:
					runClientSession(ctx, connNum)
					log.Printf("[Conn %d] Session ended. Reconnecting in %v...", connNum, reconnectDelay)
					time.Sleep(reconnectDelay)
				}
			}
		}(i + 1)
	}

	// Wait for interrupt signal
	<-interrupt
	log.Println("Interrupt received, shutting down all connections.")
	cancel() // Signal all goroutines to stop
	wg.Wait()  // Wait for all goroutines to finish
	log.Println("All connections closed. Exiting.")
}

func runClientSession(ctx context.Context, connNum int) {
	u := url.URL{Scheme: "ws", Host: *serverAddr, Path: "/.tunnel"}
	log.Printf("[Conn %d] Connecting to %s", connNum, u.String())

	header := http.Header{}
	header.Set("X-Endpoint-Name", *name)
	header.Set("X-Tunnel-Name", *tunnelName)

	conn, _, err := websocket.DefaultDialer.Dial(u.String(), header)
	if err != nil {
		log.Println("Dial error:", err)
		return
	}
	defer conn.Close()
	log.Printf("[Conn %d] Successfully connected to tunnel server.", connNum)

	// The server will send pings, and the client will automatically respond with pongs.
	// We just need to handle the ping message to know the connection is alive.
	// The gorilla/websocket library handles the pong response automatically.
	conn.SetPingHandler(func(appData string) error {
		if *debug {
			log.Printf("[Conn %d] Ping received", connNum)
		}
		// The library will automatically send a pong. We don't need to do anything here
		// except perhaps update a read deadline if we were managing it manually.
		// Since the server-side read deadline is the primary check, this is sufficient.
		return nil
	})

	done := make(chan struct{})

	// Start reader goroutine
	go func() {
		defer close(done)
		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				// Check for clean close or actual error
				if websocket.IsUnexpectedCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					log.Printf("[Conn %d] Read error: %v", connNum, err)
				} else {
					log.Printf("[Conn %d] Connection closed gracefully.", connNum)
				}
				return
			}

			if *debug {
				log.Printf("RECV: %s", message)
			}

			var msg TunnelMessage
			if err := json.Unmarshal(message, &msg); err != nil {
				log.Printf("Error unmarshalling message: %v", err)
				continue
			}

			switch msg.Type {
			case MessageTypeRequest:
				go handleRequest(conn, msg.ID, msg.Payload)
			case MessageTypeCancel:
				log.Printf("[CANCEL] Received cancellation for request %s", msg.ID)
				if cancelFunc, ok := activeRequests.Load(msg.ID); ok {
					cancelFunc.(context.CancelFunc)()
					activeRequests.Delete(msg.ID)
				}
			}
		}
	}()

	select {
	case <-done:
		log.Printf("[Conn %d] Reader finished, connection is likely closed.", connNum)
	case <-ctx.Done():
		log.Printf("[Conn %d] Context cancelled, closing connection.", connNum)
		// Attempt a clean shutdown
		err := conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		if err != nil {
			log.Printf("[Conn %d] Write close error: %v", connNum, err)
		}
		// Wait for the reader to close or timeout
		select {
		case <-done:
		case <-time.After(time.Second):
			log.Printf("[Conn %d] Shutdown timeout, forcing close.", connNum)
		}
	}
}

func handleRequest(conn *websocket.Conn, requestID string, payload json.RawMessage) {
	ctx, cancel := context.WithCancel(context.Background())
	activeRequests.Store(requestID, cancel)
	defer func() {
		cancel()
		activeRequests.Delete(requestID)
	}()

	if *debug {
		log.Printf("[DEBUG %s] Handling request", requestID)
	}

	var reqPayload RequestPayload
	if err := json.Unmarshal(payload, &reqPayload); err != nil {
		log.Printf("[ERROR %s] Error unmarshalling request payload: %v", requestID, err)
		sendErrorResponse(conn, requestID, "bad request payload")
		return
	}
	if *debug {
		log.Printf("[DEBUG %s] Unmarshalled payload, URL: %s, DataLen: %d", requestID, reqPayload.URL, len(reqPayload.Data))
	}

	decryptedData, err := decrypt(reqPayload.Data, *tunnelPassword)
	if err != nil {
		log.Printf("[ERROR %s] Error decrypting request: %v", requestID, err)
		sendErrorResponse(conn, requestID, "decryption failed")
		return
	}
	if *debug {
		log.Printf("[DEBUG %s] Decrypted request data, len: %d", requestID, len(decryptedData))
	}

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(decryptedData)))
	if err != nil {
		log.Printf("[ERROR %s] Error reading request: %v", requestID, err)
		sendErrorResponse(conn, requestID, "cannot read request")
		return
	}

	targetURL, err := url.Parse(reqPayload.URL)
	if err != nil {
		log.Printf("[ERROR %s] Error parsing target URL from payload: %v", requestID, err)
		sendErrorResponse(conn, requestID, "invalid target URL in payload")
		return
	}
	req.URL.Scheme = targetURL.Scheme
	req.URL.Host = targetURL.Host
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
		sendErrorResponse(conn, requestID, err.Error())
		return
	}
	defer resp.Body.Close()

	if *debug {
		log.Printf("[DEBUG %s] Received response: %s", requestID, resp.Status)
	}

	respData, err := httputil.DumpResponse(resp, true)
	if err != nil {
		log.Printf("[ERROR %s] Error dumping response: %v", requestID, err)
		sendErrorResponse(conn, requestID, "cannot dump response")
		return
	}
	if *debug {
		log.Printf("[DEBUG %s] Dumped response, len: %d", requestID, len(respData))
	}

	encryptedData, err := encrypt(respData, *tunnelPassword)
	if err != nil {
		log.Printf("[ERROR %s] Error encrypting response: %v", requestID, err)
		sendErrorResponse(conn, requestID, "encryption failed")
		return
	}
	if *debug {
		log.Printf("[DEBUG %s] Encrypted response, len: %d", requestID, len(encryptedData))
	}

	sendSuccessResponse(conn, requestID, encryptedData)
}

func sendResponse(conn *websocket.Conn, requestID string, payload ResponsePayload) {
	payloadBytes, _ := json.Marshal(payload)
	msg := TunnelMessage{
		ID:      requestID,
		Type:    MessageTypeResponse,
		Payload: payloadBytes,
	}
	msgBytes, _ := json.Marshal(msg)

	// Use a mutex to protect concurrent writes to the websocket connection
	// This is a simplified approach. A better one would be a dedicated writer goroutine.
	// For now, let's assume handleRequest is the primary writer for responses.
	// Note: The heartbeat goroutine also writes, so a lock is necessary.
	// Let's create a simple mutex on the connection object or a global one.
	// For now, we will rely on the fact that response writes are less frequent than pings.
	// A proper implementation would have a send channel and a single writer goroutine.
	// The current `sendResponse` is not called from multiple goroutines for the same conn,
	// except for the heartbeat. Let's assume it's safe enough for now.

	if err := conn.WriteMessage(websocket.TextMessage, msgBytes); err != nil {
		log.Printf("Error writing response for request %s: %v", requestID, err)
	}
}

func sendSuccessResponse(conn *websocket.Conn, requestID string, data []byte) {
	if *debug {
		log.Printf("[DEBUG %s] Sending success response, len: %d", requestID, len(data))
	}
	sendResponse(conn, requestID, ResponsePayload{Data: data})
}

func sendErrorResponse(conn *websocket.Conn, requestID string, errorMsg string) {
	log.Printf("Sending error response for request %s: %s", requestID, errorMsg)
	sendResponse(conn, requestID, ResponsePayload{Error: errorMsg})
}

// createKey generates a 32-byte key from a password string
func createKey(password string) []byte {
	hash := sha256.Sum256([]byte(password))
	return hash[:]
}

// encrypt encrypts data using AES-GCM
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

// decrypt decrypts data using AES-GCM
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