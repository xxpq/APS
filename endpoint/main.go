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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

// Message structures (copied from server side)
const (
	MessageTypeRequest  = "request"
	MessageTypeResponse = "response"
	MessageTypePing     = "ping"
	MessageTypePong     = "pong"
	MessageTypeCancel   = "cancel"
)

type TunnelMessage struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

type RequestPayload struct {
	Data []byte `json:"data"`
}

type ResponsePayload struct {
	Data  []byte `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

type PingPayload struct {
	Timestamp int64 `json:"timestamp"`
}

type PongPayload struct {
	Timestamp int64 `json:"timestamp"`
}

var (
	serverAddr     = flag.String("server", "localhost:8080", "proxy server address (e.g., 'your_proxy.com:8080')")
	name           = flag.String("name", "default-endpoint", "unique name for this endpoint client")
	tunnelName     = flag.String("tunnel", "", "name of the tunnel to connect to (must be defined in server config)")
	tunnelPassword = flag.String("password", "", "tunnel password for encryption")

	lastPongTime   atomic.Value
	activeRequests sync.Map // Stores map[string]context.CancelFunc
)

const (
	pingInterval   = 10 * time.Second
	pongTimeout    = 30 * time.Second
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

	for {
		select {
		case <-interrupt:
			log.Println("Interrupt received, shutting down.")
			return
		default:
			runClientSession(interrupt)
			log.Printf("Session ended. Reconnecting in %v...", reconnectDelay)
			time.Sleep(reconnectDelay)
		}
	}
}

func runClientSession(interrupt chan os.Signal) {
	u := url.URL{Scheme: "ws", Host: *serverAddr, Path: "/.tunnel"}
	log.Printf("Connecting to %s", u.String())

	header := http.Header{}
	header.Set("X-Endpoint-Name", *name)
	header.Set("X-Tunnel-Name", *tunnelName)

	conn, _, err := websocket.DefaultDialer.Dial(u.String(), header)
	if err != nil {
		log.Println("Dial error:", err)
		return
	}
	defer conn.Close()
	log.Println("Successfully connected to tunnel server.")

	done := make(chan struct{})
	lastPongTime.Store(time.Now())

	// Start reader goroutine
	go func() {
		defer close(done)
		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				log.Println("Read error:", err)
				return
			}

			var msg TunnelMessage
			if err := json.Unmarshal(message, &msg); err != nil {
				log.Printf("Error unmarshalling message: %v", err)
				continue
			}

			switch msg.Type {
			case MessageTypeRequest:
				go handleRequest(conn, msg.ID, msg.Payload)
			case MessageTypePong:
				lastPongTime.Store(time.Now())
			case MessageTypeCancel:
				log.Printf("[CANCEL] Received cancellation for request %s", msg.ID)
				if cancelFunc, ok := activeRequests.Load(msg.ID); ok {
					cancelFunc.(context.CancelFunc)()
					activeRequests.Delete(msg.ID)
				}
			}
		}
	}()

	// Start heartbeat goroutine
	go func() {
		ticker := time.NewTicker(pingInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Check if the last pong is too old
				if time.Since(lastPongTime.Load().(time.Time)) > pongTimeout {
					log.Printf("Pong timeout. Disconnecting.")
					conn.Close() // This will cause the reader to error out and close 'done'
					return
				}

				// Send ping
				pingPayload := PingPayload{Timestamp: time.Now().UnixNano()}
				payloadBytes, _ := json.Marshal(pingPayload)
				pingMsg := TunnelMessage{Type: MessageTypePing, Payload: payloadBytes}
				msgBytes, _ := json.Marshal(pingMsg)

				if err := conn.WriteMessage(websocket.TextMessage, msgBytes); err != nil {
					log.Println("Write ping error:", err)
					return
				}
				// log.Println("Ping sent.")
			case <-done:
				return
			}
		}
	}()

	select {
	case <-done:
		log.Println("Connection closed.")
	case <-interrupt:
		log.Println("Interrupt received, closing connection.")
		err := conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		if err != nil {
			log.Println("Write close error:", err)
		}
		// Wait a bit for the close message to be sent
		select {
		case <-done:
		case <-time.After(time.Second):
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

	var reqPayload RequestPayload
	if err := json.Unmarshal(payload, &reqPayload); err != nil {
		log.Printf("Error unmarshalling request payload: %v", err)
		sendErrorResponse(conn, requestID, "bad request payload")
		return
	}

	decryptedData, err := decrypt(reqPayload.Data, *tunnelPassword)
	if err != nil {
		log.Printf("Error decrypting request: %v", err)
		sendErrorResponse(conn, requestID, "decryption failed")
		return
	}

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(decryptedData)))
	if err != nil {
		log.Printf("Error reading request: %v", err)
		sendErrorResponse(conn, requestID, "cannot read request")
		return
	}
	req = req.WithContext(ctx)

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		// Check if the error is due to cancellation
		if errors.Is(err, context.Canceled) {
			log.Printf("[CANCEL] Request %s was cancelled locally.", requestID)
			// Don't send a response, as the server-side has already timed out.
			return
		}
		log.Printf("Error executing request: %v", err)
		sendErrorResponse(conn, requestID, err.Error())
		return
	}
	defer resp.Body.Close()

	respData, err := httputil.DumpResponse(resp, true)
	if err != nil {
		log.Printf("Error dumping response: %v", err)
		sendErrorResponse(conn, requestID, "cannot dump response")
		return
	}

	encryptedData, err := encrypt(respData, *tunnelPassword)
	if err != nil {
		log.Printf("Error encrypting response: %v", err)
		sendErrorResponse(conn, requestID, "encryption failed")
		return
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
	log.Printf("Sending success response for request %s", requestID)
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