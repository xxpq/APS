package main

import (
	"bufio"
	"bytes"
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
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

// Message structures (copied from server side)
const (
	MessageTypeRequest  = "request"
	MessageTypeResponse = "response"
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

var addr = flag.String("addr", "localhost:8080", "http service address")
var endpointName = flag.String("name", "default-endpoint", "name for this endpoint")
var tunnelPassword = flag.String("password", "", "tunnel password for encryption")

func main() {
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	u := url.URL{Scheme: "ws", Host: *addr, Path: "/.tunnel"}
	log.Printf("Connecting to %s", u.String())

	header := http.Header{}
	header.Set("X-Endpoint-Name", *endpointName)

	var conn *websocket.Conn
	var err error

	for {
		conn, _, err = websocket.DefaultDialer.Dial(u.String(), header)
		if err != nil {
			log.Println("Dial error:", err)
			log.Println("Retrying in 5 seconds...")
			time.Sleep(5 * time.Second)
			continue
		}
		break
	}
	defer conn.Close()
	log.Println("Successfully connected to tunnel server.")

	done := make(chan struct{})

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

			if msg.Type == MessageTypeRequest {
				go handleRequest(conn, msg.ID, msg.Payload)
			}
		}
	}()

	ticker := time.NewTicker(time.Second * 30)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-interrupt:
			log.Println("Interrupt received, closing connection.")
			err := conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			if err != nil {
				log.Println("Write close error:", err)
				return
			}
			select {
			case <-done:
			case <-time.After(time.Second):
			}
			return
		}
	}
}

func handleRequest(conn *websocket.Conn, requestID string, payload json.RawMessage) {
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

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
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

	if err := conn.WriteMessage(websocket.BinaryMessage, msgBytes); err != nil {
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