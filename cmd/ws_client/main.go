package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocket测试客户端
func main() {
	serverAddr := flag.String("server", "localhost:8080", "proxy server address")
	tunnelName := flag.String("tunnel", "tunnel1", "tunnel name")
	endpointName := flag.String("endpoint", "test-endpoint", "endpoint name")
	password := flag.String("password", "test123", "tunnel password")
	flag.Parse()

	// 连接到WebSocket隧道
	u := url.URL{Scheme: "ws", Host: *serverAddr, Path: "/.tunnel"}
	log.Printf("Connecting to WebSocket tunnel: %s", u.String())

	header := http.Header{}
	header.Set("X-Tunnel-Name", *tunnelName)
	header.Set("X-Endpoint-Name", *endpointName)
	header.Set("X-Tunnel-Password", *password)

	conn, _, err := websocket.DefaultDialer.Dial(u.String(), header)
	if err != nil {
		log.Fatalf("Failed to connect to WebSocket tunnel: %v", err)
	}
	defer conn.Close()

	log.Printf("Successfully connected to WebSocket tunnel %s as endpoint %s", *tunnelName, *endpointName)

	// 启动消息处理goroutine
	go func() {
		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				log.Printf("Read error: %v", err)
				return
			}

			// 解析消息
			var msg map[string]interface{}
			if err := json.Unmarshal(message, &msg); err != nil {
				log.Printf("Error unmarshalling message: %v", err)
				continue
			}

			msgType, _ := msg["type"].(string)
			msgID, _ := msg["id"].(string)

			switch msgType {
			case "request":
				// 处理请求
				log.Printf("Received request %s", msgID)
				
				// 模拟处理请求
				response := map[string]interface{}{
					"id":   msgID,
					"type": "response",
					"payload": map[string]interface{}{
						"data":  []byte("Hello from WebSocket endpoint!"),
						"error": "",
					},
				}

				respBytes, err := json.Marshal(response)
				if err != nil {
					log.Printf("Error marshalling response: %v", err)
					continue
				}

				if err := conn.WriteMessage(websocket.TextMessage, respBytes); err != nil {
					log.Printf("Error writing response: %v", err)
				} else {
					log.Printf("Sent response for request %s", msgID)
				}

			case "cancel":
				log.Printf("Received cancellation for request %s", msgID)

			case "ping":
				// 自动处理ping（gorilla/websocket会自动回复pong）
				log.Printf("Received ping")

			default:
				log.Printf("Unknown message type: %s", msgType)
			}
		}
	}()

	// 定期发送ping
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// 保持连接活跃
	for {
		select {
		case <-ticker.C:
			// 发送ping（gorilla/websocket会自动处理）
			log.Println("Sending ping...")
			
		case <-time.After(5 * time.Minute):
			log.Println("Test completed, closing connection")
			return
		}
	}
}