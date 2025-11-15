package main

import "encoding/json"

const (
	MessageTypeRequest  = "request"
	MessageTypeResponse = "response"
	MessageTypePing     = "ping"
	MessageTypePong     = "pong"
	MessageTypeCancel   = "cancel"
)

// TunnelMessage is the wrapper for all communications over the tunnel
type TunnelMessage struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"` // "request", "response", "ping", "pong", "cancel"
	Payload json.RawMessage `json:"payload,omitempty"`
}

// RequestPayload is the content of a request message
type RequestPayload struct {
	Data []byte `json:"data"`
}

// ResponsePayload is the content of a response message
type ResponsePayload struct {
	Data  []byte `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

// PingPayload contains the timestamp from the sender
type PingPayload struct {
	Timestamp int64 `json:"timestamp"`
}

// PongPayload echoes the timestamp from the ping
type PongPayload struct {
	Timestamp int64 `json:"timestamp"`
}