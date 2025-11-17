package main

import "encoding/json"

const (
	MessageTypeRequest  = "request"
	MessageTypeResponse = "response"
	MessageTypeCancel   = "cancel"
)

// TunnelMessage is the wrapper for all communications over the tunnel
type TunnelMessage struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"` // "request", "response", "cancel"
	Payload json.RawMessage `json:"payload,omitempty"`
}

// RequestPayload is the content of a request message
type RequestPayload struct {
	URL  string `json:"url"`
	Data []byte `json:"data"`
}

// ResponsePayload is the content of a response message
type ResponsePayload struct {
	Data  []byte `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}
