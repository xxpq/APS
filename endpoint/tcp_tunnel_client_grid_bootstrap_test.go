package main

import (
	"strings"
	"testing"
)

func TestEndpointGridBootstrapFromRegisterAckSuccess(t *testing.T) {
	nodeID, token, expires, err := endpointGridBootstrapFromRegisterAck(RegisterAckPayload{
		GridNodeID:         "node-a",
		GridSessionToken:   "token-a",
		GridSessionExpires: 12345,
	})
	if err != nil {
		t.Fatalf("expected success, got err=%v", err)
	}
	if nodeID != "node-a" || token != "token-a" || expires != 12345 {
		t.Fatalf("unexpected bootstrap result node=%s token=%s expires=%d", nodeID, token, expires)
	}
}

func TestEndpointGridBootstrapFromRegisterAckRequiresNodeID(t *testing.T) {
	_, _, _, err := endpointGridBootstrapFromRegisterAck(RegisterAckPayload{
		GridSessionToken:   "token-a",
		GridSessionExpires: 12345,
	})
	if err == nil || !strings.Contains(err.Error(), "grid_node_id") {
		t.Fatalf("expected grid_node_id validation error, got %v", err)
	}
}

func TestEndpointGridBootstrapFromRegisterAckRequiresToken(t *testing.T) {
	_, _, _, err := endpointGridBootstrapFromRegisterAck(RegisterAckPayload{
		GridNodeID:         "node-a",
		GridSessionExpires: 12345,
	})
	if err == nil || !strings.Contains(err.Error(), "grid_session_token") {
		t.Fatalf("expected grid_session_token validation error, got %v", err)
	}
}

func TestEndpointGridBootstrapFromRegisterAckRequiresExpiry(t *testing.T) {
	_, _, _, err := endpointGridBootstrapFromRegisterAck(RegisterAckPayload{
		GridNodeID:       "node-a",
		GridSessionToken: "token-a",
	})
	if err == nil || !strings.Contains(err.Error(), "grid_session_expires") {
		t.Fatalf("expected grid_session_expires validation error, got %v", err)
	}
}

