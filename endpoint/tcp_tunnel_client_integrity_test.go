package main

import "testing"

func resetGridFrameIntegrityStateForTest() {
	gridFrameIntegritySeen.mu.Lock()
	gridFrameIntegritySeen.seen = make(map[string]int64)
	gridFrameIntegritySeen.mu.Unlock()
}

func TestProxyGridFrameIntegritySignVerifyAndReplay(t *testing.T) {
	resetGatewayRuntimeStateForTest()
	defer resetGatewayRuntimeStateForTest()
	resetGridFrameIntegrityStateForTest()
	defer resetGridFrameIntegrityStateForTest()

	secret := "gw-kex-secret"
	payload := ProxyConnectPayload{
		ConnectionID:  "relay-1",
		GridFinalHost: "203.0.113.10",
		GridFinalPort: 443,
		GridFinalTLS:  true,
		RouteID:       "route-1",
		RouteEpoch:    10,
		HopCount:      2,
		TraceID:       "trace-1",
		GridNextHop:   "node-b",
		GridHops:      []string{"node-c", "node-d"},
	}
	signProxyGridFrameIntegrityWithSecret(&payload, secret)
	if err := verifyProxyGridFrameIntegrityWithSecret(payload, secret); err != nil {
		t.Fatalf("expected integrity verify success, got %v", err)
	}
	if err := verifyProxyGridFrameIntegrityWithSecret(payload, secret); err == nil {
		t.Fatal("expected replay to be rejected")
	}
}

func TestRequestGridFrameIntegrityRejectsTamperWithSecret(t *testing.T) {
	resetGatewayRuntimeStateForTest()
	defer resetGatewayRuntimeStateForTest()
	resetGridFrameIntegrityStateForTest()
	defer resetGridFrameIntegrityStateForTest()

	secret := "gw-kex-secret"
	payload := RequestStartPayloadTCP{
		ID:            "req-1",
		URL:           "https://example.com/path",
		GridFinalHost: "example.com",
		GridFinalPort: 443,
		GridFinalTLS:  true,
		RouteID:       "route-1",
		RouteEpoch:    9,
		HopCount:      1,
		TraceID:       "trace-1",
		GridNextHop:   "node-b",
		GridHops:      []string{"node-c"},
	}
	signRequestGridFrameIntegrityWithSecret(&payload, secret)
	payload.RouteEpoch++
	if err := verifyRequestGridFrameIntegrityWithSecret(payload, secret); err == nil {
		t.Fatal("expected tampered request frame to be rejected")
	}
}
