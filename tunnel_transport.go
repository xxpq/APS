package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/http/httputil"
)

// TunnelRoundTripper implements http.RoundTripper to send requests via a tunnel
type TunnelRoundTripper struct {
	tunnelManager TunnelManagerInterface
	next          http.RoundTripper // The default transport
}

// NewTunnelRoundTripper creates a new TunnelRoundTripper
func NewTunnelRoundTripper(tm TunnelManagerInterface, defaultTransport http.RoundTripper) *TunnelRoundTripper {
	return &TunnelRoundTripper{
		tunnelManager: tm,
		next:          defaultTransport,
	}
}

// RoundTrip executes a single HTTP transaction
func (t *TunnelRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	mapping, ok := req.Context().Value("mapping").(*Mapping)
	if !ok {
		return t.next.RoundTrip(req)
	}

	// If either tunnel or endpoint names are specified, attempt to send via tunnel.
	if len(mapping.tunnelNames) > 0 || len(mapping.endpointNames) > 0 {
		return t.roundTripViaTunnel(req, mapping)
	}

	// No endpoint or tunnel configured for this mapping, proceed with normal transport
	return t.next.RoundTrip(req)
}

func (t *TunnelRoundTripper) roundTripViaTunnel(req *http.Request, mapping *Mapping) (*http.Response, error) {
	// Determine tunnel and endpoint names from mapping
	var tunnelName, endpointName string
	if len(mapping.tunnelNames) > 0 {
		tunnelName = mapping.tunnelNames[rand.Intn(len(mapping.tunnelNames))]
	}
	if len(mapping.endpointNames) > 0 {
		endpointName = mapping.endpointNames[rand.Intn(len(mapping.endpointNames))]
	}

	// Serialize the request
	reqBytes, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		return nil, fmt.Errorf("failed to dump request: %w", err)
	}

	// Prepare payload for the tunnel manager
	reqPayload := &RequestPayload{
		URL:  req.URL.String(),
		Data: reqBytes,
	}

	// Send the request via the tunnel manager's gRPC stream
	log.Printf("[TUNNEL] Sending request for %s via tunnel '%s' to endpoint '%s'", req.URL.String(), tunnelName, endpointName)
	respData, err := t.tunnelManager.SendRequest(req.Context(), tunnelName, endpointName, reqPayload)
	if err != nil {
		log.Printf("[TUNNEL] Request via tunnel failed: %v. Falling back to direct connection.", err)
		return t.next.RoundTrip(req) // Fallback
	}

	// Deserialize the response
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(respData)), req)
	if err != nil {
		return nil, fmt.Errorf("failed to read response from tunnel: %w", err)
	}

	return resp, nil
}

// GetInnerTransport returns the next round tripper in the chain.
func (t *TunnelRoundTripper) GetInnerTransport() http.RoundTripper {
	return t.next
}
