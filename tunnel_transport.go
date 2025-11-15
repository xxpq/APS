package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
)

// TunnelRoundTripper implements http.RoundTripper to send requests via a tunnel
type TunnelRoundTripper struct {
	tunnelManager *TunnelManager
	next          http.RoundTripper // The default transport
}

// NewTunnelRoundTripper creates a new TunnelRoundTripper
func NewTunnelRoundTripper(tm *TunnelManager, defaultTransport http.RoundTripper) *TunnelRoundTripper {
	return &TunnelRoundTripper{
		tunnelManager: tm,
		next:          defaultTransport,
	}
}

// RoundTrip executes a single HTTP transaction
func (t *TunnelRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	mapping, ok := req.Context().Value("mapping").(*Mapping)
	if !ok || len(mapping.endpointNames) == 0 {
		// No mapping or no endpoint configured, proceed with normal transport
		return t.next.RoundTrip(req)
	}

	// TODO: Select endpoint based on user, group, server config as well
	endpointName := mapping.endpointNames[0] // Simple selection for now

	var selectedEndpoint *EndpointConn
	var selectedTunnel *Tunnel

	// Find the endpoint and its tunnel
	for _, tunnel := range t.tunnelManager.tunnels {
		tunnel.mu.RLock()
		if ep, exists := tunnel.endpoints[endpointName]; exists {
			selectedEndpoint = ep
			selectedTunnel = tunnel
		}
		tunnel.mu.RUnlock()
		if selectedEndpoint != nil {
			break
		}
	}

	if selectedEndpoint == nil {
		log.Printf("[TUNNEL] Endpoint '%s' not found or not online, falling back to direct connection", endpointName)
		return t.next.RoundTrip(req)
	}

	return t.roundTripViaTunnel(req, selectedEndpoint, selectedTunnel)
}

func (t *TunnelRoundTripper) roundTripViaTunnel(req *http.Request, endpoint *EndpointConn, tunnel *Tunnel) (*http.Response, error) {
	// 1. Serialize the request
	reqBytes, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		return nil, fmt.Errorf("failed to dump request: %w", err)
	}

	// 2. Send the request and wait for the response, passing the request's context
	log.Printf("[TUNNEL] Sending request for %s via endpoint '%s' in tunnel '%s'", req.URL.String(), endpoint.name, tunnel.name)
	respData, err := endpoint.SendRequest(req.Context(), reqBytes, tunnel)
	if err != nil {
		return nil, fmt.Errorf("tunnel request failed: %w", err)
	}

	// 3. Deserialize the response
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
