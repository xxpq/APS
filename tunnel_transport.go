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
	if !ok {
		return t.next.RoundTrip(req)
	}

	// Priority 1: Specific endpoint name is provided
	if len(mapping.endpointNames) > 0 {
		endpointName := mapping.endpointNames[rand.Intn(len(mapping.endpointNames))] // Select one randomly
		endpoint, tunnel := t.tunnelManager.FindEndpoint(endpointName)
		if endpoint != nil {
			return t.roundTripViaTunnel(req, endpoint, tunnel)
		}
		log.Printf("[TUNNEL] Specified endpoint '%s' not found or not online, falling back to direct connection", endpointName)
		return t.next.RoundTrip(req)
	}

	// Priority 2: Tunnel name is provided
	if len(mapping.tunnelNames) > 0 {
		tunnelName := mapping.tunnelNames[rand.Intn(len(mapping.tunnelNames))] // Select one randomly
		endpoint, tunnel := t.tunnelManager.GetRandomEndpointFromTunnel(tunnelName)
		if endpoint != nil {
			return t.roundTripViaTunnel(req, endpoint, tunnel)
		}
		log.Printf("[TUNNEL] No online endpoints found in specified tunnel '%s', falling back to direct connection", tunnelName)
		return t.next.RoundTrip(req)
	}

	// No endpoint or tunnel configured for this mapping, proceed with normal transport
	return t.next.RoundTrip(req)
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
