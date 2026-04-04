package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/http/httputil"
)

// mappingContextKey 是用于存储mapping对象的context键
// 这个常量也在http_handler.go中定义，保持一致性
const mappingContextKey = "mapping"

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

	reqHeaderBytes, err := httputil.DumpRequestOut(req, false)
	if err != nil {
		return nil, fmt.Errorf("failed to dump request: %w", err)
	}

	bodyForTunnel := req.Body
	if req.GetBody != nil {
		if replayBody, replayErr := req.GetBody(); replayErr == nil {
			bodyForTunnel = replayBody
		}
	}

	// Prepare payload for the tunnel manager
	reqPayload := &RequestPayload{
		URL:        req.URL.String(),
		SourceIP:   extractIPFromAddr(req.RemoteAddr),
		HeaderData: reqHeaderBytes,
		Body:       bodyForTunnel,
	}

	// Send the request via the tunnel manager's gRPC stream
	DebugLog("[TUNNEL] Sending request for %s via tunnel '%s' to endpoint '%s'", req.URL.String(), tunnelName, endpointName)
	var bodyStream io.ReadCloser
	var headerBytes []byte
	if runtime := GetGlobalGridRuntime(); runtime != nil {
		if engine := NewGridExecutionEngine(runtime, t.tunnelManager, "http-roundtripper"); engine != nil {
			bodyStream, headerBytes, err = engine.SendRequestStream(req.Context(), tunnelName, endpointName, reqPayload)
		}
	}
	if bodyStream == nil && err == nil {
		bodyStream, headerBytes, err = t.tunnelManager.SendRequestStream(req.Context(), tunnelName, endpointName, reqPayload)
	}
	if err != nil {
		if bodyForTunnel != nil && bodyForTunnel != req.Body {
			bodyForTunnel.Close()
		}
		log.Printf("[TUNNEL] Request via tunnel failed: %v. Falling back to direct connection.", err)
		return t.next.RoundTrip(req) // Fallback
	}

	// Deserialize the response
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(headerBytes)), req)
	if err != nil {
		bodyStream.Close()
		return nil, fmt.Errorf("failed to read response from tunnel: %w", err)
	}
	resp.Body = bodyStream

	return resp, nil
}

// GetInnerTransport returns the next round tripper in the chain.
func (t *TunnelRoundTripper) GetInnerTransport() http.RoundTripper {
	return t.next
}
