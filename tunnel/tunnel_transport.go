package tunnel

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
const mappingContextKey = "mapping"

// MappingContextKey is exported for use by other packages (e.g. http_handler)
// that need to set/read the mapping on a request context.
const MappingContextKey = "mapping"

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
	mapping, ok := req.Context().Value(MappingContextKey).(*Mapping)
	if !ok {
		return t.next.RoundTrip(req)
	}

	// If either tunnel or endpoint names are specified, attempt to send via tunnel.
	if len(mapping.TunnelNames) > 0 || len(mapping.EndpointNames) > 0 {
		return t.roundTripViaTunnel(req, mapping)
	}

	// No endpoint or tunnel configured for this mapping, proceed with normal transport
	return t.next.RoundTrip(req)
}

func (t *TunnelRoundTripper) roundTripViaTunnel(req *http.Request, mapping *Mapping) (*http.Response, error) {
	// Determine tunnel and endpoint names from mapping
	var tunnelName, endpointName string
	if len(mapping.TunnelNames) > 0 {
		tunnelName = mapping.TunnelNames[0]
	}
	if len(mapping.EndpointNames) > 0 {
		endpointName = mapping.EndpointNames[0]
	}

	// Build payload
	bodyStream, headerBytes, err := t.buildPayload(req, mapping)
	if err != nil {
		return nil, err
	}
	if bodyStream != nil {
		defer bodyStream.Close()
	}
	reqPayload := &RequestPayload{
		ID:         fmt.Sprintf("trt-%d", rand.Int63()),
		Method:     req.Method,
		URL:        req.URL.String(),
		SourceIP:   extractClientIP(req),
		Header:     cloneHTTPHeader(req.Header),
		Data:       nil,
		HeaderData: headerBytes,
		Body:       bodyStream,
	}

	// Send the request via the tunnel manager's gRPC stream
	log.Printf("[TUNNEL] Sending request for %s via tunnel '%s' to endpoint '%s'", req.URL.String(), tunnelName, endpointName)
	var sr io.ReadCloser
	var hb []byte
	sr, hb, err = t.tunnelManager.SendRequestStream(req.Context(), tunnelName, endpointName, reqPayload)
	if err != nil {
		return nil, err
	}

	// Build the response from the stream
	return t.buildResponse(sr, hb, req)
}

func (t *TunnelRoundTripper) buildPayload(req *http.Request, mapping *Mapping) (io.ReadCloser, []byte, error) {
	var bodyStream io.ReadCloser
	if req.Body != nil {
		bodyStream = req.Body
	}

	// Capture request headers as a dump for the tunnel payload.
	headerBytes, err := serializeHeaders(req.Header)
	if err != nil {
		return nil, nil, err
	}

	return bodyStream, headerBytes, nil
}

func (t *TunnelRoundTripper) buildResponse(sr io.ReadCloser, hb []byte, req *http.Request) (*http.Response, error) {
	// Read header bytes first
	headerBuf := bytes.NewReader(hb)
	br := bufio.NewReader(headerBuf)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, err
	}
	// Body is the stream
	resp.Body = sr
	return resp, nil
}

// Mapping is a minimal projection of the project's main Mapping type.
// Only the fields read by TunnelRoundTripper are exposed.
type Mapping struct {
	TunnelNames   []string
	EndpointNames []string
}

func extractClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return xrip
	}
	host, _, err := splitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func cloneHTTPHeader(h http.Header) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, v := range h {
		cp := make([]string, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}

func serializeHeaders(h http.Header) ([]byte, error) {
	// Dump headers in a stable form
	var buf bytes.Buffer
	for k, v := range h {
		for _, vv := range v {
			buf.WriteString(k)
			buf.WriteString(": ")
			buf.WriteString(vv)
			buf.WriteString("\r\n")
		}
	}
	return buf.Bytes(), nil
}

func splitHostPort(addr string) (string, int, error) {
	// Simple wrapper around net.SplitHostPort
	host, portStr, err := netSplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port := 0
	if portStr != "" {
		_, _ = fmt.Sscanf(portStr, "%d", &port)
	}
	return host, port, nil
}

func netSplitHostPort(addr string) (string, string, error) {
	// indirection so we don't need a separate import
	idx := -1
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			idx = i
			break
		}
	}
	if idx < 0 {
		return addr, "", nil
	}
	return addr[:idx], addr[idx+1:], nil
}

// NewTunnelRoundTripperWithMapping sets up a RoundTripper that picks up the
// mapping from the request context. Provided for backward compatibility.
var _ = httputil.NewSingleHostReverseProxy

// GetInnerTransport returns the wrapped default transport so callers can
// access fields like IdleConnPool on the underlying http.Transport.
func (t *TunnelRoundTripper) GetInnerTransport() http.RoundTripper {
	return t.next
}
