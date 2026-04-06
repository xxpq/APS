package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"
)

const apsInsecureHeader = "X-Aps-Insecure"

type backendPolicyTransport struct {
	base *http.Transport
}

func newSharedBackendHTTPClient() *http.Client {
	baseTransport := &http.Transport{
		Proxy:                 endpointHTTPProxySelector,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS13},
		MaxIdleConns:          1000,
		MaxIdleConnsPerHost:   100,
		MaxConnsPerHost:       0,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    true,
		ForceAttemptHTTP2:     true,
	}

	return &http.Client{
		Transport: &backendPolicyTransport{base: baseTransport},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 5 * time.Minute,
	}
}

func (t *backendPolicyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil {
		return t.base.RoundTrip(req)
	}

	clonedReq := req.Clone(req.Context())
	clonedReq.Header = req.Header.Clone()
	allowInsecure := shouldAllowInsecureBackendTLS(clonedReq)

	// Internal control header must never be forwarded to backend services.
	clonedReq.Header.Del(apsInsecureHeader)

	if !allowInsecure {
		return t.base.RoundTrip(clonedReq)
	}

	insecureTransport := cloneInsecureBackendTransport(t.base)
	return insecureTransport.RoundTrip(clonedReq)
}

func cloneInsecureBackendTransport(base *http.Transport) *http.Transport {
	insecureTransport := base.Clone()
	if insecureTransport.TLSClientConfig == nil {
		insecureTransport.TLSClientConfig = &tls.Config{}
	} else {
		insecureTransport.TLSClientConfig = insecureTransport.TLSClientConfig.Clone()
	}
	insecureTransport.TLSClientConfig.InsecureSkipVerify = true
	insecureTransport.TLSClientConfig.MinVersion = tls.VersionTLS10
	return insecureTransport
}

func shouldAllowInsecureBackendTLS(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}
	if !strings.EqualFold(req.URL.Scheme, "https") {
		return false
	}

	host := normalizeTLSPolicyHost(req.URL.Hostname())
	if host == "" {
		return false
	}

	// Never allow bypassing cert validation when targeting APS servers.
	if isAPSServerHost(host) {
		return false
	}

	if isTruthyHeader(req.Header.Get(apsInsecureHeader)) {
		return true
	}

	// Allow internal/self-signed backends by default (except APS hosts above).
	return isInternalTLSPolicyHost(host)
}

func isTruthyHeader(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func isInternalTLSPolicyHost(host string) bool {
	host = normalizeTLSPolicyHost(host)
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

func isAPSServerHost(host string) bool {
	host = normalizeTLSPolicyHost(host)
	if host == "" || connectionManager == nil {
		return false
	}

	for _, addr := range connectionManager.GetAllServers() {
		if normalizeTLSPolicyHost(hostFromServerAddress(addr)) == host {
			return true
		}
	}
	return false
}

func hostFromServerAddress(addr string) string {
	addr = strings.TrimSpace(addr)
	if idx := strings.Index(addr, "@"); idx >= 0 && idx+1 < len(addr) {
		addr = addr[idx+1:]
	}

	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

func normalizeTLSPolicyHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.Trim(host, "[]")
	host = strings.TrimSuffix(host, ".")
	return strings.ToLower(host)
}
