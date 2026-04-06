package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/http/httpproxy"
	xproxy "golang.org/x/net/proxy"
)

func endpointProxyURLForTarget(targetURL *url.URL) (*url.URL, error) {
	if targetURL == nil {
		return nil, nil
	}
	cfg := httpproxy.FromEnvironment()
	allProxy := strings.TrimSpace(os.Getenv("ALL_PROXY"))
	if allProxy == "" {
		allProxy = strings.TrimSpace(os.Getenv("all_proxy"))
	}
	if allProxy != "" {
		if strings.TrimSpace(cfg.HTTPSProxy) == "" {
			cfg.HTTPSProxy = allProxy
		}
		if strings.TrimSpace(cfg.HTTPProxy) == "" {
			cfg.HTTPProxy = allProxy
		}
	}
	proxyURL, err := cfg.ProxyFunc()(targetURL)
	if err != nil {
		return nil, err
	}
	if proxyURL == nil {
		return nil, nil
	}
	if strings.TrimSpace(proxyURL.Scheme) == "" {
		parsed, parseErr := url.Parse("http://" + strings.TrimSpace(proxyURL.String()))
		if parseErr != nil {
			return nil, parseErr
		}
		proxyURL = parsed
	}
	if strings.TrimSpace(proxyURL.Host) == "" {
		return nil, fmt.Errorf("proxy URL missing host: %q", proxyURL.String())
	}
	return proxyURL, nil
}

func endpointHTTPProxySelector(req *http.Request) (*url.URL, error) {
	if req == nil || req.URL == nil {
		return nil, nil
	}
	return endpointProxyURLForTarget(req.URL)
}

func proxyAddressWithDefaultPort(proxyURL *url.URL) (string, error) {
	if proxyURL == nil {
		return "", fmt.Errorf("nil proxy URL")
	}
	host := strings.TrimSpace(proxyURL.Host)
	if host == "" {
		return "", fmt.Errorf("proxy URL missing host")
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host, nil
	}

	scheme := strings.ToLower(strings.TrimSpace(proxyURL.Scheme))
	defaultPort := ""
	switch scheme {
	case "http":
		defaultPort = "80"
	case "https":
		defaultPort = "443"
	case "socks5", "socks5h":
		defaultPort = "1080"
	default:
		defaultPort = "80"
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), defaultPort), nil
}

func connectWithHTTPProxyCONNECT(conn net.Conn, targetAddress string, proxyURL *url.URL) (net.Conn, error) {
	targetAddress = normalizeServerAddressForSession(targetAddress)
	if targetAddress == "" {
		return nil, fmt.Errorf("empty CONNECT target address")
	}

	var authHeader string
	if proxyURL != nil && proxyURL.User != nil {
		username := proxyURL.User.Username()
		password, _ := proxyURL.User.Password()
		token := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		authHeader = "Proxy-Authorization: Basic " + token + "\r\n"
	}

	reqText := "CONNECT " + targetAddress + " HTTP/1.1\r\n" +
		"Host: " + targetAddress + "\r\n" +
		"User-Agent: aps-endpoint/" + endpointVersion + "\r\n" +
		"Connection: keep-alive\r\n" +
		"Proxy-Connection: keep-alive\r\n" +
		authHeader +
		"\r\n"

	if err := conn.SetDeadline(time.Now().Add(connectHandshakeTimeout)); err != nil {
		return nil, err
	}
	defer conn.SetDeadline(time.Time{})

	if _, err := io.WriteString(conn, reqText); err != nil {
		return nil, err
	}

	reader := bufio.NewReader(conn)
	req := &http.Request{Method: http.MethodConnect}
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		bodyBytes := []byte{}
		if resp.Body != nil {
			bodyBytes, _ = io.ReadAll(io.LimitReader(resp.Body, 256))
			resp.Body.Close()
		}
		return nil, fmt.Errorf("proxy CONNECT status %d: %s", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	buffered := reader.Buffered()
	if buffered == 0 {
		return conn, nil
	}
	prefixBytes, err := reader.Peek(buffered)
	if err != nil {
		return nil, err
	}
	prefix := make([]byte, len(prefixBytes))
	copy(prefix, prefixBytes)
	return &prefixedConn{Conn: conn, prefix: prefix}, nil
}

func dialTargetViaEnvironmentProxy(ctx context.Context, targetAddress string, proxyURL *url.URL, timeout time.Duration) (net.Conn, error) {
	if proxyURL == nil {
		return nil, fmt.Errorf("proxy URL is nil")
	}
	scheme := strings.ToLower(strings.TrimSpace(proxyURL.Scheme))
	if scheme == "" {
		scheme = "http"
	}
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	targetAddress = normalizeServerAddressForSession(targetAddress)
	if targetAddress == "" {
		return nil, fmt.Errorf("empty target address")
	}

	switch scheme {
	case "http", "https":
		proxyAddr, err := proxyAddressWithDefaultPort(proxyURL)
		if err != nil {
			return nil, err
		}
		dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
		rawConn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
		if err != nil {
			return nil, err
		}
		conn := rawConn
		if scheme == "https" {
			serverName := strings.TrimSpace(proxyURL.Hostname())
			if serverName == "" {
				_ = rawConn.Close()
				return nil, fmt.Errorf("https proxy missing hostname")
			}
			tlsConn := tls.Client(rawConn, &tls.Config{
				MinVersion: tls.VersionTLS12,
				ServerName: serverName,
			})
			if err := tlsConn.SetDeadline(time.Now().Add(timeout)); err != nil {
				_ = rawConn.Close()
				return nil, err
			}
			if err := tlsConn.Handshake(); err != nil {
				_ = rawConn.Close()
				return nil, err
			}
			_ = tlsConn.SetDeadline(time.Time{})
			conn = tlsConn
		}
		tunneledConn, err := connectWithHTTPProxyCONNECT(conn, targetAddress, proxyURL)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		return tunneledConn, nil
	case "socks5", "socks5h":
		proxyAddr, err := proxyAddressWithDefaultPort(proxyURL)
		if err != nil {
			return nil, err
		}
		var auth *xproxy.Auth
		if proxyURL.User != nil {
			username := proxyURL.User.Username()
			password, _ := proxyURL.User.Password()
			auth = &xproxy.Auth{
				User:     username,
				Password: password,
			}
		}
		baseDialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
		socksDialer, err := xproxy.SOCKS5("tcp", proxyAddr, auth, baseDialer)
		if err != nil {
			return nil, err
		}
		type contextDialer interface {
			DialContext(context.Context, string, string) (net.Conn, error)
		}
		if d, ok := socksDialer.(contextDialer); ok {
			return d.DialContext(ctx, "tcp", targetAddress)
		}
		return socksDialer.Dial("tcp", targetAddress)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", proxyURL.Scheme)
	}
}
