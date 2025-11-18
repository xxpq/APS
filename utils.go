package main

import (
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

var (
	regexCache = make(map[string]*regexp.Regexp)
	regexMutex = &sync.RWMutex{}
	// Global WebSocket upgrader, shared between tunnel and proxy logic
	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		// Allow any origin
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
)

// compileRegex 使用缓存来编译正则表达式，提高性能
func compileRegex(pattern string) (*regexp.Regexp, error) {
	regexMutex.RLock()
	re, found := regexCache[pattern]
	regexMutex.RUnlock()

	if found {
		return re, nil
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	regexMutex.Lock()
	regexCache[pattern] = re
	regexMutex.Unlock()

	return re, nil
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		// These headers are connection-specific and should not be copied.
		// gorilla/websocket handles the Sec-WebSocket-* headers.
		if key == "Host" || key == "Connection" || key == "Proxy-Connection" ||
			key == "Keep-Alive" || key == "Proxy-Authenticate" || key == "Proxy-Authorization" ||
			key == "Te" || key == "Trailer" || key == "Transfer-Encoding" || key == "Upgrade" ||
			strings.HasPrefix(key, "Sec-Websocket-") {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func setCorsHeaders(h http.Header) {
	h.Set("Origin", "*")
	h.Set("Timing-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Vary", "Etag, Save-Data, Accept-Encoding")
	h.Set("Access-Control-Allow-Headers", "*")
	h.Set("Access-Control-Allow-Methods", "*")
	h.Set("Access-Control-Allow-Credentials", "true")
	h.Set("Access-Control-Expose-Headers", "*")
	h.Set("Access-Control-Request-Method", "*")
	h.Set("Access-Control-Request-Headers", "*")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "cross-origin")
}

func getClientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0]
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}

func getScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if scheme := r.Header.Get("X-Forwarded-Proto"); scheme != "" {
		return scheme
	}
	return "http"
}

func findIndexFile(path string) string {
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return path
	}

	indexFiles := []string{"index.html", "index.htm"}
	for _, indexFile := range indexFiles {
		indexPath := filepath.Join(path, indexFile)
		if _, err := os.Stat(indexPath); err == nil {
			return indexPath
		}
	}

	return path
}

func (p *MapRemoteProxy) buildOriginalURL(r *http.Request) string {
	originalURL := r.URL.String()

	if !strings.HasPrefix(originalURL, "http://") && !strings.HasPrefix(originalURL, "https://") {
		scheme := getScheme(r)
		originalURL = scheme + "://" + r.Host + originalURL
	}

	return originalURL
}

// pickRandomIP 从IP列表中随机选择一个IP地址
func pickRandomIP(ips []string) string {
	if len(ips) == 0 {
		return ""
	}
	if len(ips) == 1 {
		return ips[0]
	}
	return ips[rand.Intn(len(ips))]
}

// replaceHostWithIP 将URL中的主机名替换为指定的IP地址
func replaceHostWithIP(originalURL string, ip string) (string, error) {
	parsedURL, err := url.Parse(originalURL)
	if err != nil {
		return "", err
	}

	// 保留原始主机名作为Host头，只替换连接目标
	originalHost := parsedURL.Host
	if strings.Contains(originalHost, ":") {
		// 如果原始主机包含端口，保留端口
		hostParts := strings.Split(originalHost, ":")
		if len(hostParts) == 2 {
			parsedURL.Host = ip + ":" + hostParts[1]
		} else {
			parsedURL.Host = ip
		}
	} else {
		// 如果没有端口，根据协议添加默认端口
		if parsedURL.Scheme == "https" {
			parsedURL.Host = ip + ":443"
		} else {
			parsedURL.Host = ip + ":80"
		}
	}

	return parsedURL.String(), nil
}

// extractDomain 从 URL 中提取域名 (不含端口)
func extractDomain(rawURL string) string {
	// 尝试解析 URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		// 如果解析失败，可能是一个不带协议的域名，例如 "example.com/*"
		// 尝试直接从字符串中提取
		parts := strings.Split(rawURL, "/")
		if len(parts) > 0 {
			hostParts := strings.Split(parts[0], ":")
			return hostParts[0]
		}
		return ""
	}

	// 从解析后的 URL 中获取主机名 (包含端口)
	host := parsedURL.Hostname()
	return host
}

// containsString 检查字符串切片中是否包含指定的字符串
func containsString(slice []string, str string) bool {
	for _, item := range slice {
		if item == str {
			return true
		}
	}
	return false
}