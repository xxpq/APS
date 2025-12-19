package main

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/gorilla/websocket"
)

var (
	regexCache = make(map[string]*regexp.Regexp)
	regexMutex = &sync.RWMutex{}
	// Global WebSocket upgrader, shared between tunnel and proxy logic
	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024 * 1024, // 1MB buffer for large messages
		WriteBufferSize: 1024 * 1024, // 1MB buffer for large messages
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

// skipHeaders 预定义需要跳过的 header 集合（使用 map 查表替代多次字符串比较）
var skipHeaders = map[string]struct{}{
	"Host":                {},
	"Connection":          {},
	"Proxy-Connection":    {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

func copyHeaders(dst, src http.Header) {
	for key, values := range src {
		// 使用 map 查表替代多次字符串比较
		if _, skip := skipHeaders[key]; skip {
			continue
		}
		// WebSocket 相关的 header 仍需前缀匹配
		if strings.HasPrefix(key, "Sec-Websocket-") {
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
	h.Set("Cross-Origin-Opener-Policy", "cross-origin")
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

// extractIPFromAddr extracts IP from a RemoteAddr string (e.g., "1.2.3.4:1234" -> "1.2.3.4")
func extractIPFromAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr // Fallback to full string if split fails
	}
	return host
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
	return ips[mrand.Intn(len(ips))]
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

func normalizeContentEncoding(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.Split(header, ",")
	if len(parts) == 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(parts[0]))
}

func decodeBodyWithEncoding(body []byte, header string) ([]byte, string, bool, error) {
	encoding := normalizeContentEncoding(header)
	if encoding == "" {
		return body, "", false, nil
	}

	var reader io.ReadCloser
	var err error

	switch encoding {
	case "gzip":
		reader, err = gzip.NewReader(bytes.NewReader(body))
	case "deflate":
		reader, err = zlib.NewReader(bytes.NewReader(body))
	case "br":
		reader = io.NopCloser(brotli.NewReader(bytes.NewReader(body)))
	default:
		return body, encoding, false, nil
	}

	if err != nil {
		return body, encoding, false, err
	}
	defer reader.Close()

	decoded, err := io.ReadAll(reader)
	if err != nil {
		return body, encoding, false, err
	}
	return decoded, encoding, true, nil
}

func encodeBodyWithEncoding(body []byte, encoding string) ([]byte, error) {
	if encoding == "" {
		return body, nil
	}

	var buf bytes.Buffer
	var writer io.WriteCloser
	var err error

	switch encoding {
	case "gzip":
		writer = gzip.NewWriter(&buf)
	case "deflate":
		writer = zlib.NewWriter(&buf)
	case "br":
		writer = brotli.NewWriter(&buf)
	default:
		return body, nil
	}

	if _, err = writer.Write(body); err != nil {
		writer.Close()
		return nil, err
	}
	if err = writer.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// encrypt encrypts data using AES-GCM with a key derived from the password
func encrypt(data []byte, password string) ([]byte, error) {
	key := sha256.Sum256([]byte(password))

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// decrypt decrypts data using AES-GCM with a key derived from the password
func decrypt(data []byte, password string) ([]byte, error) {
	key := sha256.Sum256([]byte(password))

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(data) < gcm.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}

	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// isMediaContent checks if the content type indicates a media file or archive
// that should be skipped for modification and compression.
func isMediaContent(r *http.Request) bool {
	lowerType := strings.ToLower(r.Header.Get("Content-Type"))
	return strings.HasPrefix(lowerType, "video/") ||
		strings.HasPrefix(lowerType, "audio/") ||
		(strings.HasPrefix(lowerType, "image/") && !strings.Contains(lowerType, "svg")) ||
		strings.Contains(lowerType, "zip") ||
		strings.Contains(lowerType, "compressed") ||
		strings.Contains(lowerType, "pdf") ||
		strings.Contains(lowerType, "octet-stream") || containsString(defaultCacheExtensions, strings.ToLower(r.URL.Path))
}

// isTextContentType checks if the content type indicates a text-based format
// that is safe for string-based modification (e.g. regex replacement).
func isTextContentType(contentType string) bool {
	if contentType == "" {
		// Assume text if no content type is provided?
		// Safer to assume binary to avoid corruption, but for web requests often default is text/html.
		// However, for proxying, it's safer to skip modification if unknown.
		return false
	}
	lowerType := strings.ToLower(contentType)
	return strings.Contains(lowerType, "text/") ||
		strings.Contains(lowerType, "json") ||
		strings.Contains(lowerType, "xml") ||
		strings.Contains(lowerType, "javascript") ||
		strings.Contains(lowerType, "ecmascript") ||
		strings.Contains(lowerType, "css") ||
		strings.Contains(lowerType, "html") ||
		strings.Contains(lowerType, "csv") ||
		strings.Contains(lowerType, "yaml")
}
