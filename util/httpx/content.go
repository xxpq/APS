package httpx

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
)

// containsString reports whether str appears in slice.
func containsString(slice []string, str string) bool {
	for _, item := range slice {
		if item == str {
			return true
		}
	}
	return false
}

// NormalizeContentEncoding returns the lower-cased first token of the
// Content-Encoding header (e.g., "gzip, br" -> "gzip").
func NormalizeContentEncoding(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.Split(header, ",")
	if len(parts) == 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(parts[0]))
}

// DecodeBodyWithEncoding decodes body using the encoding specified by
// header. Returns (decoded, encoding, wasDecoded, err). If header is
// empty or encoding is unsupported, returns body unchanged.
func DecodeBodyWithEncoding(body []byte, header string) ([]byte, string, bool, error) {
	encoding := NormalizeContentEncoding(header)
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

// EncodeBodyWithEncoding encodes body using the given encoding. Returns
// body unchanged if encoding is empty or unsupported.
func EncodeBodyWithEncoding(body []byte, encoding string) ([]byte, error) {
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

// IsMediaContent reports whether the request is for media (video,
// audio, image, archive) and should be skipped for body modification
// and compression. The cacheExtensions parameter is the list of
// static-cache file extensions (e.g., aps/cache.DefaultCacheExtensions).
func IsMediaContent(r *http.Request, cacheExtensions []string) bool {
	lowerType := strings.ToLower(r.Header.Get("Content-Type"))
	return strings.HasPrefix(lowerType, "video/") ||
		strings.HasPrefix(lowerType, "audio/") ||
		(strings.HasPrefix(lowerType, "image/") && !strings.Contains(lowerType, "svg")) ||
		strings.Contains(lowerType, "zip") ||
		strings.Contains(lowerType, "compressed") ||
		strings.Contains(lowerType, "pdf") ||
		strings.Contains(lowerType, "octet-stream") ||
		containsString(cacheExtensions, strings.ToLower(r.URL.Path))
}

// IsTextContentType reports whether the content type indicates a
// text-based format (safe for regex replacement).
func IsTextContentType(contentType string) bool {
	if contentType == "" {
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
