package main

import (
	"path/filepath"
	"strings"
)

var mimeTypes = map[string]string{
	".css":  "text/css",
	".gif":  "image/gif",
	".htm":  "text/html",
	".html": "text/html",
	".jpeg": "image/jpeg",
	".jpg":  "image/jpeg",
	".js":   "application/javascript",
	".json": "application/json",
	".png":  "image/png",
	".svg":  "image/svg+xml",
	".txt":  "text/plain",
	".xml":  "application/xml",
	".zip":  "application/zip",
	".pdf":  "application/pdf",
	".mp3":  "audio/mpeg",
	".mp4":  "video/mp4",
	".ico":  "image/x-icon",
	".wav":  "audio/wav",
	".woff": "font/woff",
	".woff2":"font/woff2",
	".ttf":  "font/ttf",
	".eot":  "application/vnd.ms-fontobject",
	".otf":  "font/otf",
	".wasm":"application/wasm",
	".webp": "image/webp",
	".ts":   "video/mp2t",
	".m3u8": "application/vnd.apple.mpegurl",
	".webm": "video/webm",
	".flv":  "video/x-flv",
	".avi":  "video/x-msvideo",
}

func getMimeType(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	if mime, ok := mimeTypes[ext]; ok {
		return mime
	}
	return "application/octet-stream"
}