package main

import (
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func (p *MapRemoteProxy) serveFile(w http.ResponseWriter, r *http.Request, mapping *Mapping) {
	toURL := mapping.GetToURL()

	// Resolve file:// URL to local path (supports relative and absolute paths)
	localPath, err := resolveFileURL(toURL)
	if err != nil {
		http.Error(w, "Invalid file path", http.StatusInternalServerError)
		log.Printf("Error resolving file URL %s: %v", toURL, err)
		return
	}

	if strings.HasSuffix(toURL, "*") {
		basePath := strings.TrimSuffix(localPath, "*")
		fromURL := mapping.GetFromURL()
		fromBasePath := ""
		if parsedURL, err := url.Parse(fromURL); err == nil {
			fromBasePath = strings.TrimSuffix(parsedURL.Path, "*")
		}
		requestedPath := strings.TrimPrefix(r.URL.Path, fromBasePath)
		localPath = filepath.Join(basePath, requestedPath)
	}

	localPath = findIndexFile(localPath)

	content, err := os.ReadFile(localPath)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		log.Printf("Error reading file %s: %v", localPath, err)
		return
	}

	contentType := getMimeType(localPath)
	w.Header().Set("Content-Type", contentType)
	setCorsHeaders(w.Header())
	w.WriteHeader(http.StatusOK)
	w.Write(content)
}
