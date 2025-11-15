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
	localPath := mapping.Local
	if strings.HasSuffix(localPath, "*") {
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
