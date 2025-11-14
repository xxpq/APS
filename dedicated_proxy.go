package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type DedicatedProxy struct {
	mapping *Mapping
	client  *http.Client
}

func NewDedicatedProxy(mapping *Mapping) *DedicatedProxy {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	return &DedicatedProxy{
		mapping: mapping,
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Timeout: 60 * time.Second,
		},
	}
}

func (p *DedicatedProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.mapping.Local != "" {
		log.Printf("[DEDICATED:%d] %s -> [LOCAL] %s", p.mapping.Listen.Port, r.URL.String(), p.mapping.Local)
		p.serveFile(w, r)
		return
	}

	targetURL, err := p.buildTargetURL(r)
	if err != nil {
		http.Error(w, "Failed to build target URL", http.StatusInternalServerError)
		log.Printf("Error building target URL: %v", err)
		return
	}

	log.Printf("[DEDICATED:%d] %s -> %s", p.mapping.Listen.Port, r.URL.String(), targetURL)

	proxyReq, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, "Failed to create proxy request", http.StatusInternalServerError)
		log.Printf("Error creating request: %v", err)
		return
	}

	copyHeaders(proxyReq.Header, r.Header)

	targetParsed, _ := url.Parse(targetURL)
	proxyReq.Host = targetParsed.Host
	proxyReq.Header.Set("Host", targetParsed.Host)

	for key, value := range p.mapping.Headers {
		proxyReq.Header.Set(key, value)
	}

	if len(p.mapping.Cc) > 0 {
		go p.carbonCopyRequest(proxyReq, p.mapping.Cc)
	}

	resp, err := p.client.Do(proxyReq)
	if err != nil {
		http.Error(w, "Failed to proxy request", http.StatusBadGateway)
		log.Printf("Error proxying request: %v", err)
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	setCorsHeaders(w.Header())

	body, err := p.modifyResponseBody(resp)
	if err != nil {
		http.Error(w, "Failed to modify response body", http.StatusInternalServerError)
		log.Printf("Error modifying response body: %v", err)
		return
	}

	w.Header().Set("Content-Length", string(len(body)))
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

func (p *DedicatedProxy) buildTargetURL(r *http.Request) (string, error) {
	fromPath := p.mapping.From
	toPath := p.mapping.To

	originalPath := r.URL.Path

	if strings.HasSuffix(fromPath, "*") {
		fromPathPrefix := strings.TrimSuffix(fromPath, "*")
		toPathPrefix := strings.TrimSuffix(toPath, "*")

		if strings.HasPrefix(originalPath, fromPathPrefix) {
			remainingPath := strings.TrimPrefix(originalPath, fromPathPrefix)
			newPath := toPathPrefix + remainingPath
			
			parsedURL, err := url.Parse(newPath)
			if err != nil {
				return "", err
			}
			
			parsedURL.RawQuery = r.URL.RawQuery
			return parsedURL.String(), nil
		}
	}

	// Exact match
	parsedURL, err := url.Parse(toPath)
	if err != nil {
		return "", err
	}
	parsedURL.RawQuery = r.URL.RawQuery
	return parsedURL.String(), nil
}

func (p *DedicatedProxy) carbonCopyRequest(req *http.Request, ccTargets []string) {
	for _, target := range ccTargets {
		go func(targetURL string) {
			var bodyBytes []byte
			if req.Body != nil {
				bodyBytes, _ = io.ReadAll(req.Body)
				req.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
			}

			ccReq, err := http.NewRequest(req.Method, targetURL, strings.NewReader(string(bodyBytes)))
			if err != nil {
				log.Printf("[CC DEDICATED:%d] Error creating request for %s: %v", p.mapping.Listen.Port, targetURL, err)
				return
			}
			copyHeaders(ccReq.Header, req.Header)

			resp, err := p.client.Do(ccReq)
			if err != nil {
				log.Printf("[CC DEDICATED:%d] Error sending request to %s: %v", p.mapping.Listen.Port, targetURL, err)
				return
			}
			defer resp.Body.Close()
			log.Printf("[CC DEDICATED:%d] Request sent to %s, status: %d", p.mapping.Listen.Port, targetURL, resp.StatusCode)
		}(target)
	}
}

func (p *DedicatedProxy) serveFile(w http.ResponseWriter, r *http.Request) {
	localPath := p.mapping.Local
	if strings.HasSuffix(localPath, "*") {
		basePath := strings.TrimSuffix(localPath, "*")
		fromBasePath := strings.TrimSuffix(p.mapping.From, "*")
		requestedPath := strings.TrimPrefix(r.URL.Path, fromBasePath)
		localPath = filepath.Join(basePath, requestedPath)
	}

	content, err := ioutil.ReadFile(localPath)
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

func (p *DedicatedProxy) modifyResponseBody(resp *http.Response) ([]byte, error) {
	if resp.Body == nil {
		return nil, nil
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	// Match
	if p.mapping.Match != "" {
		re, err := regexp.Compile(p.mapping.Match)
		if err != nil {
			log.Printf("Invalid match regex: %v", err)
			return body, nil
		}
		matches := re.FindSubmatch(body)
		if len(matches) > 1 {
			body = matches[1]
		} else {
			body = []byte{}
		}
	}

	// Replace
	if len(p.mapping.Replace) > 0 {
		tempBody := string(body)
		for key, value := range p.mapping.Replace {
			re, err := regexp.Compile(key)
			if err != nil {
				log.Printf("Invalid replace regex: %v", err)
				continue
			}
			tempBody = re.ReplaceAllString(tempBody, value)
		}
		body = []byte(tempBody)
	}

	return body, nil
}