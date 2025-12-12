package main

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"time"
)

func (p *MapRemoteProxy) logHarEntry(req *http.Request, resp *http.Response, startTime time.Time, mapping *Mapping, user *User) {
	if p.harManager == nil {
		return
	}

	dumpPaths := p.collectDumpPaths(mapping, user)
	if len(dumpPaths) == 0 {
		return
	}

	harEntry, err := p.createHarEntry(req, resp, startTime)
	if err != nil {
		log.Printf("Error creating HAR entry: %v", err)
		return
	}

	p.harManager.LogEntry(dumpPaths, *harEntry)
}

// collectDumpPaths gathers all unique dump file paths from server, mapping, user, and groups.
func (p *MapRemoteProxy) collectDumpPaths(mapping *Mapping, user *User) []string {
	paths := make(map[string]struct{})

	// Server level
	if server, ok := p.config.Servers[p.serverName]; ok && server.Dump != "" {
		paths[server.Dump] = struct{}{}
	}

	// Mapping level
	if mapping != nil && mapping.Dump != "" {
		paths[mapping.Dump] = struct{}{}
	}

	// User and Group levels
	if user != nil {
		if user.Dump != "" {
			paths[user.Dump] = struct{}{}
		}
		if p.config.Auth != nil && p.config.Auth.Groups != nil {
			for _, groupName := range user.Groups {
				if group, ok := p.config.Auth.Groups[groupName]; ok && group.Dump != "" {
					paths[group.Dump] = struct{}{}
				}
			}
		}
	}

	// Convert map keys to a slice
	result := make([]string, 0, len(paths))
	for path := range paths {
		result = append(result, path)
	}
	return result
}

func (p *MapRemoteProxy) createHarEntry(req *http.Request, resp *http.Response, startTime time.Time) (*HarEntry, error) {
	harReq, err := p.createHarRequest(req)
	if err != nil {
		return nil, err
	}

	var harResp HarResponse
	if resp != nil {
		harResp, err = p.createHarResponse(resp)
		if err != nil {
			return nil, err
		}
	}

	return &HarEntry{
		StartedDateTime: startTime.Format(time.RFC3339),
		Time:            float64(time.Since(startTime).Milliseconds()),
		Request:         *harReq,
		Response:        harResp,
		Cache:           HarCache{},
		Timings: HarTimings{
			Send:    0,
			Wait:    float64(time.Since(startTime).Milliseconds()),
			Receive: 0,
		},
	}, nil
}

func (p *MapRemoteProxy) createHarRequest(req *http.Request) (*HarRequest, error) {
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	headers := make([]HarHeader, 0)
	for name, values := range req.Header {
		for _, value := range values {
			headers = append(headers, HarHeader{Name: name, Value: value})
		}
	}

	queryString := make([]HarQueryPair, 0)
	for name, values := range req.URL.Query() {
		for _, value := range values {
			queryString = append(queryString, HarQueryPair{Name: name, Value: value})
		}
	}

	var postData *HarPostData
	if len(bodyBytes) > 0 {
		postData = &HarPostData{
			MimeType: req.Header.Get("Content-Type"),
			Text:     string(bodyBytes),
		}
	}

	reqDump, _ := httputil.DumpRequest(req, false)

	return &HarRequest{
		Method:      req.Method,
		URL:         req.URL.String(),
		HTTPVersion: req.Proto,
		Headers:     headers,
		QueryString: queryString,
		PostData:    postData,
		HeadersSize: int64(len(reqDump)),
		BodySize:    req.ContentLength,
	}, nil
}

func (p *MapRemoteProxy) createHarResponse(resp *http.Response) (HarResponse, error) {
	var bodyBytes []byte
	if resp.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[HAR] Error reading response body: %v", err)
			// We must still restore the body (what we read so far) to allow downstream to see at least that (or the error)
			// But since we consumed it, the original error is lost to the downstream unless we propagate it?
			// Actually, if we return what we got, downstream sees partial data and no error from Read().
			// This might explain "0 bytes" if it failed immediately.
		}
		resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	headers := make([]HarHeader, 0)
	for name, values := range resp.Header {
		for _, value := range values {
			headers = append(headers, HarHeader{Name: name, Value: value})
		}
	}

	respDump, _ := httputil.DumpResponse(resp, false)

	return HarResponse{
		Status:      resp.StatusCode,
		StatusText:  resp.Status,
		HTTPVersion: resp.Proto,
		Headers:     headers,
		Content: HarContentDetails{
			Size:     int64(len(bodyBytes)),
			MimeType: resp.Header.Get("Content-Type"),
			Text:     string(bodyBytes),
		},
		RedirectURL: resp.Header.Get("Location"),
		HeadersSize: int64(len(respDump)),
		BodySize:    resp.ContentLength,
	}, nil
}
