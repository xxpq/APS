package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"time"
)

func (p *MapRemoteProxy) logHarEntry(req *http.Request, resp *http.Response, startTime time.Time, mapping *Mapping, user *User) {
	if p.harManager == nil {
		return
	}

	harEntry, err := p.createHarEntry(req, resp, startTime)
	if err != nil {
		log.Printf("Error creating HAR entry: %v", err)
		return
	}

	p.harManager.LogEntry(*harEntry, p.serverName, mapping, user)
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
		bodyBytes, _ = ioutil.ReadAll(req.Body)
		req.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
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
		bodyBytes, _ = ioutil.ReadAll(resp.Body)
		resp.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
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