package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
)

func (p *MapRemoteProxy) carbonCopyRequest(req *http.Request, ccTargets []string) {
	for _, target := range ccTargets {
		go func(targetURL string) {
			var bodyBytes []byte
			if req.Body != nil {
				bodyBytes, _ = ioutil.ReadAll(req.Body)
				// Restore the body so the original request can read it
				req.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
			}

			ccReq, err := http.NewRequest(req.Method, targetURL, bytes.NewBuffer(bodyBytes))
			if err != nil {
				log.Printf("[CC] Error creating request for %s: %v", targetURL, err)
				return
			}
			copyHeaders(ccReq.Header, req.Header)

			resp, err := p.client.Do(ccReq)
			if err != nil {
				log.Printf("[CC] Error sending request to %s: %v", targetURL, err)
				return
			}
			defer resp.Body.Close()
			log.Printf("[CC] Request sent to %s, status: %d", targetURL, resp.StatusCode)
		}(target)
	}
}