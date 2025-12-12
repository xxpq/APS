package main

import (
	"io"
	"log"
	"net/http"
)

func (p *MapRemoteProxy) carbonCopyRequest(req *http.Request, ccTargets []string) {
	// We must not read req.Body directly as it is being read by the main request concurrently.
	// We use req.GetBody() which gives us a fresh reader if available.
	// In handleHTTP, we ensured the body is a bytes.Reader, so GetBody should be set.
	var getBody func() (io.ReadCloser, error)
	if req.GetBody != nil {
		getBody = req.GetBody
	} else if req.Body != nil {
		// Fallback: If GetBody is not set, we can't safely read req.Body concurrently.
		// However, since we control request creation, this shouldn't happen for mapped requests with body.
		// If it does, we skip body for CC to avoid race/corruption of main request.
		log.Printf("[CC] Warning: req.GetBody is nil, sending CC without body to avoid race condition.")
		getBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
	} else {
		getBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
	}

	for _, target := range ccTargets {
		go func(targetURL string) {
			bodyReader, err := getBody()
			if err != nil {
				log.Printf("[CC] Error getting body for %s: %v", targetURL, err)
				return
			}
			defer bodyReader.Close()

			ccReq, err := http.NewRequest(req.Method, targetURL, bodyReader)
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
