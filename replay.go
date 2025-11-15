package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/chromedp/cdproto/har"
)

// ReplayManager handles the logic for replaying HAR entries.
type ReplayManager struct {
	config *Config
	client *http.Client
}

// NewReplayManager creates a new ReplayManager.
func NewReplayManager(config *Config) *ReplayManager {
	return &ReplayManager{
		config: config,
		client: &http.Client{
			// We might want a more sophisticated transport later,
			// e.g., one that can handle insecure certs or specific proxies.
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
			},
			Timeout: 30 * time.Second, // Default timeout
		},
	}
}

// ServeHTTP is the handler for the /.replay endpoint.
func (rm *ReplayManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}

	var harData har.HAR
	if err := json.Unmarshal(body, &harData); err != nil {
		// Try unmarshalling as a single entry
		var entry har.Entry
		if err2 := json.Unmarshal(body, &entry); err2 != nil {
			http.Error(w, fmt.Sprintf("Failed to unmarshal HAR data or a single HAR entry: %v / %v", err, err2), http.StatusBadRequest)
			return
		}
		harData.Log = &har.Log{Entries: []*har.Entry{&entry}}
	}

	if harData.Log == nil || len(harData.Log.Entries) == 0 {
		http.Error(w, "No HAR entries found in the provided data", http.StatusBadRequest)
		return
	}

	log.Printf("[REPLAY] Received %d HAR entries to replay.", len(harData.Log.Entries))

	// For now, we just replay the first entry.
	// A more advanced implementation could replay all or select one.
	entry := harData.Log.Entries[0]

	resp, err := rm.replayRequest(entry)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to replay request: %v", err), http.StatusInternalServerError)
		log.Printf("[REPLAY] Error replaying request: %v", err)
		return
	}
	defer resp.Body.Close()

	log.Printf("[REPLAY] Replayed request to %s, got status %d", entry.Request.URL, resp.StatusCode)

	// Copy headers from replayed response to our response writer
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Copy body
	replayedBody, _ := ioutil.ReadAll(resp.Body)
	w.Write(replayedBody)
}

// replayRequest reconstructs and sends a request based on a HAR entry.
func (rm *ReplayManager) replayRequest(entry *har.Entry) (*http.Response, error) {
	reqDetails := entry.Request

	// Reconstruct body
	var bodyReader strings.Reader
	if reqDetails.PostData != nil {
		bodyReader = *strings.NewReader(reqDetails.PostData.Text)
	}

	// Reconstruct request
	req, err := http.NewRequest(reqDetails.Method, reqDetails.URL, &bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create new request: %w", err)
	}

	// Reconstruct headers
	for _, header := range reqDetails.Headers {
		// Host header is set automatically by Go's http client
		if strings.ToLower(header.Name) != "host" {
			req.Header.Set(header.Name, header.Value)
		}
	}

	// Set Host field for correct routing
	parsedURL, err := url.Parse(reqDetails.URL)
	if err == nil {
		req.Host = parsedURL.Host
	}

	log.Printf("[REPLAY] Replaying %s %s", req.Method, req.URL)
	return rm.client.Do(req)
}