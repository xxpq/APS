package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"sync"
)

// HAR Structs based on HAR 1.2 Spec
type HarLog struct {
	Log HarContent `json:"log"`
}

type HarContent struct {
	Version string      `json:"version"`
	Creator HarCreator  `json:"creator"`
	Entries []HarEntry  `json:"entries"`
}

type HarCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type HarEntry struct {
	StartedDateTime string        `json:"startedDateTime"`
	Time            float64       `json:"time"`
	Request         HarRequest    `json:"request"`
	Response        HarResponse   `json:"response"`
	Cache           HarCache      `json:"cache"`
	Timings         HarTimings    `json:"timings"`
}

type HarRequest struct {
	Method      string         `json:"method"`
	URL         string         `json:"url"`
	HTTPVersion string         `json:"httpVersion"`
	Cookies     []HarCookie    `json:"cookies"`
	Headers     []HarHeader    `json:"headers"`
	QueryString []HarQueryPair `json:"queryString"`
	PostData    *HarPostData   `json:"postData,omitempty"`
	HeadersSize int64          `json:"headersSize"`
	BodySize    int64          `json:"bodySize"`
}

type HarResponse struct {
	Status      int         `json:"status"`
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Cookies     []HarCookie `json:"cookies"`
	Headers     []HarHeader `json:"headers"`
	Content     HarContentDetails `json:"content"`
	RedirectURL string      `json:"redirectURL"`
	HeadersSize int64       `json:"headersSize"`
	BodySize    int64       `json:"bodySize"`
}

type HarHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HarCookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HarQueryPair struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HarPostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

type HarContentDetails struct {
	Size     int64  `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
	Encoding string `json:"encoding,omitempty"`
}

type HarCache struct{}

type HarTimings struct {
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}

// HarLogger manages the HAR log
type HarLogger struct {
	mu  sync.Mutex
	log *HarLog
}

func NewHarLogger() *HarLogger {
	return &HarLogger{
		log: &HarLog{
			Log: HarContent{
				Version: "1.2",
				Creator: HarCreator{
					Name:    "Cato Proxy",
					Version: "1.0",
				},
				Entries: make([]HarEntry, 0),
			},
		},
	}
}

func (h *HarLogger) AddEntry(entry HarEntry) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.log.Log.Entries = append(h.log.Log.Entries, entry)
}

func (h *HarLogger) SaveToFile(filename string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	data, err := json.MarshalIndent(h.log, "", "  ")
	if err != nil {
		log.Printf("Error marshalling HAR log: %v", err)
		return
	}

	err = ioutil.WriteFile(filename, data, 0644)
	if err != nil {
		log.Printf("Error writing HAR file: %v", err)
	} else {
		log.Printf("HAR log saved to %s", filename)
	}
}