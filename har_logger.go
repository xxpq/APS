package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
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
	mu       sync.Mutex
	log      *HarLog
	filePath string
}

func NewHarLogger(filePath string) *HarLogger {
	// 尝试读取现有文件
	existingData, err := ioutil.ReadFile(filePath)
	if err == nil {
		var harLog HarLog
		if json.Unmarshal(existingData, &harLog) == nil {
			log.Printf("[HAR DUMP] Loaded %d existing entries from: %s", len(harLog.Log.Entries), filePath)
			return &HarLogger{
				filePath: filePath,
				log:      &harLog,
			}
		}
		log.Printf("[HAR DUMP] Warning: Could not parse existing HAR file %s, it will be overwritten.", filePath)
	}

	// 如果文件不存在或无法解析，则创建一个新的
	log.Printf("[HAR DUMP] Initialized new HAR logger for: %s", filePath)
	return &HarLogger{
		filePath: filePath,
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

func (h *HarLogger) SaveToFile() {
	h.mu.Lock()
	defer h.mu.Unlock()

	// 确保目录存在
	dir := filepath.Dir(h.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("Error creating directory for HAR file %s: %v", h.filePath, err)
		return
	}

	data, err := json.MarshalIndent(h.log, "", "  ")
	if err != nil {
		log.Printf("Error marshalling HAR log for %s: %v", h.filePath, err)
		return
	}

	err = ioutil.WriteFile(h.filePath, data, 0644)
	if err != nil {
		log.Printf("Error writing HAR file %s: %v", h.filePath, err)
	} else {
		log.Printf("HAR log with %d entries saved to %s", len(h.log.Log.Entries), h.filePath)
	}
}