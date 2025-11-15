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
	Version string     `json:"version"`
	Creator HarCreator `json:"creator"`
	Entries []HarEntry `json:"entries"`
}

type HarCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type HarEntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            float64     `json:"time"`
	Request         HarRequest  `json:"request"`
	Response        HarResponse `json:"response"`
	Cache           HarCache    `json:"cache"`
	Timings         HarTimings  `json:"timings"`
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
	Status      int               `json:"status"`
	StatusText  string            `json:"statusText"`
	HTTPVersion string            `json:"httpVersion"`
	Cookies     []HarCookie       `json:"cookies"`
	Headers     []HarHeader       `json:"headers"`
	Content     HarContentDetails `json:"content"`
	RedirectURL string            `json:"redirectURL"`
	HeadersSize int64             `json:"headersSize"`
	BodySize    int64             `json:"bodySize"`
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

// HarLogger manages a single HAR log file.
type HarLogger struct {
	mu       sync.Mutex
	log      *HarLog
	filePath string
}

// HarLoggerManager manages multiple HarLogger instances.
type HarLoggerManager struct {
	mu      sync.Mutex
	loggers map[string]*HarLogger
	config  *Config
}

func NewHarLoggerManager(config *Config) *HarLoggerManager {
	return &HarLoggerManager{
		loggers: make(map[string]*HarLogger),
		config:  config,
	}
}

// GetLogger retrieves or creates a HarLogger for a given file path.
func (m *HarLoggerManager) GetLogger(filePath string) *HarLogger {
	m.mu.Lock()
	defer m.mu.Unlock()

	if logger, exists := m.loggers[filePath]; exists {
		return logger
	}

	logger := newHarLogger(filePath)
	m.loggers[filePath] = logger
	return logger
}

// LogEntry logs a HAR entry to all specified file paths.
func (m *HarLoggerManager) LogEntry(filePaths []string, entry HarEntry) {
	for _, path := range filePaths {
		if path != "" {
			logger := m.GetLogger(path)
			logger.addEntry(entry)
		}
	}
}

// Shutdown saves all managed HAR logs to their respective files.
func (m *HarLoggerManager) Shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	log.Println("Shutting down HAR logger manager, saving all logs...")
	for _, logger := range m.loggers {
		logger.saveToFile()
	}
}

// newHarLogger creates a new HarLogger instance.
func newHarLogger(filePath string) *HarLogger {
	// Attempt to read existing file
	existingData, err := os.ReadFile(filePath)
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

	// Create a new log if file doesn't exist or is invalid
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

func (h *HarLogger) addEntry(entry HarEntry) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.log.Log.Entries = append(h.log.Log.Entries, entry)
}

func (h *HarLogger) saveToFile() {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Ensure directory exists
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
