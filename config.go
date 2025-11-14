package main

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"strings"
	"sync"
)

type Config struct {
	Mappings []Mapping `json:"mappings"`
	mu       sync.RWMutex
}

type Mapping struct {
	From    string            `json:"from"`
	To      string            `json:"to,omitempty"`
	Local   string            `json:"local,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Listen  *ListenConfig     `json:"listen,omitempty"`
	Cc      []string          `json:"cc,omitempty"`
	Match   string            `json:"match,omitempty"`
	Replace map[string]string `json:"replace,omitempty"`
}

type ListenConfig struct {
	Port int
	Cert interface{} // string ("auto") or CertFiles
	Key  string
}

type CertFiles struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

func (lc *ListenConfig) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as an int first
	var port int
	if err := json.Unmarshal(data, &port); err == nil {
		lc.Port = port
		return nil
	}

	// If that fails, try to unmarshal as an object
	var obj struct {
		Port int         `json:"port"`
		Cert interface{} `json:"cert"`
		Key  string      `json:"key"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}

	lc.Port = obj.Port
	lc.Key = obj.Key

	// Check the type of Cert
	if certStr, ok := obj.Cert.(string); ok {
		if certStr != "auto" {
			return errors.New("cert string must be 'auto'")
		}
		lc.Cert = "auto"
	} else if certMap, ok := obj.Cert.(map[string]interface{}); ok {
		files := CertFiles{}
		if c, ok := certMap["cert"].(string); ok {
			files.Cert = c
		}
		if k, ok := certMap["key"].(string); ok {
			files.Key = k
		}
		lc.Cert = files
	} else if obj.Cert != nil {
		return errors.New("invalid type for 'cert' field")
	}

	return nil
}

func LoadConfig(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var config Config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}

	for i := range config.Mappings {
		config.Mappings[i].From = strings.TrimSpace(config.Mappings[i].From)
		config.Mappings[i].To = strings.TrimSpace(config.Mappings[i].To)
		config.Mappings[i].From = strings.Trim(config.Mappings[i].From, "`")
		config.Mappings[i].To = strings.Trim(config.Mappings[i].To, "`")
	}

	return &config, nil
}

func (c *Config) Reload(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	var newConfig Config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&newConfig); err != nil {
		return err
	}

	for i := range newConfig.Mappings {
		newConfig.Mappings[i].From = strings.TrimSpace(newConfig.Mappings[i].From)
		newConfig.Mappings[i].To = strings.TrimSpace(newConfig.Mappings[i].To)
		newConfig.Mappings[i].From = strings.Trim(newConfig.Mappings[i].From, "`")
		newConfig.Mappings[i].To = strings.Trim(newConfig.Mappings[i].To, "`")
	}

	c.mu.Lock()
	c.Mappings = newConfig.Mappings
	c.mu.Unlock()

	log.Printf("Configuration reloaded: %d mapping rules", len(c.Mappings))
	for _, mapping := range c.Mappings {
		headersInfo := ""
		if len(mapping.Headers) > 0 {
			headersInfo = " (with custom headers)"
		}
		log.Printf("  %s -> %s%s", mapping.From, mapping.To, headersInfo)
	}

	return nil
}

func (c *Config) GetMappings() []Mapping {
	c.mu.RLock()
	defer c.mu.RUnlock()

	mappings := make([]Mapping, len(c.Mappings))
	copy(mappings, c.Mappings)
	return mappings
}
