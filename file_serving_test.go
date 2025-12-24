package main

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDedicatedProxy_ServeFile_RelativePath(t *testing.T) {
	// Create a temporary subdirectory in current working directory
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	tempSubDir := filepath.Join(cwd, "test_relative_path")
	if err := os.MkdirAll(tempSubDir, 0755); err != nil {
		t.Fatalf("Failed to create temp subdir: %v", err)
	}
	defer os.RemoveAll(tempSubDir)

	// Create index.html in the temp subdirectory
	testContent := "<html><body><h1>Relative Path Test</h1></body></html>"
	testPath := filepath.Join(tempSubDir, "index.html")
	if err := ioutil.WriteFile(testPath, []byte(testContent), 0644); err != nil {
		t.Fatalf("Failed to create index.html: %v", err)
	}

	// Use relative path (with ./ prefix) pointing to directory
	toURL := "file://./test_relative_path"

	// Parse the mapping to populate internal fields
	fromConfig, _ := parseEndpointConfig("/rel")
	toConfig, _ := parseEndpointConfig(toURL)

	mapping := &Mapping{
		From:       "/rel",
		To:         toURL,
		fromConfig: fromConfig,
		toConfig:   toConfig,
	}

	proxy := NewDedicatedProxy(mapping, 8081)

	req, err := http.NewRequest("GET", "http://localhost:8081/rel", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	rr := httptest.NewRecorder()
	proxy.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v (body: %s)",
			status, http.StatusOK, rr.Body.String())
	} else {
		if rr.Body.String() != testContent {
			t.Errorf("Handler returned unexpected body: got %v want %v",
				rr.Body.String(), testContent)
		}
	}
}

func TestDedicatedProxy_ServeFile_DirectFile(t *testing.T) {
	// Create a temporary subdirectory
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	tempSubDir := filepath.Join(cwd, "test_direct_file")
	if err := os.MkdirAll(tempSubDir, 0755); err != nil {
		t.Fatalf("Failed to create temp subdir: %v", err)
	}
	defer os.RemoveAll(tempSubDir)

	// Create test.html in the temp subdirectory
	testContent := "<html><body><h1>Direct File Test</h1></body></html>"
	testPath := filepath.Join(tempSubDir, "test.html")
	if err := ioutil.WriteFile(testPath, []byte(testContent), 0644); err != nil {
		t.Fatalf("Failed to create test.html: %v", err)
	}

	// Use relative path pointing directly to file
	toURL := "file://./test_direct_file/test.html"

	// Parse the mapping to populate internal fields
	fromConfig, _ := parseEndpointConfig("/direct")
	toConfig, _ := parseEndpointConfig(toURL)

	mapping := &Mapping{
		From:       "/direct",
		To:         toURL,
		fromConfig: fromConfig,
		toConfig:   toConfig,
	}

	proxy := NewDedicatedProxy(mapping, 8082)

	req, err := http.NewRequest("GET", "http://localhost:8082/direct", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	rr := httptest.NewRecorder()
	proxy.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v (body: %s)",
			status, http.StatusOK, rr.Body.String())
	} else {
		if rr.Body.String() != testContent {
			t.Errorf("Handler returned unexpected body: got %v want %v",
				rr.Body.String(), testContent)
		}
	}
}
