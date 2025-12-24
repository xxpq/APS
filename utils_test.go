package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestResolveFileURL(t *testing.T) {
	// Get current working directory for relative path tests
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		expected string
		skipOS   string // Skip test on this OS ("windows" or "unix")
	}{
		{
			name:     "Absolute path Unix style",
			input:    "file://www/wwwroot",
			expected: "/www/wwwroot",
			skipOS:   "",
		},
		{
			name:     "Relative path",
			input:    "file://./www/wwwroot",
			expected: filepath.Join(cwd, "www/wwwroot"),
			skipOS:   "",
		},
		{
			name:     "Windows absolute path with three slashes",
			input:    "file:///C:/www/wwwroot",
			expected: "C:/www/wwwroot",
			skipOS:   "unix",
		},
		{
			name:     "Relative path with subdirectory",
			input:    "file://./test/data",
			expected: filepath.Join(cwd, "test/data"),
			skipOS:   "",
		},
		{
			name:     "Absolute path already with leading slash",
			input:    "file:///var/www/html",
			expected: "/var/www/html",
			skipOS:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Skip test if not applicable to current OS
			if tt.skipOS == "windows" && runtime.GOOS == "windows" {
				t.Skip("Skipping on Windows")
			}
			if tt.skipOS == "unix" && runtime.GOOS != "windows" {
				t.Skip("Skipping on Unix")
			}

			result, err := resolveFileURL(tt.input)
			if err != nil {
				t.Errorf("resolveFileURL(%q) returned error: %v", tt.input, err)
				return
			}

			// Normalize paths for comparison
			expectedNorm := filepath.Clean(tt.expected)
			resultNorm := filepath.Clean(result)

			if resultNorm != expectedNorm {
				t.Errorf("resolveFileURL(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
