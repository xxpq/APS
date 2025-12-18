package main

import "testing"

func TestIsTextContentType(t *testing.T) {
	tests := []struct {
		contentType string
		want        bool
	}{
		{"text/html", true},
		{"text/plain", true},
		{"application/json", true},
		{"application/xml", true},
		{"application/javascript", true},
		{"application/ecmascript", true},
		{"text/css", true},
		{"text/csv", true},
		{"application/x-yaml", true},
		{"image/png", false},
		{"image/jpeg", false},
		{"application/octet-stream", false},
		{"application/pdf", false},
		{"video/mp4", false},
		{"", false},
		{"TEXT/HTML", true}, // Case insensitive check
	}

	for _, tt := range tests {
		t.Run(tt.contentType, func(t *testing.T) {
			if got := isTextContentType(tt.contentType); got != tt.want {
				t.Errorf("isTextContentType(%q) = %v, want %v", tt.contentType, got, tt.want)
			}
		})
	}
}
