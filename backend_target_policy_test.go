package main

import (
	"aps/config"
	"testing"
)

func TestShouldUseInsecureBackendMode(t *testing.T) {
	trueValue := true
	falseValue := false

	tests := []struct {
		name      string
		ToConfig  *config.EndpointConfig
		targetURL string
		want      bool
	}{
		{
			name:      "nil mapping config remains secure",
			ToConfig:  nil,
			targetURL: "https://10.1.2.3/",
			want:      false,
		},
		{
			name:      "explicit insecure true wins",
			ToConfig:  &config.EndpointConfig{Insecure: &trueValue},
			targetURL: "https://example.com/",
			want:      true,
		},
		{
			name:      "explicit insecure false wins over internal IP",
			ToConfig:  &config.EndpointConfig{Insecure: &falseValue},
			targetURL: "https://10.1.2.3/",
			want:      false,
		},
		{
			name:      "auto insecure for https private IP",
			ToConfig:  &config.EndpointConfig{},
			targetURL: "https://10.1.2.3/",
			want:      true,
		},
		{
			name:      "auto insecure for wss private IP",
			ToConfig:  &config.EndpointConfig{},
			targetURL: "wss://192.168.10.20/ws",
			want:      true,
		},
		{
			name:      "public host remains secure by default",
			ToConfig:  &config.EndpointConfig{},
			targetURL: "https://example.com/",
			want:      false,
		},
		{
			name:      "non TLS scheme remains secure by default",
			ToConfig:  &config.EndpointConfig{},
			targetURL: "http://10.1.2.3/",
			want:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldUseInsecureBackendMode(tc.ToConfig, tc.targetURL)
			if got != tc.want {
				t.Fatalf("shouldUseInsecureBackendMode(%q) = %v, want %v", tc.targetURL, got, tc.want)
			}
		})
	}
}
