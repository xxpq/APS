package main

import "testing"

func TestShouldUseInsecureBackendMode(t *testing.T) {
	trueValue := true
	falseValue := false

	tests := []struct {
		name      string
		toConfig  *EndpointConfig
		targetURL string
		want      bool
	}{
		{
			name:      "nil mapping config remains secure",
			toConfig:  nil,
			targetURL: "https://10.1.2.3/",
			want:      false,
		},
		{
			name:      "explicit insecure true wins",
			toConfig:  &EndpointConfig{Insecure: &trueValue},
			targetURL: "https://example.com/",
			want:      true,
		},
		{
			name:      "explicit insecure false wins over internal IP",
			toConfig:  &EndpointConfig{Insecure: &falseValue},
			targetURL: "https://10.1.2.3/",
			want:      false,
		},
		{
			name:      "auto insecure for https private IP",
			toConfig:  &EndpointConfig{},
			targetURL: "https://10.1.2.3/",
			want:      true,
		},
		{
			name:      "auto insecure for wss private IP",
			toConfig:  &EndpointConfig{},
			targetURL: "wss://192.168.10.20/ws",
			want:      true,
		},
		{
			name:      "public host remains secure by default",
			toConfig:  &EndpointConfig{},
			targetURL: "https://example.com/",
			want:      false,
		},
		{
			name:      "non TLS scheme remains secure by default",
			toConfig:  &EndpointConfig{},
			targetURL: "http://10.1.2.3/",
			want:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldUseInsecureBackendMode(tc.toConfig, tc.targetURL)
			if got != tc.want {
				t.Fatalf("shouldUseInsecureBackendMode(%q) = %v, want %v", tc.targetURL, got, tc.want)
			}
		})
	}
}
