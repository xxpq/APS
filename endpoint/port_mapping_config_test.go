package main

import (
	"encoding/json"
	"testing"
)

func TestPortMappingConfigLocalListenNumber(t *testing.T) {
	raw := []byte(`{"localListen":8080,"targetEndpoint":"node-b","remoteTarget":"127.0.0.1:80"}`)
	var mapping PortMappingConfig
	if err := json.Unmarshal(raw, &mapping); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if mapping.LocalListen != "0.0.0.0:8080" {
		t.Fatalf("expected normalized localListen 0.0.0.0:8080 got %s", mapping.LocalListen)
	}
}

func TestPortMappingConfigLocalListenStringForms(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		expected string
	}{
		{
			name:     "wildcard short form",
			raw:      `{"localListen":":18080","targetEndpoint":"node-b","remoteTarget":"127.0.0.1:80"}`,
			expected: "0.0.0.0:18080",
		},
		{
			name:     "explicit host",
			raw:      `{"localListen":"127.0.0.2:28080","targetEndpoint":"node-b","remoteTarget":"127.0.0.1:80"}`,
			expected: "127.0.0.2:28080",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mapping PortMappingConfig
			if err := json.Unmarshal([]byte(tc.raw), &mapping); err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}
			if mapping.LocalListen != tc.expected {
				t.Fatalf("expected localListen=%s got %s", tc.expected, mapping.LocalListen)
			}
		})
	}
}

func TestPortMappingConfigRequiresLocalListen(t *testing.T) {
	raw := []byte(`{"localPort":8080,"targetEndpoint":"node-b","remoteTarget":"127.0.0.1:80"}`)
	var mapping PortMappingConfig
	if err := json.Unmarshal(raw, &mapping); err == nil {
		t.Fatal("expected unmarshal to fail when localListen is missing")
	}
}
