package security

import "testing"

// TestShouldUseInsecureBackendMode verifies the projection-based decision
// logic. Stage 9.2 moved this test out of root main into the aps/security
// sub-package so the test exercises the package's exported API directly
// (rather than going through the now-deleted root-main wrapper).
func TestShouldUseInsecureBackendMode(t *testing.T) {
	trueValue := true
	falseValue := false

	tests := []struct {
		name      string
		projection *EndpointConfigProjection
		targetURL string
		want      bool
	}{
		{
			name:       "nil projection remains secure",
			projection: nil,
			targetURL:  "https://10.1.2.3/",
			want:       false,
		},
		{
			name:       "explicit insecure true wins",
			projection: &EndpointConfigProjection{Insecure: &trueValue},
			targetURL:  "https://example.com/",
			want:       true,
		},
		{
			name:       "explicit insecure false wins over internal IP",
			projection: &EndpointConfigProjection{Insecure: &falseValue},
			targetURL:  "https://10.1.2.3/",
			want:       false,
		},
		{
			name:       "auto insecure for https private IP",
			projection: &EndpointConfigProjection{},
			targetURL:  "https://10.1.2.3/",
			want:       true,
		},
		{
			name:       "auto insecure for wss private IP",
			projection: &EndpointConfigProjection{},
			targetURL:  "wss://192.168.10.20/ws",
			want:       true,
		},
		{
			name:       "public host remains secure by default",
			projection: &EndpointConfigProjection{},
			targetURL:  "https://example.com/",
			want:       false,
		},
		{
			name:       "non TLS scheme remains secure by default",
			projection: &EndpointConfigProjection{},
			targetURL:  "http://10.1.2.3/",
			want:       false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ShouldUseInsecureBackendMode(tc.projection, tc.targetURL)
			if got != tc.want {
				t.Fatalf("ShouldUseInsecureBackendMode(%q) = %v, want %v", tc.targetURL, got, tc.want)
			}
		})
	}
}
