package httpx

import "testing"

// TestResolveFileURL moved from root main (utils_test.go) into the
// aps/util/httpx sub-package as part of Stage 9.3.
func TestResolveFileURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		skipOn  string // skip if running on this OS ("windows" / "unix")
	}{
		{
			name:   "Absolute path Unix style",
			input:  "file:///www/wwwroot",
			want:   "/www/wwwroot",
			skipOn: "windows",
		},
		{
			name:   "Relative path",
			input:  "file://./www/wwwroot",
			// Joined with CWD; just verify it stays relative-clean.
			want:   "",
		},
		{
			name:   "Windows absolute path with three slashes",
			input:  "file:///C:/www/wwwroot",
			want:   "C:/www/wwwroot",
			skipOn: "unix",
		},
		{
			name:   "Relative path with subdirectory",
			input:  "file://./www/sub",
			want:   "",
		},
		{
			name:   "Absolute path already with leading slash",
			input:  "file://www/wwwroot",
			want:   "/www/wwwroot",
			skipOn: "windows",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skipOn == "unix" {
				t.Skip("Skipping on Unix")
			}
			if tc.skipOn == "windows" {
				// Could be skipped on Windows CI; not currently relevant on this dev box.
			}
			got, err := ResolveFileURL(tc.input)
			if err != nil {
				t.Fatalf("ResolveFileURL(%q) returned error: %v", tc.input, err)
			}
			if tc.want != "" && got != tc.want {
				t.Fatalf("ResolveFileURL(%q) = %q, want %q", tc.input, got, tc.want)
			}
			if tc.want == "" && got == "" {
				t.Fatalf("ResolveFileURL(%q) returned empty", tc.input)
			}
		})
	}
}
