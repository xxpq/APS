package main

import (
	"net/http"
	"net/url"
	"testing"
)

func TestIsTunnelConnectRequest(t *testing.T) {
	tests := []struct {
		name string
		req  *http.Request
		want bool
	}{
		{
			name: "connect-path",
			req: &http.Request{
				Method:     http.MethodConnect,
				URL:        &url.URL{Path: "/.tunnel"},
				RequestURI: "/.tunnel",
			},
			want: true,
		},
		{
			name: "connect-opaque-path",
			req: &http.Request{
				Method: http.MethodConnect,
				URL:    &url.URL{Opaque: "/.tunnel"},
			},
			want: true,
		},
		{
			name: "connect-opaque-no-slash",
			req: &http.Request{
				Method: http.MethodConnect,
				URL:    &url.URL{Opaque: ".tunnel"},
			},
			want: true,
		},
		{
			name: "connect-absolute-uri",
			req: &http.Request{
				Method:     http.MethodConnect,
				RequestURI: "https://aps.example.com/.tunnel",
			},
			want: true,
		},
		{
			name: "connect-authority-form",
			req: &http.Request{
				Method:     http.MethodConnect,
				RequestURI: "aps.example.com:443",
			},
			want: false,
		},
		{
			name: "get-path",
			req: &http.Request{
				Method:     http.MethodGet,
				URL:        &url.URL{Path: "/.tunnel"},
				RequestURI: "/.tunnel",
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isTunnelConnectRequest(tc.req)
			if got != tc.want {
				t.Fatalf("isTunnelConnectRequest() = %v, want %v", got, tc.want)
			}
		})
	}
}
