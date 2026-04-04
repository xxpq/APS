package main

import (
	"net"
	"strconv"
	"testing"
)

func TestBuildGridICECandidatesIncludesHost(t *testing.T) {
	const (
		host = "127.0.0.1"
		port = 8443
	)
	candidates := buildGridICECandidates(host, port)
	if len(candidates) == 0 {
		t.Fatal("expected non-empty candidate list")
	}

	expected := net.JoinHostPort(host, strconv.Itoa(port))
	found := false
	for _, candidate := range candidates {
		if candidate == expected {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected candidate list to contain %s, got %v", expected, candidates)
	}
}

func TestExpandGridICECandidateTemplates(t *testing.T) {
	out := expandGridICECandidateTemplates(
		[]string{
			"{host}",
			"{host}:{port}",
			"$HOST:$PORT",
			"udp://$HOST:$PORT",
			"candidate:1 1 udp 1 $HOST $PORT typ host",
		},
		"198.51.100.1",
		9443,
	)
	if len(out) == 0 {
		t.Fatal("expected expanded candidates")
	}
	expected := map[string]bool{
		"[198.51.100.1]:9443":                            false,
		"198.51.100.1:9443":                              false,
		"udp://198.51.100.1:9443":                        false,
		"candidate:1 1 udp 1 198.51.100.1 9443 typ host": false,
	}
	for _, candidate := range out {
		if _, ok := expected[candidate]; ok {
			expected[candidate] = true
		}
	}
	if !expected["198.51.100.1:9443"] {
		t.Fatalf("expected host:port candidate in expanded list, got %v", out)
	}
	if !expected["udp://198.51.100.1:9443"] {
		t.Fatalf("expected udp url candidate in expanded list, got %v", out)
	}
	if !expected["candidate:1 1 udp 1 198.51.100.1 9443 typ host"] {
		t.Fatalf("expected SDP candidate in expanded list, got %v", out)
	}
}

func TestBuildGridICECandidatesWithExtras(t *testing.T) {
	const (
		host = "127.0.0.1"
		port = 443
	)
	out := buildGridICECandidatesWithExtras(host, port, []string{"udp://{host}:{port}", "203.0.113.8:3478"})
	if len(out) == 0 {
		t.Fatal("expected candidates")
	}
	want := map[string]bool{
		"udp://127.0.0.1:443": false,
		"203.0.113.8:3478":    false,
	}
	for _, candidate := range out {
		if _, ok := want[candidate]; ok {
			want[candidate] = true
		}
	}
	for candidate, seen := range want {
		if !seen {
			t.Fatalf("missing expected extra candidate %s in %v", candidate, out)
		}
	}
}

func TestMergeGridICECandidateSets(t *testing.T) {
	merged := mergeGridICECandidateSets(
		[]string{"203.0.113.10:443", "198.51.100.8:3478"},
		[]string{"203.0.113.10:443", "  ", "192.168.1.10:5000"},
	)
	if len(merged) != 3 {
		t.Fatalf("expected merged unique candidates=3 got %d (%v)", len(merged), merged)
	}
}
