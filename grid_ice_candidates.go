package main

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"
)

func buildGridICECandidates(host string, port int) []string {
	return buildGridICECandidatesWithExtras(host, port, nil)
}

func buildGridICECandidatesWithExtras(host string, port int, extras []string) []string {
	host = strings.TrimSpace(host)
	if host == "" || port <= 0 {
		return nil
	}

	candidateMap := make(map[string]struct{})
	appendCandidate := func(h string) {
		h = strings.TrimSpace(h)
		if h == "" {
			return
		}
		candidateMap[net.JoinHostPort(h, strconv.Itoa(port))] = struct{}{}
	}

	appendCandidate(host)

	lookupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(lookupCtx, "ip", host)
	if err == nil {
		for _, ip := range ips {
			if ip == nil {
				continue
			}
			appendCandidate(ip.String())
		}
	}
	for _, extraCandidate := range expandGridICECandidateTemplates(extras, host, port) {
		candidateMap[extraCandidate] = struct{}{}
	}

	out := make([]string, 0, len(candidateMap))
	for candidate := range candidateMap {
		out = append(out, candidate)
	}
	return out
}

func mergeGridICECandidateSets(groups ...[]string) []string {
	total := 0
	for _, group := range groups {
		total += len(group)
	}
	if total == 0 {
		return nil
	}
	seen := make(map[string]struct{}, total)
	out := make([]string, 0, total)
	for _, group := range groups {
		for _, candidate := range group {
			c := strings.TrimSpace(candidate)
			if c == "" {
				continue
			}
			if _, exists := seen[c]; exists {
				continue
			}
			seen[c] = struct{}{}
			out = append(out, c)
		}
	}
	return out
}

func expandGridICECandidateTemplates(templates []string, host string, port int) []string {
	host = strings.TrimSpace(host)
	if len(templates) == 0 || host == "" || port <= 0 {
		return nil
	}
	portStr := strconv.Itoa(port)
	seen := make(map[string]struct{}, len(templates))
	out := make([]string, 0, len(templates))
	for _, candidate := range templates {
		c := strings.TrimSpace(candidate)
		if c == "" {
			continue
		}
		c = strings.ReplaceAll(c, "{host}", host)
		c = strings.ReplaceAll(c, "{port}", portStr)
		c = strings.ReplaceAll(c, "$HOST", host)
		c = strings.ReplaceAll(c, "$PORT", portStr)
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(c), "candidate:") && !strings.Contains(c, "://") {
			if _, _, err := net.SplitHostPort(c); err != nil {
				c = net.JoinHostPort(c, portStr)
			}
		}
		if _, exists := seen[c]; exists {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}
