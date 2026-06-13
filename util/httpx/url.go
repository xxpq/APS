package httpx

import (
	mrand "math/rand"
	"net/url"
	"strings"
)

// PickRandomIP returns a random IP from ips. Returns "" if ips is empty.
func PickRandomIP(ips []string) string {
	if len(ips) == 0 {
		return ""
	}
	if len(ips) == 1 {
		return ips[0]
	}
	return ips[mrand.Intn(len(ips))]
}

// ReplaceHostWithIP substitutes the URL's host with ip, preserving the
// original port (or defaulting to 80/443 when no port was specified).
func ReplaceHostWithIP(originalURL string, ip string) (string, error) {
	parsedURL, err := url.Parse(originalURL)
	if err != nil {
		return "", err
	}

	originalHost := parsedURL.Host
	if strings.Contains(originalHost, ":") {
		hostParts := strings.Split(originalHost, ":")
		if len(hostParts) == 2 {
			parsedURL.Host = ip + ":" + hostParts[1]
		} else {
			parsedURL.Host = ip
		}
	} else {
		if parsedURL.Scheme == "https" {
			parsedURL.Host = ip + ":443"
		} else {
			parsedURL.Host = ip + ":80"
		}
	}

	return parsedURL.String(), nil
}

// ExtractDomain returns the host (no port) portion of rawURL. Falls
// back to splitting the input on "/" if URL parsing fails.
func ExtractDomain(rawURL string) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		parts := strings.Split(rawURL, "/")
		if len(parts) > 0 {
			hostParts := strings.Split(parts[0], ":")
			return hostParts[0]
		}
		return ""
	}
	return parsedURL.Hostname()
}
