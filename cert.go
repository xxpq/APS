package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/ocsp"
)

var (
	acmeManager *autocert.Manager

	acmeDomainsMutex sync.RWMutex
	acmeDomains      []string
	acmeDomainSet    = make(map[string]struct{})

	// Fast-reject domain index shared with mapping.go.
	mappingDomainSet      = make(map[string]struct{})
	mappingHasDynamicHost bool
	mappingDomainConfig   *Config
)

const (
	acmeDir = ".cert/acme"

	ocspHTTPTimeout       = 8 * time.Second
	ocspResponseReadLimit = 1 << 20
	ocspRefreshSkew       = 10 * time.Minute
)

func cloneTLSCertificate(cert *tls.Certificate) *tls.Certificate {
	if cert == nil {
		return nil
	}
	cloned := *cert
	if cert.Certificate != nil {
		cloned.Certificate = make([][]byte, len(cert.Certificate))
		for i := range cert.Certificate {
			cloned.Certificate[i] = append([]byte(nil), cert.Certificate[i]...)
		}
	}
	cloned.OCSPStaple = append([]byte(nil), cert.OCSPStaple...)
	cloned.SignedCertificateTimestamps = append([][]byte(nil), cert.SignedCertificateTimestamps...)
	return &cloned
}

func resolveLeafAndIssuer(cert *tls.Certificate) (*x509.Certificate, *x509.Certificate, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return nil, nil, os.ErrInvalid
	}

	leaf := cert.Leaf
	if leaf == nil {
		parsedLeaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, nil, err
		}
		leaf = parsedLeaf
		cert.Leaf = parsedLeaf
	}

	var issuer *x509.Certificate
	for i := 1; i < len(cert.Certificate); i++ {
		candidate, err := x509.ParseCertificate(cert.Certificate[i])
		if err != nil {
			continue
		}
		if leaf.CheckSignatureFrom(candidate) == nil {
			issuer = candidate
			break
		}
	}
	if issuer == nil {
		return leaf, nil, nil
	}
	return leaf, issuer, nil
}

func ocspStapleNeedsRefresh(cert *tls.Certificate, leaf, issuer *x509.Certificate) bool {
	if cert == nil || leaf == nil || issuer == nil {
		return false
	}
	if len(cert.OCSPStaple) == 0 {
		return true
	}
	resp, err := ocsp.ParseResponseForCert(cert.OCSPStaple, leaf, issuer)
	if err != nil {
		return true
	}
	if resp.Status != ocsp.Good {
		return true
	}
	if resp.NextUpdate.IsZero() {
		return false
	}
	return time.Now().After(resp.NextUpdate.Add(-ocspRefreshSkew))
}

func fetchOCSPStaple(leaf, issuer *x509.Certificate) ([]byte, *ocsp.Response, error) {
	if leaf == nil || issuer == nil {
		return nil, nil, nil
	}
	if len(leaf.OCSPServer) == 0 {
		return nil, nil, nil
	}

	reqDER, err := ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{Hash: crypto.SHA1})
	if err != nil {
		return nil, nil, err
	}

	client := &http.Client{Timeout: ocspHTTPTimeout}
	var lastErr error
	for _, endpoint := range leaf.OCSPServer {
		httpReq, reqErr := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(reqDER))
		if reqErr != nil {
			lastErr = reqErr
			continue
		}
		httpReq.Header.Set("Content-Type", "application/ocsp-request")
		httpReq.Header.Set("Accept", "application/ocsp-response")

		resp, doErr := client.Do(httpReq)
		if doErr != nil {
			lastErr = doErr
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, ocspResponseReadLimit))
		resp.Body.Close()
		if readErr != nil {
			lastErr = readErr
			continue
		}
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("ocsp responder returned status %d", resp.StatusCode)
			continue
		}

		ocspResp, parseErr := ocsp.ParseResponseForCert(body, leaf, issuer)
		if parseErr != nil {
			lastErr = parseErr
			continue
		}
		return body, ocspResp, nil
	}
	return nil, nil, lastErr
}

// EnsureOCSPStaple refreshes OCSP staple for publicly trusted certificates when available.
func EnsureOCSPStaple(cert *tls.Certificate, contextLabel string) {
	if cert == nil {
		return
	}
	leaf, issuer, err := resolveLeafAndIssuer(cert)
	if err != nil || leaf == nil || issuer == nil {
		return
	}
	if len(leaf.OCSPServer) == 0 {
		return
	}
	if !ocspStapleNeedsRefresh(cert, leaf, issuer) {
		return
	}

	staple, ocspResp, fetchErr := fetchOCSPStaple(leaf, issuer)
	if fetchErr != nil {
		log.Printf("[OCSP] Failed to refresh OCSP staple for %s: %v", contextLabel, fetchErr)
		return
	}
	if len(staple) == 0 || ocspResp == nil {
		return
	}

	cert.OCSPStaple = append([]byte(nil), staple...)
	switch ocspResp.Status {
	case ocsp.Good:
		log.Printf("[OCSP] Stapled OCSP response for %s (next update: %v)", contextLabel, ocspResp.NextUpdate)
	case ocsp.Revoked:
		log.Printf("[OCSP] WARNING certificate revoked for %s (revoked at: %v)", contextLabel, ocspResp.RevokedAt)
	default:
		log.Printf("[OCSP] Stapled non-good OCSP status %d for %s", ocspResp.Status, contextLabel)
	}
}

// InitCertificates, generateAndSaveCA, loadCA, generateCA, encodeCertAndKey,
// GenerateCertForHost, GetCACertPEM, and fileExists have been removed:
// MITM certificate generation is no longer supported. ACME remains for
// the server's own TLS via InitACME/GetACMETLSConfig.

// InitACME initializes or refreshes the ACME certificate manager.
func InitACME(config *Config) {
	refreshDomainIndexes(config)

	acmeDomainsMutex.RLock()
	newDomains := append([]string(nil), acmeDomains...)
	acmeDomainsMutex.RUnlock()

	if len(newDomains) == 0 {
		log.Println("[ACME] No domains configured for ACME, skipping initialization.")
		return
	}

	log.Printf("[ACME] Initializing/Refreshing for %d domains: %v", len(newDomains), newDomains)

	if acmeManager != nil {
		return
	}

	if err := os.MkdirAll(acmeDir, 0755); err != nil {
		log.Fatalf("[ACME] Failed to create cache directory: %v", err)
	}

	acmeManager = &autocert.Manager{
		Cache:      autocert.DirCache(acmeDir),
		Prompt:     autocert.AcceptTOS,
		HostPolicy: dynamicHostPolicy,
	}
}

// refreshDomainIndexes rebuilds ACME whitelist and request-mapping fast-reject domains in one pass.
func refreshDomainIndexes(config *Config) {
	newACMEDomains := make([]string, 0)
	newACMEDomainSet := make(map[string]struct{})
	newMappingDomainSet := make(map[string]struct{})
	hasDynamicMappingHost := false

	if config != nil {
		for i := range config.Mappings {
			mapping := &config.Mappings[i]
			isACME := mappingUsesACMEServer(config, mapping)

			for _, rawFromURL := range mappingFromURLs(mapping) {
				if isACME {
					domain := strings.ToLower(extractDomain(rawFromURL))
					if domain != "" {
						if _, exists := newACMEDomainSet[domain]; !exists {
							newACMEDomainSet[domain] = struct{}{}
							newACMEDomains = append(newACMEDomains, domain)
						}
					}
				}

				host, schemeRelevant, dynamicHost := extractExactRuleHost(rawFromURL)
				if !schemeRelevant {
					continue
				}
				if dynamicHost {
					hasDynamicMappingHost = true
					continue
				}
				if host != "" {
					newMappingDomainSet[host] = struct{}{}
				}
			}
		}
	}

	acmeDomainsMutex.Lock()
	acmeDomains = newACMEDomains
	acmeDomainSet = newACMEDomainSet
	mappingDomainSet = newMappingDomainSet
	mappingHasDynamicHost = hasDynamicMappingHost
	mappingDomainConfig = config
	acmeDomainsMutex.Unlock()
}

func mappingUsesACMEServer(config *Config, mapping *Mapping) bool {
	for _, serverName := range mapping.serverNames {
		if server, ok := config.Servers[serverName]; ok {
			if certStr, ok := server.Cert.(string); ok && certStr == "acme" {
				return true
			}
		}
	}
	return false
}

func mappingFromURLs(mapping *Mapping) []string {
	fromConfig := mapping.GetFromConfig()
	if fromConfig != nil && len(fromConfig.URLs) > 0 {
		return fromConfig.URLs
	}
	if fromURL := mapping.GetFromURL(); fromURL != "" {
		return []string{fromURL}
	}
	return nil
}

func extractExactRuleHost(rawURL string) (host string, schemeRelevant bool, dynamicHost bool) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", false, false
	}

	parsedURL, err := url.Parse(rawURL)
	if err == nil {
		scheme := strings.ToLower(parsedURL.Scheme)
		if !isDomainIndexedScheme(scheme) {
			return "", false, false
		}

		host = strings.ToLower(parsedURL.Hostname())
		if host == "" {
			if containsURLScheme(rawURL) {
				return "", true, true
			}
			return "", true, false
		}

		if strings.IndexAny(host, `[](){}^$|\+?*`) != -1 {
			return "", true, true
		}

		return host, true, false
	}

	if containsURLScheme(rawURL) {
		return "", true, true
	}

	return "", false, false
}

func isDomainIndexedScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "http", "https", "ws", "wss", "*":
		return true
	default:
		return false
	}
}

func containsURLScheme(rawURL string) bool {
	lower := strings.ToLower(rawURL)
	return strings.Contains(lower, "http://") ||
		strings.Contains(lower, "https://") ||
		strings.Contains(lower, "ws://") ||
		strings.Contains(lower, "wss://") ||
		strings.Contains(lower, "*://")
}

func shouldFastRejectByDomain(config *Config, host string) bool {
	if config == nil || host == "" {
		return false
	}

	host = strings.ToLower(host)

	acmeDomainsMutex.RLock()
	defer acmeDomainsMutex.RUnlock()

	if mappingDomainConfig != config {
		return false
	}

	if mappingHasDynamicHost {
		return false
	}

	_, exists := mappingDomainSet[host]
	return !exists
}

func normalizeACMEWhitelistLookupHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}

	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}

	host = strings.TrimSpace(host)
	host = strings.Trim(host, "[]")
	host = strings.TrimSuffix(host, ".")
	return strings.ToLower(host)
}

func isHostInACMEWhitelistLocked(host string) bool {
	if host == "" {
		return false
	}

	if _, ok := acmeDomainSet[host]; ok {
		return true
	}

	parts := strings.Split(host, ".")
	for i := 1; i < len(parts)-1; i++ {
		wildcard := "*." + strings.Join(parts[i:], ".")
		if _, ok := acmeDomainSet[wildcard]; ok {
			return true
		}
	}

	return false
}

func isHostInACMEWhitelist(host string) bool {
	host = normalizeACMEWhitelistLookupHost(host)
	if host == "" {
		return false
	}

	acmeDomainsMutex.RLock()
	defer acmeDomainsMutex.RUnlock()
	return isHostInACMEWhitelistLocked(host)
}

// dynamicHostPolicy is a thread-safe host policy that checks against the current ACME domains.
func dynamicHostPolicy(ctx context.Context, host string) error {
	if isHostInACMEWhitelist(host) {
		return nil
	}
	return os.ErrPermission
}

// GetACMETLSConfig returns a TLS config for ACME.
func GetACMETLSConfig() *tls.Config {
	if acmeManager == nil {
		return nil
	}
	return acmeManager.TLSConfig()
}

// GetACMEHandler returns the HTTP handler for the ACME challenge.
func GetACMEHandler(fallback http.Handler) http.Handler {
	if acmeManager == nil {
		return fallback
	}
	return acmeManager.HTTPHandler(fallback)
}
