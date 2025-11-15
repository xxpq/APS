package main

import (
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

func (p *MapRemoteProxy) mapRequest(r *http.Request) (string, bool, *Mapping) {
	originalURL := p.buildOriginalURL(r)
	mappings := p.config.GetMappings()
	
	var bestMatch *Mapping
	var bestScore = -1
	var finalURL string

	for i := range mappings {
		mapping := &mappings[i]
		
		score, newURL := p.calculateMatchScore(mapping, r, originalURL)

		if score > bestScore {
			bestScore = score
			bestMatch = mapping
			finalURL = newURL
		}
	}

	if bestMatch != nil {
		return finalURL, true, bestMatch
	}

	return originalURL, false, nil
}

func (p *MapRemoteProxy) calculateMatchScore(mapping *Mapping, r *http.Request, originalURL string) (int, string) {
	// Check if the mapping is for the current server
	isForThisServer := false
	for _, name := range mapping.serverNames {
		if name == p.serverName {
			isForThisServer = true
			break
		}
	}
	if !isForThisServer {
		return -1, ""
	}

	// Base URL match
	matched, newURL := p.matchAndReplace(originalURL, *mapping)
	if !matched {
		return -1, ""
	}

	score := 1 // Base score for URL match
	fromConfig := mapping.GetFromConfig()

	if fromConfig != nil {
		// Method match
		if fromConfig.Method != nil {
			if fromConfig.MatchesMethod(r.Method) {
				score += 10
			} else {
				return -1, "" // Method is specified but does not match
			}
		}

		// Header match
		if len(fromConfig.Headers) > 0 {
			for key, value := range fromConfig.Headers {
				if r.Header.Get(key) != "" && (value == nil || r.Header.Get(key) == value) {
					score++
				}
			}
		}

		// Query string match
		if len(fromConfig.QueryString) > 0 {
			queryParams := r.URL.Query()
			for key, value := range fromConfig.QueryString {
				if queryParams.Get(key) != "" && (value == nil || queryParams.Get(key) == value.(string)) {
					score++
				}
			}
		}
	}

	return score, newURL
}

func (p *MapRemoteProxy) matchAndReplace(originalURL string, mapping Mapping) (bool, string) {
	fromPattern := mapping.GetFromURL()
	toPattern := mapping.GetToURL()

	log.Printf("[DEBUG] Trying to match: %s with pattern: %s", originalURL, fromPattern)

	if matched, newURL := p.tryRegexMatch(originalURL, fromPattern, toPattern); matched {
		return true, newURL
	}

	parsedOriginal, err := url.Parse(originalURL)
	if err != nil {
		log.Printf("[DEBUG] Failed to parse original URL: %v", err)
		return false, originalURL
	}

	parsedFrom, err := url.Parse(fromPattern)
	if err != nil {
		log.Printf("[DEBUG] Failed to parse from pattern: %v", err)
		return false, originalURL
	}

	log.Printf("[DEBUG] Original - Scheme: %s, Host: %s, Path: %s",
		parsedOriginal.Scheme, parsedOriginal.Host, parsedOriginal.Path)
	log.Printf("[DEBUG] Pattern  - Scheme: %s, Host: %s, Path: %s",
		parsedFrom.Scheme, parsedFrom.Host, parsedFrom.Path)

	if parsedOriginal.Scheme != parsedFrom.Scheme {
		log.Printf("[DEBUG] Scheme mismatch: %s != %s", parsedOriginal.Scheme, parsedFrom.Scheme)
		return false, originalURL
	}

	if parsedOriginal.Host != parsedFrom.Host {
		log.Printf("[DEBUG] Host mismatch: %s != %s", parsedOriginal.Host, parsedFrom.Host)
		return false, originalURL
	}

	fromPath := parsedFrom.Path
	originalPath := parsedOriginal.Path

	if originalPath == "" {
		originalPath = "/"
	}

	if strings.HasSuffix(fromPath, "*") {
		fromPathPrefix := strings.TrimSuffix(fromPath, "*")

		if fromPathPrefix == "" || fromPathPrefix == "/" {
			log.Printf("[DEBUG] Root wildcard match - matches any path")
		} else {
			log.Printf("[DEBUG] Wildcard match - checking if %s starts with %s", originalPath, fromPathPrefix)
		}

		if fromPathPrefix == "" || fromPathPrefix == "/" || strings.HasPrefix(originalPath, fromPathPrefix) {
			toPath := strings.TrimSuffix(toPattern, "*")

			parsedTo, err := url.Parse(toPath)
			if err != nil {
				return false, originalURL
			}

			var remainingPath string
			if fromPathPrefix == "" || fromPathPrefix == "/" {
				if originalPath == "/" {
					remainingPath = ""
				} else {
					remainingPath = originalPath
				}
			} else {
				remainingPath = strings.TrimPrefix(originalPath, fromPathPrefix)
			}

			newPath := parsedTo.Path
			if strings.HasSuffix(newPath, "/") && strings.HasPrefix(remainingPath, "/") {
				newPath = strings.TrimSuffix(newPath, "/")
			}
			newPath = newPath + remainingPath

			newURL := url.URL{
				Scheme:   parsedTo.Scheme,
				Host:     parsedTo.Host,
				Path:     newPath,
				RawQuery: parsedOriginal.RawQuery,
				Fragment: parsedOriginal.Fragment,
			}

			log.Printf("[DEBUG] ✓ Wildcard matched! New URL: %s", newURL.String())
			return true, newURL.String()
		}
	} else {
		log.Printf("[DEBUG] Exact match - checking if %s == %s", originalPath, fromPath)
		if originalPath == fromPath || (originalPath == "/" && fromPath == "") || (originalPath == "" && fromPath == "/") {
			parsedTo, err := url.Parse(toPattern)
			if err != nil {
				return false, originalURL
			}

			newURL := url.URL{
				Scheme:   parsedTo.Scheme,
				Host:     parsedTo.Host,
				Path:     parsedTo.Path,
				RawQuery: parsedOriginal.RawQuery,
				Fragment: parsedOriginal.Fragment,
			}

			log.Printf("[DEBUG] ✓ Exact matched! New URL: %s", newURL.String())
			return true, newURL.String()
		}
	}

	log.Printf("[DEBUG] ✗ No match")
	return false, originalURL
}

func (p *MapRemoteProxy) tryRegexMatch(originalURL, fromPattern, toPattern string) (bool, string) {
	if !strings.Contains(fromPattern, "(") && !strings.Contains(fromPattern, "[") &&
		!strings.Contains(fromPattern, "{") && !strings.Contains(fromPattern, "^") &&
		!strings.Contains(fromPattern, "$") && !strings.Contains(fromPattern, "|") {
		return false, originalURL
	}

	re, err := regexp.Compile(fromPattern)
	if err != nil {
		log.Printf("[DEBUG] Not a valid regex pattern: %v", err)
		return false, originalURL
	}

	if !re.MatchString(originalURL) {
		return false, originalURL
	}

	newURL := re.ReplaceAllString(originalURL, toPattern)
	log.Printf("[DEBUG] ✓ Regex matched! %s -> %s", originalURL, newURL)
	return true, newURL
}