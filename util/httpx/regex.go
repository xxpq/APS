package httpx

import (
	"regexp"
	"sync"
)

var (
	regexCache = make(map[string]*regexp.Regexp)
	regexMutex = &sync.RWMutex{}
)

// CompileRegex returns a compiled regexp.Regexp, using a process-wide
// cache to avoid re-compiling the same pattern. Returns the same
// instance for repeated calls with the same pattern.
func CompileRegex(pattern string) (*regexp.Regexp, error) {
	regexMutex.RLock()
	re, found := regexCache[pattern]
	regexMutex.RUnlock()

	if found {
		return re, nil
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	regexMutex.Lock()
	regexCache[pattern] = re
	regexMutex.Unlock()

	return re, nil
}
