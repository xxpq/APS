package util

// ContainsString reports whether str appears in slice.
// Stage 9.3 moved this from root main's utils.go (the original name
// was containsString) to the aps/util package and exported it.
func ContainsString(slice []string, str string) bool {
	for _, item := range slice {
		if item == str {
			return true
		}
	}
	return false
}

// BoolCachePart is reserved for future use as a fast boolean cache
// lookup helper. Currently unused by the codebase; keeping the
// signature to avoid breaking callers that may import it later.
func BoolCachePart(v bool) string {
	if v {
		return "1"
	}
	return "0"
}
