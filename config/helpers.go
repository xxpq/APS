package config

import (
	"errors"
	"log"
	"strconv"
)

// Errors used by types.go during JSON unmarshaling and rate-limit parsing.
var (
	errInvalidCertString = errors.New("cert string must be 'auto' or 'acme'")
	errInvalidCertField  = errors.New("invalid type for 'cert' field")
	errInvalidRateUnit   = errors.New("invalid rate limit unit, use kbps, mbps, or gbps")
)

// logPrintf is a thin wrapper around log.Printf so that types.go and
// endpoint_aps.go can stay free of the "log" import directly. If a future
// refactor wants to route through util.DebugLog, only this function changes.
func logPrintf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

// parseRateFloat wraps strconv.ParseFloat so types.go does not need to
// import strconv directly.
func parseRateFloat(s string) (float64, error) {
	return strconv.ParseFloat(s, 64)
}
