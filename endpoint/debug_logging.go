package main

import "log"

// DebugLog prints logs only when -debug is enabled.
func DebugLog(format string, args ...interface{}) {
	if debug != nil && *debug {
		log.Printf(format, args...)
	}
}
