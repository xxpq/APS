package main

import "fmt"

func DebugLog(format string, args ...interface{}) {
	fmt.Printf("[DEBUG] "+format+"\n", args...)
}
