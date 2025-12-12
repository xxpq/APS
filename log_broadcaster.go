package main

import (
	"io"
	"strings"
	"sync"
)

// LogBroadcaster implements io.Writer to broadcast logs to SSE clients
// while also writing to the underlying writer (e.g., os.Stderr)
type LogBroadcaster struct {
	mu      sync.RWMutex
	clients map[chan string]struct{}
	out     io.Writer
}

// NewLogBroadcaster creates a new LogBroadcaster
func NewLogBroadcaster(out io.Writer) *LogBroadcaster {
	return &LogBroadcaster{
		clients: make(map[chan string]struct{}),
		out:     out,
	}
}

// Write implements io.Writer
func (lb *LogBroadcaster) Write(p []byte) (n int, err error) {
	// Write to the original output first
	n, err = lb.out.Write(p)
	if err != nil {
		return n, err
	}

	// Broadcast to all clients
	msg := string(p)
	// Remove trailing newline for cleaner SSE handling if desired,
	// but keeping it raw is also fine. Let's trim it for the data payload.
	msg = strings.TrimSuffix(msg, "\n")

	lb.mu.RLock()
	defer lb.mu.RUnlock()
	for client := range lb.clients {
		select {
		case client <- msg:
		default:
			// If client channel is full, skip to avoid blocking the logger
		}
	}
	return n, nil
}

// Subscribe adds a new client and returns a channel to receive logs
func (lb *LogBroadcaster) Subscribe() chan string {
	ch := make(chan string, 100) // Buffer to prevent blocking
	lb.mu.Lock()
	lb.clients[ch] = struct{}{}
	lb.mu.Unlock()
	return ch
}

// Unsubscribe removes a client and closes the channel
func (lb *LogBroadcaster) Unsubscribe(ch chan string) {
	lb.mu.Lock()
	if _, ok := lb.clients[ch]; ok {
		delete(lb.clients, ch)
		close(ch)
	}
	lb.mu.Unlock()
}
