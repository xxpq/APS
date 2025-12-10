package main

import (
	"bufio"
	"bytes"
	"regexp"
	"sync"
)

// ============================================================================
// Buffer Pools - Reduces GC pressure in high-concurrency scenarios
// ============================================================================

// headerPool provides reusable 5-byte buffers for protocol headers
var headerPool = sync.Pool{
	New: func() any {
		return make([]byte, 5)
	},
}

// smallBufPool provides reusable 1KB buffers for small reads
var smallBufPool = sync.Pool{
	New: func() any {
		return make([]byte, 1024)
	},
}

// mediumBufPool provides reusable 32KB buffers for proxy data
var mediumBufPool = sync.Pool{
	New: func() any {
		return make([]byte, 32*1024)
	},
}

// largeBufPool provides reusable 128KB buffers for streaming responses
var largeBufPool = sync.Pool{
	New: func() any {
		return make([]byte, 128*1024)
	},
}

// bufioReaderPool provides reusable buffered readers
var bufioReaderPool = sync.Pool{
	New: func() any {
		return bufio.NewReaderSize(nil, 4096)
	},
}

// bytesBufferPool provides reusable bytes.Buffer instances
var bytesBufferPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

// doneChannelPool provides reusable done channels (capacity 2)
var doneChannelPool = sync.Pool{
	New: func() any {
		return make(chan struct{}, 2)
	},
}

// ============================================================================
// Regex Cache - Use compileRegex from utils.go
// ============================================================================

// GetOrCompileRegex is an alias for the existing compileRegex function in utils.go
// for API consistency with the pools module
func GetOrCompileRegex(pattern string) (*regexp.Regexp, error) {
	return compileRegex(pattern)
}

// ============================================================================
// Protocol Detection Lookup Table - O(1) instead of O(n) slice iteration
// ============================================================================

// httpMethodFirstBytes is a lookup table for HTTP request first bytes
var httpMethodFirstBytes = map[byte]bool{
	'G': true, // GET
	'P': true, // POST, PUT, PATCH
	'H': true, // HEAD
	'D': true, // DELETE
	'O': true, // OPTIONS
	'C': true, // CONNECT
	'T': true, // TRACE
}

// validTunnelTypes is a lookup table for valid tunnel message types
var validTunnelTypes = map[byte]bool{
	MsgTypeRegister:        true,
	MsgTypeRegisterAck:     true,
	MsgTypeRequest:         true,
	MsgTypeResponse:        true,
	MsgTypeResponseHeader:  true,
	MsgTypeResponseChunk:   true,
	MsgTypeResponseEnd:     true,
	MsgTypeProxyConnect:    true,
	MsgTypeProxyConnectAck: true,
	MsgTypeProxyData:       true,
	MsgTypeProxyClose:      true,
	MsgTypeHeartbeat:       true,
	MsgTypeCancel:          true,
}

// ============================================================================
// Pool Helper Functions
// ============================================================================

// GetHeaderBuffer gets a 5-byte header buffer from pool
func GetHeaderBuffer() []byte {
	return headerPool.Get().([]byte)
}

// PutHeaderBuffer returns a header buffer to pool
func PutHeaderBuffer(buf []byte) {
	if cap(buf) >= 5 {
		headerPool.Put(buf[:5])
	}
}

// GetSmallBuffer gets a 1KB buffer from pool
func GetSmallBuffer() []byte {
	return smallBufPool.Get().([]byte)
}

// PutSmallBuffer returns a small buffer to pool
func PutSmallBuffer(buf []byte) {
	if cap(buf) >= 1024 {
		smallBufPool.Put(buf[:1024])
	}
}

// GetMediumBuffer gets a 32KB buffer from pool
func GetMediumBuffer() []byte {
	return mediumBufPool.Get().([]byte)
}

// PutMediumBuffer returns a medium buffer to pool
func PutMediumBuffer(buf []byte) {
	if cap(buf) >= 32*1024 {
		mediumBufPool.Put(buf[:32*1024])
	}
}

// GetLargeBuffer gets a 128KB buffer from pool
func GetLargeBuffer() []byte {
	return largeBufPool.Get().([]byte)
}

// PutLargeBuffer returns a large buffer to pool
func PutLargeBuffer(buf []byte) {
	if cap(buf) >= 128*1024 {
		largeBufPool.Put(buf[:128*1024])
	}
}

// GetBufioReader gets a bufio.Reader from pool and resets it with the given reader
func GetBufioReader(r interface{ Read([]byte) (int, error) }) *bufio.Reader {
	reader := bufioReaderPool.Get().(*bufio.Reader)
	reader.Reset(r)
	return reader
}

// PutBufioReader returns a bufio.Reader to pool
func PutBufioReader(r *bufio.Reader) {
	r.Reset(nil)
	bufioReaderPool.Put(r)
}

// GetBytesBuffer gets a bytes.Buffer from pool
func GetBytesBuffer() *bytes.Buffer {
	buf := bytesBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	return buf
}

// PutBytesBuffer returns a bytes.Buffer to pool
func PutBytesBuffer(buf *bytes.Buffer) {
	buf.Reset()
	bytesBufferPool.Put(buf)
}

// GetDoneChannel gets a done channel from pool
func GetDoneChannel() chan struct{} {
	ch := doneChannelPool.Get().(chan struct{})
	// Drain any stale signals
	select {
	case <-ch:
	default:
	}
	select {
	case <-ch:
	default:
	}
	return ch
}

// PutDoneChannel returns a done channel to pool
func PutDoneChannel(ch chan struct{}) {
	// Drain any remaining signals
	select {
	case <-ch:
	default:
	}
	select {
	case <-ch:
	default:
	}
	doneChannelPool.Put(ch)
}

// ============================================================================
// Pre-allocated Constants
// ============================================================================

// connectEstablishedResponse is the pre-allocated HTTP 200 response for CONNECT
var connectEstablishedResponse = []byte("HTTP/1.1 200 Connection Established\r\n\r\n")
