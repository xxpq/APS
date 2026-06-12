package tcptunnel

import "sync"

// Local buffer pools for the tcptunnel package. Originally these lived in
// the root package pools.go and were used by both tcptunnel and other code.
// For the move to aps/tcptunnel we keep independent local pools to avoid
// cross-package coupling; they are not shared with main's pools.

var headerPool = sync.Pool{
	New: func() any {
		return make([]byte, 5)
	},
}

var mediumBufPool = sync.Pool{
	New: func() any {
		return make([]byte, 32*1024)
	},
}

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
