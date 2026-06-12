package util

import (
	"io"
	"log"
	"strings"
)

type httpServerErrorFilter struct {
	out io.Writer
}

func (w *httpServerErrorFilter) Write(p []byte) (n int, err error) {
	msg := string(p)
	if strings.Contains(msg, "http: TLS handshake error") && strings.Contains(msg, "permission denied") {
		return len(p), nil
	}
	return w.out.Write(p)
}

func NewHTTPServerErrorLogger(out io.Writer) *log.Logger {
	return log.New(&httpServerErrorFilter{out: out}, "", log.LstdFlags)
}
