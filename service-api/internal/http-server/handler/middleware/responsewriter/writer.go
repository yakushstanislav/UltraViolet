// Package responsewriter wraps http.ResponseWriter for status/size capture
// while preserving optional interfaces required by upgrades (WebSocket, SSE).
package responsewriter

import (
	"bufio"
	"errors"
	"net"
	"net/http"
)

// Recorder captures the response status code and body size.
type Recorder struct {
	http.ResponseWriter
	Status int
	Bytes  int
}

// New returns a recorder with default status 200.
func New(w http.ResponseWriter) *Recorder {
	return &Recorder{
		ResponseWriter: w,
		Status:         http.StatusOK,
	}
}

// WriteHeader records the status code before delegating to the underlying writer.
func (r *Recorder) WriteHeader(code int) {
	r.Status = code

	r.ResponseWriter.WriteHeader(code)
}

// Write records the number of bytes written.
func (r *Recorder) Write(data []byte) (int, error) {
	n, err := r.ResponseWriter.Write(data)
	r.Bytes += n

	return n, err
}

// Hijack delegates to the underlying ResponseWriter when it supports upgrades.
func (r *Recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("http.ResponseWriter does not implement http.Hijacker")
	}

	return hj.Hijack()
}

// Unwrap exposes the underlying writer for http.ResponseController and WS stacks.
func (r *Recorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

// Flush delegates to the underlying ResponseWriter when it supports flushing.
func (r *Recorder) Flush() {
	fl, ok := r.ResponseWriter.(http.Flusher)
	if !ok {
		return
	}

	fl.Flush()
}
