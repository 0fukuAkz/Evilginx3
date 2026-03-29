package core

import (
	"net/http"
	"time"
)

// SharedHTTPTransport is a globally reused HTTP transport with connection pooling.
// Reusing a single transport allows TCP connections to be kept alive and reused,
// dramatically reducing ephemeral port exhaustion and handshake overhead.
var SharedHTTPTransport = &http.Transport{
	MaxIdleConns:        100,
	MaxIdleConnsPerHost: 20,
	IdleConnTimeout:     90 * time.Second,
	TLSHandshakeTimeout: 10 * time.Second,
}

// NewHTTPClient returns a new HTTP client sharing the global transport.
// Use this instead of &http.Client{} to benefit from connection pooling.
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: SharedHTTPTransport,
		Timeout:   timeout,
	}
}
