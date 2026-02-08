package core

import (
	"testing"
)

func TestConfig_Http2Enabled(t *testing.T) {
	cfg := &Config{
		general: &GeneralConfig{},
	}

	// Default false
	if cfg.IsHttp2Enabled() {
		t.Errorf("Expected Http2Enabled to be false by default")
	}

	// Enable
	cfg.general.Http2Enabled = true
	if !cfg.IsHttp2Enabled() {
		t.Errorf("Expected Http2Enabled to be true")
	}
}

func TestUTLSTransport_Http2Enabled(t *testing.T) {
	// Test initialization
	transport := NewUTLSTransport(FingerprintChrome, true, false)
	if transport.http2Enabled {
		t.Errorf("Expected http2Enabled to be false")
	}

	transport = NewUTLSTransport(FingerprintChrome, true, true)
	if !transport.http2Enabled {
		t.Errorf("Expected http2Enabled to be true")
	}

	// Test setter
	transport.SetHttp2Enabled(false)
	if transport.http2Enabled {
		t.Errorf("Expected http2Enabled to be false after SetHttp2Enabled(false)")
	}
}

func TestHttpProxy_SetHttp2Enabled(t *testing.T) {
	// Mock proxy with just enough to test the method
	proxy := &HttpProxy{
		utlsTransport: NewUTLSTransport(FingerprintChrome, true, false),
	}

	// Verify initial state
	if proxy.utlsTransport.http2Enabled {
		t.Errorf("Expected transport http2Enabled to be false")
	}

	// Enable via Proxy
	proxy.SetHttp2Enabled(true)
	if !proxy.utlsTransport.http2Enabled {
		t.Errorf("Expected transport http2Enabled to be true after Proxy.SetHttp2Enabled(true)")
	}

	// Disable via Proxy
	proxy.SetHttp2Enabled(false)
	if proxy.utlsTransport.http2Enabled {
		t.Errorf("Expected transport http2Enabled to be false after Proxy.SetHttp2Enabled(false)")
	}
}
