package core

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

type contextKey string

const (
	FingerprintContextKey contextKey = "utls_fingerprint"
)

// UTLSFingerprint represents a browser fingerprint type
type UTLSFingerprint string

const (
	FingerprintChrome  UTLSFingerprint = "chrome"
	FingerprintFirefox UTLSFingerprint = "firefox"
	FingerprintSafari  UTLSFingerprint = "safari"
	FingerprintIOS     UTLSFingerprint = "ios"
	FingerprintAndroid UTLSFingerprint = "android"
	FingerprintEdge    UTLSFingerprint = "edge"
	FingerprintDefault UTLSFingerprint = "chrome" // Default to Chrome
)

// UTLSTransport provides an http.RoundTripper that uses uTLS for TLS connections
// to spoof browser TLS fingerprints (JA3)
type UTLSTransport struct {
	fingerprint   UTLSFingerprint
	clientHelloID utls.ClientHelloID
	dialer        *net.Dialer
	connPool      sync.Map // Connection pooling for performance
	enabled       bool
	http2Enabled  bool
}

// NewUTLSTransport creates a new transport with the specified browser fingerprint
func NewUTLSTransport(fingerprint UTLSFingerprint, enabled bool, http2Enabled bool) *UTLSTransport {
	t := &UTLSTransport{
		fingerprint:  fingerprint,
		enabled:      enabled,
		http2Enabled: http2Enabled,
		dialer: &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		},
	}
	t.clientHelloID = t.getClientHelloID(fingerprint)
	return t
}

// getClientHelloID maps fingerprint string to uTLS ClientHelloID
func (t *UTLSTransport) getClientHelloID(fp UTLSFingerprint) utls.ClientHelloID {
	switch fp {
	case FingerprintChrome:
		return utls.HelloChrome_Auto
	case FingerprintFirefox:
		return utls.HelloFirefox_Auto
	case FingerprintSafari:
		return utls.HelloSafari_Auto
	case FingerprintIOS:
		return utls.HelloIOS_Auto
	case FingerprintAndroid:
		return utls.HelloAndroid_11_OkHttp
	case FingerprintEdge:
		return utls.HelloEdge_Auto
	default:
		return utls.HelloChrome_Auto
	}
}

// dialTLS creates a TLS connection using uTLS with the configured fingerprint
func (t *UTLSTransport) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	// Extract host for SNI
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	// Dial the raw TCP connection
	rawConn, err := t.dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial %s: %w", addr, err)
	}

	// Determine fingerprint ID
	clientHelloID := t.clientHelloID

	// Check context for dynamic fingerprint override
	if fp, ok := ctx.Value(FingerprintContextKey).(UTLSFingerprint); ok {
		clientHelloID = t.getClientHelloID(fp)
	}

	config := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: false, // Verify TLS by default
		MinVersion:         tls.VersionTLS12,
	}

	if t.http2Enabled {
		config.NextProtos = []string{"h2", "http/1.1"}
	} else {
		config.NextProtos = []string{"http/1.1"}
	}

	// Create uTLS client with the browser fingerprint
	uconn := utls.UClient(rawConn, config, clientHelloID)

	// Perform the TLS handshake
	if err := uconn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("TLS handshake failed for %s: %w", addr, err)
	}

	return uconn, nil
}

// GetTransport returns an http.Transport configured with uTLS
func (t *UTLSTransport) GetTransport() *http.Transport {
	if !t.enabled {
		// Return default transport if uTLS is disabled
		return &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  false,
			DisableKeepAlives:   false,
			MaxIdleConnsPerHost: 10,
		}
	}

	return &http.Transport{
		DialTLSContext:      t.dialTLS,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		DisableKeepAlives:   false,
		MaxIdleConnsPerHost: 10,
		ForceAttemptHTTP2:   t.http2Enabled,
		// Non-TLS connections use standard dial
		DialContext: t.dialer.DialContext,
	}
}

// RoundTrip implements http.RoundTripper
func (t *UTLSTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	transport := t.GetTransport()
	return transport.RoundTrip(req)
}

// SetFingerprint changes the browser fingerprint
func (t *UTLSTransport) SetFingerprint(fp UTLSFingerprint) {
	t.fingerprint = fp
	t.clientHelloID = t.getClientHelloID(fp)
}

// GetFingerprint returns the current fingerprint
func (t *UTLSTransport) GetFingerprint() UTLSFingerprint {
	return t.fingerprint
}

// IsEnabled returns whether uTLS is enabled
func (t *UTLSTransport) IsEnabled() bool {
	return t.enabled
}

// SetEnabled enables or disables uTLS
func (t *UTLSTransport) SetEnabled(enabled bool) {
	t.enabled = enabled
}

// SetHttp2Enabled enables or disables HTTP/2
func (t *UTLSTransport) SetHttp2Enabled(enabled bool) {
	t.http2Enabled = enabled
}

// GetFingerprintName returns a human-readable name for the fingerprint
func (t *UTLSTransport) GetFingerprintName() string {
	switch t.fingerprint {
	case FingerprintChrome:
		return "Chrome (Latest)"
	case FingerprintFirefox:
		return "Firefox (Latest)"
	case FingerprintSafari:
		return "Safari (Latest)"
	case FingerprintIOS:
		return "iOS Safari"
	case FingerprintAndroid:
		return "Android (OkHttp)"
	case FingerprintEdge:
		return "Microsoft Edge"
	default:
		return "Chrome (Latest)"
	}
}

// ValidFingerprints returns list of valid fingerprint options
func ValidFingerprints() []UTLSFingerprint {
	return []UTLSFingerprint{
		FingerprintChrome,
		FingerprintFirefox,
		FingerprintSafari,
		FingerprintIOS,
		FingerprintAndroid,
		FingerprintEdge,
	}
}

// DetermineFingerprint returns the appropriate UTLSFingerprint based on the User-Agent string
func DetermineFingerprint(userAgent string) UTLSFingerprint {
	ua := strings.ToLower(userAgent)

	if strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") || strings.Contains(ua, "ipod") {
		return FingerprintIOS
	}
	if strings.Contains(ua, "android") {
		return FingerprintAndroid
	}
	if strings.Contains(ua, "firefox") && !strings.Contains(ua, "seamonkey") {
		return FingerprintFirefox
	}
	if strings.Contains(ua, "edg/") || strings.Contains(ua, "edge/") {
		return FingerprintEdge
	}
	if strings.Contains(ua, "safari") && !strings.Contains(ua, "chrome") && !strings.Contains(ua, "crios") && !strings.Contains(ua, "fxios") {
		return FingerprintSafari
	}

	return FingerprintChrome
}
