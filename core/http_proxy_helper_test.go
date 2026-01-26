package core

import (
	"net/http/httptest"
	"testing"
)

func TestGetRealIP(t *testing.T) {
	// Setup
	// Initialize Config strictly enough to avoid nil pointers if GetTrustedProxies is called
	// getRealIP calls p.cfg.GetTrustedProxies() which returns p.cfg.general.TrustedProxies
	cfg := &Config{
		general: &GeneralConfig{},
	}
	p := &HttpProxy{
		cfg: cfg,
	}

	tests := []struct {
		name           string
		remoteAddr     string
		trustedProxies []string
		headers        map[string]string
		expectedIP     string
	}{
		{
			name:       "No Trusted Proxies - RemoteAddr used",
			remoteAddr: "1.2.3.4:1234",
			expectedIP: "1.2.3.4",
		},
		{
			name:           "Trusted IP - X-Forwarded-For used",
			remoteAddr:     "10.0.0.1:1234",
			trustedProxies: []string{"10.0.0.0/8"},
			headers:        map[string]string{"X-Forwarded-For": "5.6.7.8"},
			expectedIP:     "5.6.7.8",
		},
		{
			name:           "Trusted IP (CIDR mismatch) - X-Forwarded-For ignored",
			remoteAddr:     "192.168.1.1:1234",
			trustedProxies: []string{"10.0.0.0/8"},
			headers:        map[string]string{"X-Forwarded-For": "5.6.7.8"},
			expectedIP:     "192.168.1.1",
		},
		{
			name:           "Untrusted IP - X-Forwarded-For ignored",
			remoteAddr:     "1.2.3.4:1234",
			trustedProxies: []string{"10.0.0.0/8"},
			headers:        map[string]string{"X-Forwarded-For": "5.6.7.8"},
			expectedIP:     "1.2.3.4",
		},
		{
			name:           "Multi-XFF - First IP used",
			remoteAddr:     "10.0.0.1:1234",
			trustedProxies: []string{"10.0.0.0/8"},
			headers:        map[string]string{"X-Forwarded-For": "5.6.7.8, 9.9.9.9"},
			expectedIP:     "5.6.7.8",
		},
		{
			name:           "Single IP Trusted Proxy Match",
			remoteAddr:     "10.0.0.50:1234",
			trustedProxies: []string{"10.0.0.50"},
			headers:        map[string]string{"X-Forwarded-For": "8.8.8.8"},
			expectedIP:     "8.8.8.8",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p.cfg.general.TrustedProxies = tc.trustedProxies

			req := httptest.NewRequest("GET", "http://example.com", nil)
			req.RemoteAddr = tc.remoteAddr
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}

			ip := p.getRealIP(req)
			if ip != tc.expectedIP {
				t.Errorf("Expected IP %s, got %s", tc.expectedIP, ip)
			}
		})
	}
}
