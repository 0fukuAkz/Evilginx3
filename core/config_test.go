package core

import (
	"testing"
)

func TestConfig_TrustedProxies(t *testing.T) {
	cfg := &Config{
		general: &GeneralConfig{},
	}
	// Default empty
	if len(cfg.GetTrustedProxies()) != 0 {
		t.Errorf("Expected empty trusted proxies")
	}

	// Set some
	ips := []string{"10.0.0.0/8", "192.168.1.1"}
	cfg.general.TrustedProxies = ips

	got := cfg.GetTrustedProxies()
	if len(got) != 2 {
		t.Errorf("Expected 2 proxies")
	}
	if got[0] != ips[0] {
		t.Errorf("Mismatch")
	}
}
