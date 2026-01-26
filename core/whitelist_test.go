package core

import (
	"os"
	"testing"
)

func TestWhitelist_Operations(t *testing.T) {
	tmp, err := os.CreateTemp("", "whitelist_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	wl, err := NewWhitelist(tmp.Name())
	if err != nil {
		t.Fatalf("NewWhitelist failed: %v", err)
	}

	// 1. Add Single IP
	ip := "1.2.3.4"
	if err := wl.AddIP(ip); err != nil {
		t.Errorf("AddIP failed: %v", err)
	}

	if !wl.IsWhitelisted(ip) {
		t.Errorf("IP %s should be whitelisted", ip)
	}

	// 2. Add CIDR
	cidr := "10.0.0.0/24"
	if err := wl.AddIP(cidr); err != nil {
		t.Errorf("AddIP CIDR failed: %v", err)
	}

	if !wl.IsWhitelisted("10.0.0.5") {
		t.Errorf("IP 10.0.0.5 should be whitelisted by CIDR %s", cidr)
	}
	if wl.IsWhitelisted("10.0.1.5") {
		t.Errorf("IP 10.0.1.5 should NOT be whitelisted by CIDR %s", cidr)
	}

	// 3. Remove IP
	if err := wl.RemoveIP(ip); err != nil {
		t.Errorf("RemoveIP failed: %v", err)
	}
	if wl.IsWhitelisted(ip) {
		t.Errorf("IP %s should NOT be whitelisted after removal", ip)
	}

	// 4. Persistence (Reload)
	wl2, err := NewWhitelist(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	// IP was removed, should not be there
	if wl2.IsWhitelisted(ip) {
		t.Errorf("Persistence failed: IP %s present after removal and reload", ip)
	}
	// CIDR should still be there
	if !wl2.IsWhitelisted("10.0.0.5") {
		t.Errorf("Persistence failed: CIDR match lost after reload")
	}
}
