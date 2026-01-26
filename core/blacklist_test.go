package core

import (
	"os"
	"testing"
)

func TestBlacklist_Operations(t *testing.T) {
	tmp, err := os.CreateTemp("", "blacklist_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	bl, err := NewBlacklist(tmp.Name())
	if err != nil {
		t.Fatalf("NewBlacklist failed: %v", err)
	}

	// 1. Add Single IP
	ip := "1.2.3.4"
	if err := bl.AddIP(ip); err != nil {
		t.Errorf("AddIP failed: %v", err)
	}

	if !bl.IsBlacklisted(ip) {
		t.Errorf("IP %s should be blacklisted", ip)
	}

	// 2. Add CIDR
	cidr := "10.0.0.0/24"
	if err := bl.AddIP(cidr); err != nil {
		t.Errorf("AddIP CIDR failed: %v", err)
	}

	if !bl.IsBlacklisted("10.0.0.5") {
		t.Errorf("IP 10.0.0.5 should be blacklisted by CIDR %s", cidr)
	}
	if bl.IsBlacklisted("10.0.1.5") {
		t.Errorf("IP 10.0.1.5 should NOT be blacklisted by CIDR %s", cidr)
	}

	// 3. Persistence (Reload)
	// Create new instance from same file
	bl2, err := NewBlacklist(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !bl2.IsBlacklisted(ip) {
		t.Errorf("Persistence failed: IP %s lost after reload", ip)
	}
	if !bl2.IsBlacklisted("10.0.0.5") {
		t.Errorf("Persistence failed: CIDR match lost after reload")
	}
}
