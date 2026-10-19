package core

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLicenseRoundTrip exercises the full issue → check → validate → info cycle.
func TestLicenseRoundTrip(t *testing.T) {
	if LICENSE_PUBLIC_KEY == "" {
		t.Skip("LICENSE_PUBLIC_KEY is empty — verification disabled, skipping")
	}

	adminKeyPath := filepath.Join("..", "admin.key")
	if _, err := os.Stat(adminKeyPath); err != nil {
		t.Skipf("admin.key not found at %s — skipping issue test", adminKeyPath)
	}

	dir := t.TempDir()

	// Issue a 30-day license
	if err := IssueLicense(adminKeyPath, dir, "test-user", 30); err != nil {
		t.Fatalf("IssueLicense: %v", err)
	}

	licPath := filepath.Join(dir, "license.key")
	if _, err := os.Stat(licPath); err != nil {
		t.Fatalf("license.key not created: %v", err)
	}

	// CheckLicense (reads file, validates signature + expiry)
	if err := CheckLicense(dir); err != nil {
		t.Fatalf("CheckLicense: %v", err)
	}

	// ReadLicenseInfo
	issuedTo, issuedAt, expiresAt, valid, err := ReadLicenseInfo(dir)
	if err != nil {
		t.Fatalf("ReadLicenseInfo: %v", err)
	}
	if !valid {
		t.Fatal("ReadLicenseInfo: expected valid=true")
	}
	if issuedTo != "test-user" {
		t.Errorf("ReadLicenseInfo: issued_to = %q, want %q", issuedTo, "test-user")
	}
	if issuedAt.IsZero() {
		t.Error("ReadLicenseInfo: issued_at is zero")
	}
	if expiresAt.Before(time.Now().Add(29 * 24 * time.Hour)) {
		t.Errorf("ReadLicenseInfo: expires_at %v is too soon", expiresAt)
	}

	// ValidateLicenseKey (in-memory, no file I/O)
	data, err := os.ReadFile(licPath)
	if err != nil {
		t.Fatalf("reading license.key: %v", err)
	}
	pl, err := ValidateLicenseKey(string(data))
	if err != nil {
		t.Fatalf("ValidateLicenseKey: %v", err)
	}
	if pl.To != "test-user" {
		t.Errorf("ValidateLicenseKey: To = %q, want %q", pl.To, "test-user")
	}
}

// TestLicenseMissingFile verifies CheckLicense returns an error when no license.key exists.
func TestLicenseMissingFile(t *testing.T) {
	if LICENSE_PUBLIC_KEY == "" {
		t.Skip("verification disabled")
	}
	err := CheckLicense(t.TempDir())
	if err == nil {
		t.Fatal("CheckLicense: expected error for missing license.key, got nil")
	}
}

// TestLicenseExpired verifies that a validly-signed but expired token is rejected.
func TestLicenseExpired(t *testing.T) {
	if LICENSE_PUBLIC_KEY == "" {
		t.Skip("verification disabled")
	}
	adminKeyPath := filepath.Join("..", "admin.key")
	if _, err := os.Stat(adminKeyPath); err != nil {
		t.Skipf("admin.key not found at %s — skipping", adminKeyPath)
	}

	privData, err := os.ReadFile(adminKeyPath)
	if err != nil {
		t.Fatalf("read admin.key: %v", err)
	}
	privBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(privData)))
	if err != nil {
		t.Fatalf("decode admin.key: %v", err)
	}

	type payload struct {
		To  string `json:"to"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}
	pl := payload{
		To:  "test-expired",
		Iat: time.Now().Unix() - 86400*2,
		Exp: time.Now().Unix() - 86400, // expired 24 hours ago
	}
	plBytes, _ := json.Marshal(pl)
	sig := ed25519.Sign(ed25519.PrivateKey(privBytes), plBytes)
	token := base64.RawURLEncoding.EncodeToString(plBytes) + "." +
		base64.RawURLEncoding.EncodeToString(sig)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "license.key"), []byte(token+"\n"), 0600); err != nil {
		t.Fatalf("write license.key: %v", err)
	}

	err = CheckLicense(dir)
	if err == nil {
		t.Fatal("CheckLicense: expected error for expired license, got nil")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected error containing 'expired', got: %v", err)
	}
}

// TestValidateLicenseKeyBadInput covers format and signature errors.
func TestValidateLicenseKeyBadInput(t *testing.T) {
	if LICENSE_PUBLIC_KEY == "" {
		t.Skip("verification disabled")
	}

	cases := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"no dot", "aGVsbG8="},
		{"bad payload", "!!!.aGVsbG8="},
		{"bad sig", "eyJ0byI6IngiLCJpYXQiOjEsImV4cCI6OTk5OTk5OTk5OX0.!!!"},
		{"wrong sig", "eyJ0byI6IngiLCJpYXQiOjEsImV4cCI6OTk5OTk5OTk5OX0.AAAA"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateLicenseKey(tc.token)
			if err == nil {
				t.Errorf("expected error for token %q, got nil", tc.token)
			} else {
				t.Logf("correctly rejected: %v", err)
			}
		})
	}
}
