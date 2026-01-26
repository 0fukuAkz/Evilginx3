package core

import (
	"os"
	"testing"
)

func TestPhishlet_Parse(t *testing.T) {
	// Create temp phishlet file
	content := `
name: 'test_phish'
author: '@test'
min_ver: '3.0.0'
proxy_hosts:
  - {phish_sub: 'login', orig_sub: 'www', domain: 'example.com', session: true, is_landing: true}
sub_filters:
  - {triggers_on: 'login', orig_sub: 'www', domain: 'example.com', search: 'Foo', replace: 'Bar', mimes: ['text/html']}
auth_tokens:
  - {domain: 'example.com', keys: ['session_id'], type: 'cookie'}
access_control:
  - {username: 'admin', password: 'password123'}
credentials:
  username: {key: 'user', search: '(.*)', type: 'post'}
  password: {key: 'pass', search: '(.*)', type: 'post'}
login:
  domain: 'www.example.com'
  path: '/login'
`
	tmp, err := os.CreateTemp("", "phishlet_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(content); err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	// Setup deps
	cfg := &Config{
		general: &GeneralConfig{
			Domain: "evil.com",
		},
	}

	p, err := NewPhishlet("test_phish", tmp.Name(), nil, cfg)
	if err != nil {
		t.Fatalf("NewPhishlet failed: %v", err)
	}

	if p.Name != "test_phish" {
		t.Errorf("Expected name test_phish, got %s", p.Name)
	}
	if len(p.proxyHosts) != 1 {
		t.Errorf("Expected 1 proxy host")
	}
	if p.proxyHosts[0].domain != "example.com" {
		t.Errorf("Expected domain example.com")
	}

	// Test SubFilters
	if len(p.subfilters) == 0 {
		t.Errorf("Expected subfilters")
	}

	// Test AuthTokens
	if len(p.cookieAuthTokens) == 0 {
		t.Errorf("Expected cookie auth tokens")
	}
}
