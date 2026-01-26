package core

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kgretzky/evilginx2/database"
)

func TestTerminal_Config(t *testing.T) {
	// 1. Setup Environment
	tmpDir, err := os.MkdirTemp("", "evil_term_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	cfg, _ := NewConfig(tmpDir, "")
	db, _ := database.NewDatabase(":memory:")

	// 2. Headless Terminal with Mock IO
	mockIO := NewMockTerminalIO()
	term := &Terminal{
		cfg: cfg,
		db:  db,
		io:  mockIO,
	}

	// Redirect global log output to mock buffer for verification
	log.SetOutput(mockIO.GetOutput())
	defer log.SetOutput(os.Stdout) // Restore

	// 3. Test Config Command
	// config domain example.com
	if err := term.handleConfig([]string{"domain", "example.com"}); err != nil {
		t.Errorf("handleConfig domain failed: %v", err)
	}

	if cfg.general.Domain != "example.com" {
		t.Errorf("Domain not set. Got: %s", cfg.general.Domain)
	}

	// config domains (should print to log -> mockIO)
	term.handleConfig([]string{"domains"})
	output := mockIO.OutputBuffer.String()
	if !strings.Contains(output, "example.com") {
		t.Errorf("Expected 'example.com' in output, got: %s", output)
	}

	// config ipv4 1.2.3.4
	if err := term.handleConfig([]string{"ipv4", "1.2.3.4"}); err != nil {
		t.Errorf("handleConfig ipv4 failed: %v", err)
	}

	if cfg.general.ExternalIpv4 != "1.2.3.4" {
		t.Errorf("External IP not set. Got: %s", cfg.general.ExternalIpv4)
	}
}

func TestTerminal_Phishlets(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "evil_term_phish_test")
	defer os.RemoveAll(tmpDir)

	cfg, _ := NewConfig(tmpDir, "")
	db, _ := database.NewDatabase(":memory:")

	term := &Terminal{
		cfg: cfg,
		db:  db,
		io:  NewMockTerminalIO(),
	}

	// Create dummy phishlet file
	pDir := filepath.Join(tmpDir, "phishlets")
	os.MkdirAll(pDir, 0755)

	pPath := filepath.Join(pDir, "test.yaml")
	content := `
name: 'test'
author: '@test'
min_ver: '3.0.0'
proxy_hosts:
  - {phish_sub: 'login', orig_sub: 'www', domain: 'example.com', session: true, is_landing: true}
login:
  domain: 'www.example.com'
  path: '/login'
auth_tokens:
  - {domain: 'example.com', keys: ['session_id'], type: 'cookie'}
credentials:
  username: {key: 'u', search: '(.*)', type: 'post'}
  password: {key: 'p', search: '(.*)', type: 'post'}
`
	os.WriteFile(pPath, []byte(content), 0644)

	// Load it
	pl, err := NewPhishlet("test", pPath, nil, cfg)
	if err != nil {
		t.Fatalf("NewPhishlet failed: %v", err)
	}
	cfg.AddPhishlet("test", pl)

	// Test: phishlets hostname test example.com
	// handlePhishlets expects args...
	args := []string{"hostname", "test", "example.com"}

	// Set base domain first required for validation
	cfg.general.Domain = "example.com"

	if err := term.handlePhishlets(args); err != nil {
		t.Errorf("handlePhishlets hostname failed: %v", err)
	}

	pc := cfg.PhishletConfig("test")
	if pc.Hostname != "example.com" {
		t.Errorf("Hostname not set. Got: %s", pc.Hostname)
	}

	// Test disable/enable
	term.handlePhishlets([]string{"disable", "test"})
	if cfg.IsSiteEnabled("test") {
		t.Errorf("Should be disabled")
	}

	// Tests calling manageCertificates which returns safely if t.p is nil (thanks to patch).
}
