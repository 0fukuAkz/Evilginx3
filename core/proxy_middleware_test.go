package core

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/elazarl/goproxy"
)

func TestMiddlewareChain_Basic(t *testing.T) {
	// Setup minimal proxy deps
	cfg := &Config{
		general:         &GeneralConfig{},
		phishlets:       make(map[string]*Phishlet),
		whitelistConfig: &WhitelistConfig{},
		blacklistConfig: &BlacklistConfig{Mode: "off"},
	}
	p := &HttpProxy{
		cfg: cfg,
	}

	// Helper to create context
	ps := &ProxySession{RemoteIP: "1.2.3.4"}
	ctx := &goproxy.ProxyCtx{UserData: ps}
	req := httptest.NewRequest("GET", "http://example.com", nil)

	// 1. IP Middleware (Defaults)
	ipm := &IPMiddleware{}
	_, _, proceed := ipm.Handle(req, ctx, p)
	if !proceed {
		t.Errorf("IPMiddleware should proceed when no BL/WL configured")
	}

	// 2. Traffic Middleware (Nil shaper)
	tm := &TrafficMiddleware{}
	_, _, proceed = tm.Handle(req, ctx, p)
	if !proceed {
		t.Errorf("TrafficMiddleware should proceed when nil shaper")
	}

	// 3. Bot Middleware (Nil detectors)
	bm := &BotMiddleware{}
	_, _, proceed = bm.Handle(req, ctx, p)
	if !proceed {
		t.Errorf("BotMiddleware should proceed when nil detectors")
	}
}

func TestIPMiddleware_Blacklist(t *testing.T) {
	// Setup temp blacklist file
	tmpFile, err := os.CreateTemp("", "blacklist_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	bl, err := NewBlacklist(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	blockedIP := "10.0.0.1"
	if err := bl.AddIP(blockedIP); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		general: &GeneralConfig{},
		blacklistConfig: &BlacklistConfig{
			Mode: "all",
		},
		whitelistConfig: &WhitelistConfig{},
	}
	p := &HttpProxy{
		cfg: cfg,
		bl:  bl,
	}

	// Test blocked IP
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.RemoteAddr = blockedIP + ":1234"
	ps := &ProxySession{}
	ctx := &goproxy.ProxyCtx{UserData: ps}

	ipm := &IPMiddleware{}
	_, resp, proceed := ipm.Handle(req, ctx, p)
	if proceed {
		t.Logf("Checking IP: %s (len: %d)", blockedIP, len(blockedIP))
		t.Logf("IsBlacklisted? %v", p.bl.IsBlacklisted(blockedIP))
		t.Errorf("Should block blacklisted IP")
	} else {
		if resp == nil {
			t.Errorf("Blocked request should have response")
		} else if resp.StatusCode != http.StatusForbidden {
			t.Errorf("Expected 403, got %d", resp.StatusCode)
		}
	}
}
