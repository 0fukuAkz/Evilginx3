package core

import (
	"regexp"
	"strings"
)

// subfilterKeyMatches reports whether a phishlet sub_filter `triggers_on` key
// (which may contain '*' wildcards) matches the concrete hostname.
func subfilterKeyMatches(key, hostname string) bool {
	if !strings.Contains(key, "*") {
		return strings.EqualFold(key, hostname)
	}
	parts := strings.Split(key, "*")
	var pattern strings.Builder
	pattern.WriteString("(?i)^")
	for i, p := range parts {
		if i > 0 {
			pattern.WriteString(`[A-Za-z0-9][A-Za-z0-9.\-]*`)
		}
		pattern.WriteString(regexp.QuoteMeta(p))
	}
	pattern.WriteString("$")
	re, err := regexp.Compile(pattern.String())
	if err != nil {
		return false
	}
	return re.MatchString(hostname)
}

func combineHost(sub string, domain string) string {
	if sub == "" {
		return domain
	}
	return sub + "." + domain
}

// hostWildcardMatches reports whether the hostname formed by `origSub` and
// `domainPattern` matches the concrete `actual` hostname. If `domainPattern`
// is "*", any real TLD-bearing domain following the subdomain prefix is
// accepted, and the captured real domain is returned.
func hostWildcardMatches(origSub, domainPattern, actual string) (bool, string) {
	actual = strings.ToLower(actual)
	origSub = strings.ToLower(origSub)
	if domainPattern != "*" {
		return combineHost(origSub, domainPattern) == actual, domainPattern
	}
	if origSub == "" {
		if strings.Contains(actual, ".") {
			return true, actual
		}
		return false, ""
	}
	prefix := origSub + "."
	if strings.HasPrefix(actual, prefix) {
		rest := actual[len(prefix):]
		if strings.Contains(rest, ".") {
			return true, rest
		}
	}
	return false, ""
}

func obfuscateDots(s string) string {
	return strings.Replace(s, ".", "[[d0t]]", -1)
}

func removeObfuscatedDots(s string) string {
	return strings.Replace(s, "[[d0t]]", ".", -1)
}

func stringExists(s string, sa []string) bool {
	for _, k := range sa {
		if s == k {
			return true
		}
	}
	return false
}

func intExists(i int, ia []int) bool {
	for _, k := range ia {
		if i == k {
			return true
		}
	}
	return false
}

func removeString(s string, sa []string) []string {
	for i, k := range sa {
		if s == k {
			return append(sa[:i], sa[i+1:]...)
		}
	}
	return sa
}

func truncateString(s string, maxLen int) string {
	if len(s) > maxLen {
		ml := maxLen
		pre := s[:ml/2-1]
		suf := s[len(s)-(ml/2-2):]
		return pre + "..." + suf
	}
	return s
}
